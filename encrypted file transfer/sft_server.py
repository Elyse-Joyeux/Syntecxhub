import argparse
import getpass
import hashlib
import hmac
import json
import os
import re
import socketserver
import struct
import threading
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sft_common import (CHUNK_SIZE, ProtocolError, clean_name,
                        fingerprint, raw_public, server_handshake)

USER_RE = re.compile(r"^[a-z0-9_]{3,32}$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_FILE_SIZE = 4 * 1024 ** 3
REC = struct.Struct(">12sI")      # record header: nonce, ciphertext length


class StorageError(Exception):
    pass


class Busy(StorageError):
    pass


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# --------------------------------------------------------------------------- key management
def _write_secret(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # owner-only permissions
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def load_identity(path):
    path = Path(path)
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(path.read_bytes())
    key = Ed25519PrivateKey.generate()
    _write_secret(path, key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                          serialization.NoEncryption()))
    return key


def load_master_key(data_dir):
    """Master key (KEK). Either derived from a passphrase (never stored) or read from a key file."""
    passphrase = os.environ.get("SFT_MASTER_PASSPHRASE")
    if passphrase:
        salt_path = data_dir / "master.salt"
        if not salt_path.exists():
            _write_secret(salt_path, os.urandom(16))
        return hashlib.scrypt(passphrase.encode(), salt=salt_path.read_bytes(),
                              n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    key_path = data_dir / "master.key"
    if not key_path.exists():
        _write_secret(key_path, os.urandom(32))
    return key_path.read_bytes()


# --------------------------------------------------------------------------- users
class UserStore:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.users = json.loads(self.path.read_text()) if self.path.exists() else {}

    @staticmethod
    def _hash(password, salt):
        return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    def add(self, user, password):
        if not USER_RE.match(user):
            raise ValueError("user name must be 3-32 chars of a-z, 0-9, _")
        salt = os.urandom(16)
        with self.lock:
            self.users[user] = {"salt": salt.hex(), "hash": self._hash(password, salt).hex()}
            self.path.write_text(json.dumps(self.users))

    def verify(self, user, password):
        rec = self.users.get(user)
        digest = self._hash(password, bytes.fromhex(rec["salt"]) if rec else bytes(16))   # constant work
        return bool(rec) and hmac.compare_digest(digest, bytes.fromhex(rec["hash"]))


# --------------------------------------------------------------------------- vault
class Vault:
    def __init__(self, root, master_key):
        self.root = Path(root) / "files"
        self.root.mkdir(parents=True, exist_ok=True)
        self.kek = AESGCM(master_key)

    # ---- paths / metadata
    def _paths(self, user, fid):
        assert USER_RE.match(user) and ID_RE.match(fid)          # no path traversal possible
        d = self.root / user
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{fid}.meta", d / f"{fid}.part", d / f"{fid}.enc"

    @staticmethod
    def _meta_aad(fid, user, m):
        return f"{fid}|{user}|{m['name']}|{m['size']}|{m['chunks']}|{m['sha256']}".encode()

    def _new_meta(self, user, fid, name, size, sha):
        dek = AESGCM.generate_key(bit_length=256)
        meta = {"name": name, "size": size, "chunks": -(-size // CHUNK_SIZE), "sha256": sha,
                "created": int(time.time())}
        nonce = os.urandom(12)
        meta["wrapped_dek"] = (nonce + self.kek.encrypt(nonce, dek, self._meta_aad(fid, user, meta))).hex()
        return meta, AESGCM(dek)

    def _open_meta(self, user, fid):
        mp = self._paths(user, fid)[0]
        try:
            meta = json.loads(mp.read_text())
            blob = bytes.fromhex(meta["wrapped_dek"])
            dek = self.kek.decrypt(blob[:12], blob[12:], self._meta_aad(fid, user, meta))
            return meta, AESGCM(dek)
        except Exception:
            raise StorageError("metadata missing or failed authentication (tampered / wrong master key)")

    @staticmethod
    def _chunk_aad(fid, index, total):
        return bytes.fromhex(fid) + struct.pack(">QQ", index, total)

    # ---- upload
    def open_upload(self, user, fid, name, size, sha):
        """Returns None if already stored, else an UploadSession (new or resumed)."""
        mp, pp, ep = self._paths(user, fid)
        if ep.exists():
            return None
        if mp.exists():
            meta, aead = self._open_meta(user, fid)
            if meta["size"] != size or meta["sha256"] != sha:
                raise StorageError("upload id conflict")
        else:
            meta, aead = self._new_meta(user, fid, name, size, sha)
            tmp = mp.with_suffix(".tmp")
            tmp.write_text(json.dumps(meta))
            os.replace(tmp, mp)
        count, good = self._scan(pp)
        count = min(count, meta["chunks"])
        pp.touch()
        f = open(pp, "r+b")
        f.truncate(good)               # drop any half-written trailing record from a crashed upload
        f.seek(good)
        return UploadSession(self, user, fid, meta, aead, f, count)

    @staticmethod
    def _scan(path):
        """Structural scan of a partial file: how many complete records, and how many bytes they use."""
        count = good = 0
        if not path.exists():
            return 0, 0
        size = path.stat().st_size
        with open(path, "rb") as f:
            while True:
                h = f.read(REC.size)
                if len(h) < REC.size:
                    break
                clen = REC.unpack(h)[1]
                if clen > CHUNK_SIZE + 16 or good + REC.size + clen > size:
                    break
                f.seek(clen, 1)
                good += REC.size + clen
                count += 1
        return count, good

    # ---- read
    def iter_chunks(self, path, aead, fid, total, start=0):
        with open(path, "rb") as f:
            for idx in range(total):
                h = f.read(REC.size)
                if len(h) < REC.size:
                    raise StorageError("stored file is truncated")
                nonce, clen = REC.unpack(h)
                if clen > CHUNK_SIZE + 16:
                    raise StorageError("corrupt record")
                if idx < start:
                    f.seek(clen, 1)
                    continue
                ct = f.read(clen)
                if len(ct) != clen:
                    raise StorageError("stored file is truncated")
                try:
                    yield idx, aead.decrypt(nonce, ct, self._chunk_aad(fid, idx, total))
                except InvalidTag:
                    raise StorageError(f"chunk {idx} failed authentication - stored data was modified")

    def open_download(self, user, fid):
        ep = self._paths(user, fid)[2]
        if not ep.exists():
            raise StorageError("no such file")
        meta, aead = self._open_meta(user, fid)
        return meta, aead, ep

    def list(self, user):
        out = []
        d = self.root / user
        for ep in sorted(d.glob("*.enc")) if d.exists() else []:
            fid = ep.stem
            try:
                meta, _ = self._open_meta(user, fid)
                out.append({"file_id": fid, "name": meta["name"], "size": meta["size"], "created": meta["created"]})
            except StorageError:
                out.append({"file_id": fid, "name": "<CORRUPT METADATA>", "size": 0, "created": 0})
        return out

    def delete(self, user, fid):
        found = False
        for p in self._paths(user, fid):
            if p.exists():
                p.unlink()
                found = True
        if not found:
            raise StorageError("no such file")


class UploadSession:
    def __init__(self, vault, user, fid, meta, aead, f, next_index):
        self.vault, self.user, self.fid, self.meta, self.aead, self.f = vault, user, fid, meta, aead, f
        self.next_index = next_index
        self.total = meta["chunks"]

    def append(self, index, data):
        if index != self.next_index or index >= self.total:
            raise StorageError("unexpected chunk index")
        expected = CHUNK_SIZE if index < self.total - 1 else self.meta["size"] - index * CHUNK_SIZE
        if len(data) != expected:
            raise StorageError("bad chunk length")
        nonce = os.urandom(12)
        ct = self.aead.encrypt(nonce, data, Vault._chunk_aad(self.fid, index, self.total))
        self.f.write(REC.pack(nonce, len(ct)) + ct)
        self.f.flush()
        self.next_index += 1

    def finish(self):
        """Verify everything we stored (decrypt + SHA-256 vs. what the client declared), then publish."""
        mp, pp, ep = self.vault._paths(self.user, self.fid)
        self.f.flush()
        os.fsync(self.f.fileno())
        self.f.close()
        if self.next_index != self.total:
            raise StorageError("upload incomplete")
        h, n = hashlib.sha256(), 0
        for _, pt in self.vault.iter_chunks(pp, self.aead, self.fid, self.total):
            h.update(pt)
            n += len(pt)
        if n != self.meta["size"] or h.hexdigest() != self.meta["sha256"]:
            pp.unlink(missing_ok=True)
            mp.unlink(missing_ok=True)
            raise StorageError("integrity check failed: content does not match the declared SHA-256")
        os.replace(pp, ep)

    def close(self):
        if not self.f.closed:
            self.f.close()


# --------------------------------------------------------------------------- network
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(120)
        peer = "%s:%d" % self.client_address
        try:
            ch = server_handshake(self.request, self.server.identity)
            user = self._auth(ch)
            if user is None:
                log(f"{peer}: authentication failed")
                return
            log(f"{peer}: user '{user}' connected")
            self._loop(ch, user)
        except (ConnectionError, ProtocolError, OSError, ValueError) as e:
            log(f"{peer}: connection ended ({type(e).__name__}: {e})")

    def _auth(self, ch):
        for _ in range(3):
            h, _data = ch.recv_msg()
            u, p = h.get("user"), h.get("password")
            if h.get("cmd") == "auth" and isinstance(u, str) and isinstance(p, str) \
                    and self.server.users.verify(u, p):
                ch.send_msg({"ok": True})
                return u
            time.sleep(1)                                   # slow down password guessing
            ch.send_msg({"ok": False, "error": "authentication failed"})
        return None

    def _loop(self, ch, user):
        vault = self.server.vault
        while True:
            h, _data = ch.recv_msg()
            cmd = h.get("cmd")
            try:
                if cmd == "list":
                    ch.send_msg({"ok": True, "files": vault.list(user)})
                elif cmd == "put_begin":
                    self._put(ch, user, h)
                elif cmd == "get":
                    self._get(ch, user, h)
                elif cmd == "delete":
                    fid = h.get("file_id")
                    if not (isinstance(fid, str) and ID_RE.match(fid)):
                        raise StorageError("invalid file id")
                    vault.delete(user, fid)
                    ch.send_msg({"ok": True})
                elif cmd == "quit":
                    return
                else:
                    raise ProtocolError("unknown command")
            except Busy as e:
                ch.send_msg({"ok": False, "error": str(e), "retry": True})
            except StorageError as e:
                ch.send_msg({"ok": False, "error": str(e)})

    def _put(self, ch, user, h):
        name = clean_name(h.get("name", ""))
        size, sha = h.get("size"), h.get("sha256")
        if not (isinstance(size, int) and 0 <= size <= MAX_FILE_SIZE and isinstance(sha, str) and SHA_RE.match(sha)):
            raise StorageError("invalid upload parameters")
        fid = hashlib.sha256(f"{name}\0{sha}".encode()).hexdigest()[:32]
        if not self.server.claim(user, fid):
            raise Busy("this upload is still active on another connection")
        sess = None
        try:
            sess = self.server.vault.open_upload(user, fid, name, size, sha)
            if sess is None:
                ch.send_msg({"ok": True, "exists": True, "file_id": fid})
                return
            ch.send_msg({"ok": True, "file_id": fid, "next_chunk": sess.next_index, "total": sess.total})
            try:
                while True:                                  # chunks are pipelined: no per-chunk ack
                    m, data = ch.recv_msg()
                    c = m.get("cmd")
                    if c == "chunk":
                        sess.append(m.get("index"), data)
                    elif c == "put_end":
                        sess.finish()
                        ch.send_msg({"ok": True, "file_id": fid})
                        log(f"stored {name!r} ({size} bytes) as {fid} for '{user}'")
                        return
                    else:
                        raise ProtocolError("unexpected message during upload")
            except StorageError as e:
                ch.send_msg({"ok": False, "error": str(e)})
                raise ConnectionError(f"upload aborted: {e}")
        finally:
            if sess:
                sess.close()
            self.server.release(user, fid)

    def _get(self, ch, user, h):
        fid, start = h.get("file_id"), h.get("start", 0)
        if not (isinstance(fid, str) and ID_RE.match(fid) and isinstance(start, int) and start >= 0):
            raise StorageError("invalid request")
        meta, aead, ep = self.server.vault.open_download(user, fid)
        if start > meta["chunks"]:
            raise StorageError("invalid resume offset")
        ch.send_msg({"ok": True, "name": meta["name"], "size": meta["size"],
                     "chunks": meta["chunks"], "sha256": meta["sha256"]})
        try:
            for idx, pt in self.server.vault.iter_chunks(ep, aead, fid, meta["chunks"], start):
                ch.send_msg({"type": "chunk", "index": idx}, pt)
            ch.send_msg({"type": "done"})
        except StorageError as e:
            log(f"STORAGE INTEGRITY ERROR for {fid}: {e}")
            ch.send_msg({"type": "error", "error": str(e)})


class SFTServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, data_dir):
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        self.identity = load_identity(data_dir / "identity.key")
        self.vault = Vault(data_dir, load_master_key(data_dir))
        self.users = UserStore(data_dir / "users.json")
        self._active, self._lock = set(), threading.Lock()
        super().__init__(addr, Handler)

    @property
    def fingerprint(self):
        return fingerprint(raw_public(self.identity.public_key()))

    def claim(self, user, fid):
        with self._lock:
            if (user, fid) in self._active:
                return False
            self._active.add((user, fid))
            return True

    def release(self, user, fid):
        with self._lock:
            self._active.discard((user, fid))


def main():
    ap = argparse.ArgumentParser(description="Secure File Transfer server")
    ap.add_argument("--data-dir", default="sft_data")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=9000)
    a = sub.add_parser("adduser")
    a.add_argument("name")
    args = ap.parse_args()

    if args.cmd == "adduser":
        data_dir = Path(args.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        pw = getpass.getpass("Password: ")
        if len(pw) < 8 or pw != getpass.getpass("Repeat:   "):
            raise SystemExit("passwords differ or are shorter than 8 characters")
        UserStore(data_dir / "users.json").add(args.name, pw)
        print("user created")
        return

    srv = SFTServer((args.host, args.port), args.data_dir)
    log(f"listening on {args.host}:{args.port}")
    log(f"SERVER FINGERPRINT (give this to clients out-of-band): {srv.fingerprint}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("shutting down")


if __name__ == "__main__":
    main()
