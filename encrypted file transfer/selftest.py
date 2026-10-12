import hashlib
import json
import os
import shutil
import socket
import tempfile
import threading
from pathlib import Path

from sft_client import Client, ClientError
from sft_common import CHUNK_SIZE, ProtocolError
from sft_server import SFTServer


def tamper_proxy(target, flip_at=5000):
    """Active man-in-the-middle: relays traffic but flips one bit in the client=>server stream."""
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(5)

    def pump(src, dst, flip):
        n = 0
        try:
            while True:
                b = src.recv(65536)
                if not b:
                    break
                if flip and n <= flip_at < n + len(b):
                    b = bytearray(b)
                    b[flip_at - n] ^= 1
                    b = bytes(b)

                n += len(b)
                dst.sendall(b)

        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass

    def accept_loop():
        while True:
            c, _ = ls.accept()
            s = socket.create_connection(target)
            threading.Thread(target=pump, args=(c, s, True), daemon=True).start()
            threading.Thread(target=pump, args=(s, c, False), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return ls.getsockname()


def expect(exc_types, fn, label):
    try:
        fn()
    except exc_types as e:
        print(f" PASS {label} -> {type(e).__name__}: {str(e).splitlines()[0][:90]}")
        return

    raise AssertionError(f"FAILED: {label} was not rejected")


def main():
    tmp = Path(tempfile.mkdtemp())
    os.chdir(tmp)

    try:
        srv = SFTServer(("127.0.0.1", 0), tmp / "data")
        srv.users.add("elyse", "correct horse battery")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        host, port = srv.server_address
        kh = tmp / "known.json"
        mk = lambda **kw: Client(
            host,
            port,
            "elyse",
            kw.pop("pw", "correct horse battery"),
            known_hosts=kh,
            auto_trust=True,
            quiet=True,
            **kw,
        )
        c = mk()

        marker = b"TOP-SECRET-MARKER-12345"
        src = tmp / "secret.bin"
        src.write_bytes(marker + os.urandom(int(CHUNK_SIZE * 4.5)))
        want = hashlib.sha256(src.read_bytes()).hexdigest()

        print("1. Upload with a simulated network drop after 2 chunks (resume)")
        fid = c.put(src, _drop_after=2)
        assert fid in [f["file_id"] for f in c.ls()]
        print(" PASS upload resumed and completed")

        print("2. Encryption at rest")
        for p in (tmp / "data" / "files").rglob("*"):
            if p.is_file():
                assert marker not in p.read_bytes(), f"plaintext found in {p}"
        print(" PASS no plaintext found anywhere on server disk")
        print("3. Download with a simulated drop (resume) + SHA-256 verification")
        out = c.get(fid, "restored.bin", _drop_after=3)
        assert hashlib.sha256(out.read_bytes()).hexdigest() == want
        print(" PASS  restored file identical to original")

        print("4. Tampering with stored data")
        enc = next((tmp / "data" / "files").rglob("*.enc"))
        good = enc.read_bytes()
        bad = bytearray(good)
        bad[CHUNK_SIZE // 2] ^= 1
        enc.write_bytes(bytes(bad))
        expect(
            ClientError,
            lambda: c.get(fid, "tampered.bin"),
            "flipped bit in an encrypted chunk",
        )
        Path("tampered.bin.part").unlink(missing_ok=True)
        enc.write_bytes(good)
        meta_p = enc.with_suffix(".meta")
        meta = json.loads(meta_p.read_text())
        meta_p.write_text(json.dumps({**meta, "name": "evil.exe"}))
        expect(ClientError, lambda: c.get(fid, "tampered2.bin"), "edited metadata file")
        meta_p.write_text(json.dumps(meta))

        print("5. Man-in-the-middle")
        kh2 = tmp / "known2.json"
        kh2.write_text(json.dumps({f"{host}:{port}": "00" * 32}))
        expect(
            ProtocolError,
            lambda: Client(host, port, "elyse", "x", known_hosts=kh2, quiet=True).ls(),
            "server identity differs from pinned fingerprint",
        )
        phost, pport = tamper_proxy((host, port))
        evil = Client(
            phost,
            pport,
            "elyse",
            "correct horse battery",
            known_hosts=tmp / "k3.json",
            auto_trust=True,
            quiet=True,
            retries=1,
        )
        src2 = tmp / "other.bin"
        src2.write_bytes(os.urandom(CHUNK_SIZE * 2))
        expect(
            (ClientError, ProtocolError),
            lambda: evil.put(src2),
            "attacker flips one bit of the encrypted stream",
        )

        print("6. Authentication")
        expect(ClientError, lambda: mk(pw="wrong password").ls(), "wrong password")

        print("\n ALL SECURITY CHECKS PASSED")

    finally:
        os.chdir(tempfile.gettempdir())
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
