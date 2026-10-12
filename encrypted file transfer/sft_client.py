import argparse
import getpass
import json
import os
import socket
import sys
import time
from pathlib import Path

from sft_common import (
    CHUNK_SIZE,
    ProtocolError,
    RetryLater,
    clean_name,
    client_handshake,
    sha256_file,
)

RETRYABLE = (
    ConnectionError,
    TimeoutError,
    socket.timeout,
)  # retryLater is a connectionError


class ClientError(Exception):
    """Fatal error (wrong password, integrity failure, ...). Not retried."""


class Client:
    def __init__(
        self,
        host,
        port,
        user,
        password,
        known_hosts=None,
        fingerprint=None,
        auto_trust=False,
        retries=5,
        quiet=False,
    ):
        self.host, self.port, self.user, self.password = host, port, user, password
        self.known_hosts = Path(
            known_hosts or Path.home() / ".sft" / "known_servers.json"
        )
        self.expected_fp, self.auto_trust = fingerprint, auto_trust
        self.retries, self.quiet = retries, quiet

    def say(self, msg):
        if not self.quiet:
            print(msg, flush=True)

    # server identity pinning (man-in-the-middle defence)
    def _verify_server(self, fp):
        key = f"{self.host}:{self.port}"
        if self.expected_fp:
            if fp != self.expected_fp.lower():
                raise ProtocolError(
                    f"Server fingerprint {fp} does not match the one you supplied - ABORTING"
                )
            return
        known = (
            json.loads(self.known_hosts.read_text())
            if self.known_hosts.exists()
            else {}
        )

        if key in known:
            if known[key] != fp:
                raise ProtocolError(
                    f"SERVER IDENTITY CHANGED for {key}!\n pinned: {known[key]}\n got:    {fp}\n"
                    "Possible man-in-the-middle attack - ABORTING."
                )
            return

        if not self.auto_trust:
            print(f"First connection to {key}. \nServer fingerprint: {fp}")
            if (
                input(
                    "Does this match the fingerprint the server admin gave you? [yes/no] "
                ).strip()
                != "yes"
            ):
                raise ProtocolError("Server not trusted")

        known[key] = fp
        self.known_hosts.parent.mkdir(parents=True, exist_ok=True)
        self.known_hosts.write_text(json.dumps(known, indent=2))

    def _connect(self):
        sock = socket.create_connection((self.host, self.port), timeout=30)
        try:
            ch = client_handshake(sock, self._verify_server)
            ch.send_msg({"cmd": "auth", "user": self.user, "password": self.password})
            r, _ = ch.recv_msg()

        except BaseException:
            sock.close()
            raise
        if not r.get("ok"):
            ch.close()
            raise ClientError("authentication failed")
        return ch

    @staticmethod
    def _check(r):
        if not r.get("ok"):
            if r.get("retry"):
                raise RetryLater(r.get("error", "busy"))
            raise ClientError(r.get("error", "request failed"))

        return r

    def _progress(self, label, done, total):
        if not self.quiet:
            pct = 100 if total == 0 else int(done * 100 / total)
            print(f"\r{label}: {pct:3d}% ({done}/{total} chunks)", end="", flush=True)

    # upload (chunked, pipelined, resumable)
    def put(self, path, _drop_after=None):
        path = Path(path)
        size, sha = path.stat().st_size, sha256_file(path)
        total = -(-size // CHUNK_SIZE)
        for attempt in range(self.retries + 1):
            ch = None
            try:
                ch = self._connect()
                ch.send_msg(
                    {"cmd": "put_begin", "name": path.name, "size": size, "sha256": sha}
                )
                r = self._check(ch.recv_msg()[0])
                if r.get("exists"):
                    self.say("Already stored on the server")
                    return r["file_id"]
                start = r["next_chunk"]
                if start:
                    self.say(f"Resuming upload at chunk {start}/{total}")
                with open(path, "rb") as f:
                    f.seek(start * CHUNK_SIZE)
                    for idx in range(start, total):
                        ch.send_msg({"cmd": "chunk", "index": idx}, f.read(CHUNK_SIZE))
                        self._progress("upload", idx + 1, total)
                        if (
                            _drop_after is not None
                            and attempt == 0
                            and idx + 1 - start == _drop_after
                        ):
                            raise ConnectionResetError(
                                "Simulated network failure"
                            )  # test hook

                ch.send_msg({"cmd": "put_end"})
                r = self._check(ch.recv_msg()[0])
                self.say(f"\nUploaded, file id: {r['file_id']}")
                return r["file_id"]

            except RETRYABLE as e:
                self.say(
                    f"\nConnectio problem ({e}); retry {attempt + 1}/{self.retries}"
                )
                time.sleep(min(0.5 * 2**attempt, 5))

            finally:
                if ch:
                    ch.close()
        raise ClientError("Giving up after repeated connection failures")

    # download (resumable, end to end sha-256 verification)
    def get(self, file_id, output=None, force=False, _drop_after=None):
        part = Path((output or file_id) + ".part")
        for attempt in range(self.retries + 1):
            ch = None
            try:
                start = (part.stat().st_size // CHUNK_SIZE) if part.exists() else 0
                ch = self._connect()
                ch.send_msg({"cmd": "get", "file_id": file_id, "start": start})
                meta = self._check(ch.recv_msg()[0])
                final = (
                    Path(output) if output else Path(clean_name(meta["name"]))
                )  # never trust server paths
                if final.exists() and not force:
                    raise ClientError(f"{final} already exists (use --force)")
                if start:
                    self.say(f"resuming download at chunk {start}/{meta['chunks']}")
                expected = start
                with open(part, "r+b" if part.exists() else "wb") as f:
                    f.truncate(start * CHUNK_SIZE)
                    f.seek(start * CHUNK_SIZE)
                    while True:
                        m, data = ch.recv_msg()
                        t = m.get("type")
                        if t == "chunk":
                            if m.get("index") != expected or len(data) > CHUNK_SIZE:
                                raise ProtocolError("unexpected chunk from server")
                            f.write(data)
                            expected += 1
                            self._progress("download", expected, meta["chunks"])
                            if (
                                _drop_after is not None
                                and attempt == 0
                                and expected - start == _drop_after
                            ):
                                raise ConnectionResetError(
                                    "simulated network failure"
                                )  # test hook
                        elif t == "done":
                            break
                        elif t == "error":
                            raise ClientError(f"server reported: {m.get('error')}")
                        else:
                            raise ProtocolError("unexpected message")
                if expected != meta["chunks"]:
                    raise ProtocolError("download incomplete")
                if (
                    part.stat().st_size != meta["size"]
                    or sha256_file(part) != meta["sha256"]
                ):
                    part.unlink()
                    raise ClientError(
                        "INTEGRITY CHECK FAILED: downloaded data does not match the stored SHA-256"
                    )
                os.replace(part, final)
                self.say(f"\nsaved to {final} (SHA-256 verified)")
                return final
            except RETRYABLE as e:
                self.say(
                    f"\nconnection problem ({e}); retry {attempt + 1}/{self.retries}"
                )
                time.sleep(min(0.5 * 2**attempt, 5))
            finally:
                if ch:
                    ch.close()
        raise ClientError("giving up after repeated connection failures")

    def ls(self):
        ch = self._connect()
        try:
            ch.send_msg({"cmd": "list"})
            return self._check(ch.recv_msg()[0])["files"]
        finally:
            ch.close()

    def rm(self, file_id):
        ch = self._connect()
        try:
            ch.send_msg({"cmd": "delete", "file_id": file_id})
            self._check(ch.recv_msg()[0])
        finally:
            ch.close()


def main():
    ap = argparse.ArgumentParser(description="Secure File Transfer client")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--user", required=True)
    ap.add_argument(
        "--fingerprint", help="expected server fingerprint (obtained out-of-band)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ls")
    sub.add_parser("put").add_argument("file")
    g = sub.add_parser("get")
    g.add_argument("file_id")
    g.add_argument("-o", "--output")
    g.add_argument("--force", action="store_true")
    sub.add_parser("rm").add_argument("file_id")
    args = ap.parse_args()

    password = os.environ.get("SFT_PASSWORD") or getpass.getpass("Password: ")
    c = Client(args.host, args.port, args.user, password, fingerprint=args.fingerprint)
    try:
        if args.cmd == "put":
            c.put(args.file)
        elif args.cmd == "get":
            c.get(args.file_id, args.output, args.force)
        elif args.cmd == "rm":
            c.rm(args.file_id)
            print("deleted")
        else:
            for f in c.ls():
                print(f"{f['file_id']}  {f['size']:>12}  {f['name']}")
    except (ClientError, ProtocolError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
