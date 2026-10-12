import hashlib
import hmac
import json
import os
import re
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTO = b"SFT-v1"
CHUNK_SIZE = 1024 * 1024  # 1 MiB plaintext per chunk
MAX_FRAME = CHUNK_SIZE + 4096  # reject absurd frame sizes (DoS protection)
MAX_HEADER = 64 * 1024


class ProtocolError(Exception):
    """Security or protocol violation(bad MAC, bad signature, malformed data)."""


class RetryLater(ConnectionError):
    """Server ask the client to try again shortly (e.g. previous connection still closing)."""


# helpers
def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("Connection closed by peer")
        buf += part

    return bytes(buf)


def raw_public(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(identity_pub_raw: bytes) -> str:
    return hashlib.sha256(identity_pub_raw).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(block)

    return h.hexdigest()


def clean_name(name):
    """Never trust a file name from the network: strip paths and odd characters."""
    name = os.path.basename(str(name).replace("\\", "/"))
    name = re.sub(r'[\x00-\x1f<>:"|?*]', "_", name).strip(" .")
    return name[:200] or "unnamed"


def _transcript(c_eph, c_nonce, s_eph, s_nonce, s_id):
    return hashlib.sha256(PROTO + c_eph + c_nonce + s_eph + s_nonce + s_id).digest()


# channel
class SecureChannel:
    def __init__(self, sock, shared_secret, transcript_hash, is_server):
        okm = HKDF(
            algorithm=hashes.SHA256(),
            length=128,
            salt=transcript_hash,
            info=PROTO + b" key expansion",
        ).derive(shared_secret)

        c2s_enc, c2s_mac, s2c_enc, s2c_mac = (
            okm[i : i + 32] for i in range(0, 128, 32)
        )
        if is_server:
            self.send_keys, self.recv_keys = (s2c_enc, s2c_mac), (c2s_enc, c2s_mac)

        else:
            self.send_keys, self.recv_keys = (c2s_enc, c2s_mac), (s2c_enc, s2c_mac)
        self.sock = sock
        self.send_seq = 0
        self.recv_seq = 0

    @staticmethod
    def _ctr(key, seq):
        # 128 bit counter block
        # each frame therefore gets a unique and non-overlapping key stream
        return Cipher(algorithms.AES(key), modes.CTR(struct.pack(">Q", seq) + bytes(8)))

    def send(self, payload: bytes):
        enc_key, mac_key = self.send_keys
        enc = self._ctr(enc_key, self.send_seq).encryptor()
        ct = enc.update(payload) + enc.finalize()
        tag = hmac.new(
            mac_key, struct.pack(">QI", self.send_seq, len(ct)) + ct, hashlib.sha256
        ).digest()
        self.sock.sendall(struct.pack(">I", len(ct)) + ct + tag)
        self.send_seq += 1

    def recv(self) -> bytes:
        (n,) = struct.unpack(">I", recv_exact(self.sock, 4))
        if n > MAX_FRAME:
            raise ProtocolError("Frame too large")
        body = recv_exact(self.sock, n + 32)
        ct, tag = body[:n], body[n:]
        enc_key, mac_key = self.recv_keys
        expected = hmac.new(
            mac_key, struct.pack(">QI", self.recv_seq, n) + ct, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise ProtocolError(
                "MAC check failed: data was tampered with, replayed or reordered"
            )

        dec = self._ctr(enc_key, self.recv_seq).decryptor()
        self.recv_seq += 1
        return dec.update(ct) + dec.finalize()

    # JSON header + binary body(optional)
    def send_msg(self, header: dict, data: bytes = b""):
        h = json.dumps(header, separators=(",", ":")).encode()
        self.send(struct.pack(">I", len(h)) + h + data)

    def recv_msg(self):
        p = self.recv()
        if len(p) < 4:
            raise ProtocolError("Short message")
        (h1,) = struct.unpack(">I", p[:4])
        if h1 > MAX_HEADER or 4 + h1 > len(p):
            raise ProtocolError("Bad header length")
        try:
            header = json.loads(p[4 : 4 + h1])
        except ValueError:
            raise ProtocolError("Bad header")

        if not isinstance(header, dict):
            raise ProtocolError("Bad header")
        return header, p[4 + h1 :]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# handshakes
def server_handshake(sock, identity_key) -> SecureChannel:
    hello = recv_exact(sock, 64)
    c_eph, c_nonce = hello[:32], hello[32:]
    eph = X25519PrivateKey.generate()
    s_eph, s_nonce = raw_public(eph.public_key()), os.urandom(32)
    s_id = raw_public(identity_key.public_key())
    th = _transcript(c_eph, c_nonce, s_eph, s_nonce, s_id)
    sock.sendall(s_eph + s_nonce + s_id + identity_key.sign(th))
    shared = eph.exchange(X25519PublicKey.from_public_bytes(c_eph))
    return SecureChannel(sock, shared, th, is_server=True)


def client_handshake(sock, verify_identity) -> SecureChannel:
    """verify_identity(fingerprint_hex) must raise ProtocolError if the server is not trusted."""
    eph = X25519PrivateKey.generate()
    c_eph, c_nonce = raw_public(eph.public_key()), os.urandom(32)
    sock.sendall(c_eph + c_nonce)
    reply = recv_exact(sock, 160)
    s_eph, s_nonce, s_id, sig = reply[:32], reply[32:64], reply[64:96], reply[96:]
    th = _transcript(c_eph, c_nonce, s_eph, s_nonce, s_id)
    try:
        Ed25519PublicKey.from_public_bytes(s_id).verify(sig, th)
    except Exception:
        raise ProtocolError("server handshake signature invalid")
    verify_identity(fingerprint(s_id))  # pinning / TOFU
    shared = eph.exchange(X25519PublicKey.from_public_bytes(s_eph))
    return SecureChannel(sock, shared, th, is_server=False)
