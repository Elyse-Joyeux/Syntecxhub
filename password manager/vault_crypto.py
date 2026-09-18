import os
import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 480_000  # OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256
SALT_SIZE = 16
NONCE_SIZE = 12  # standard for AES-GCM
KEY_SIZE = 32  # AES-256


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES-256 key from the master password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(master_password.encode("utf-8"))


def make_verifier(key: bytes) -> str:
    """
    A one-way check value used to confirm the master password is correct
    before we even attempt to decrypt the real data. This is NOT the key
    itself — it's a SHA-256 hash of the key, so it can't be reversed to
    recover the key or password.
    """
    return hashlib.sha256(key).hexdigest()


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext. Raises cryptography.exceptions.InvalidTag
    if the key is wrong or the data has been tampered with — this is GCM's
    built-in integrity check, not something we implement ourselves.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))
