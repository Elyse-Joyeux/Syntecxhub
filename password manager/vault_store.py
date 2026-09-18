import os
import json
import time
from dataclasses import dataclass, field

from vault_crypto import (
    derive_key, make_verifier, encrypt, decrypt, b64e, b64d,
    SALT_SIZE, PBKDF2_ITERATIONS,
)

VAULT_FORMAT_VERSION = 1


class VaultError(Exception):
    pass


class WrongPasswordError(VaultError):
    pass


class VaultCorruptError(VaultError):
    pass


@dataclass
class Vault:
    path: str
    key: bytes
    entries: list = field(default_factory=list)

    #entry operations (all operate on the in-memory, decrypted list)
    def add_entry(self, site: str, username: str, password: str, notes: str = "") -> dict:
        entry = {
            "id": _next_id(self.entries),
            "site": site,
            "username": username,
            "password": password,
            "notes": notes,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.entries.append(entry)
        return entry

    def delete_entry(self, entry_id: int) -> bool:
        before = len(self.entries)
        self.entries = [e for e in self.entries if e["id"] != entry_id]
        return len(self.entries) < before

    def get_entry(self, entry_id: int) -> dict | None:
        for e in self.entries:
            if e["id"] == entry_id:
                return e
        return None

    def search(self, query: str) -> list:
        q = query.lower()
        return [
            e for e in self.entries
            if q in e["site"].lower() or q in e["username"].lower() or q in e.get("notes", "").lower()
        ]

    def list_all(self) -> list:
        return list(self.entries)

    #persistence
    def save(self):
        plaintext = json.dumps({"entries": self.entries}).encode("utf-8")
        nonce, ciphertext = encrypt(plaintext, self.key)
        
        # Re-read salt/iterations from the existing file if present, else this
        # is a brand-new vault and the caller (create_vault) set them up already.

        salt = self._salt
        on_disk = {
            "version": VAULT_FORMAT_VERSION,
            "kdf": {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": PBKDF2_ITERATIONS,
                "salt": b64e(salt),
            },
            "verifier": make_verifier(self.key),
            "cipher": {"algorithm": "AES-256-GCM", "nonce": b64e(nonce)},
            "ciphertext": b64e(ciphertext),
        }
        tmp_path = self.path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(on_disk, f, indent=2)
        os.replace(tmp_path, self.path)  # atomic on POSIX and Windows

    _salt: bytes = field(default=b"", repr=False)


def create_vault(path: str, master_password: str) -> Vault:
    """Create a brand-new, empty vault file protected by master_password."""
    if os.path.exists(path):
        raise VaultError(f"A vault already exists at {path}. Delete it first or choose another path.")
    salt = os.urandom(SALT_SIZE)
    key = derive_key(master_password, salt)
    vault = Vault(path=path, key=key, entries=[])
    vault._salt = salt
    vault.save()
    return vault


def unlock_vault(path: str, master_password: str) -> Vault:
    """Open an existing vault, verifying the master password before decrypting."""
    if not os.path.exists(path):
        raise VaultError(f"No vault found at {path}. Run 'init' first.")

    with open(path, "r") as f:
        try:
            on_disk = json.load(f)
        except json.JSONDecodeError as exc:
            raise VaultCorruptError("Vault file is not valid JSON — it may be corrupted.") from exc

    try:
        salt = b64d(on_disk["kdf"]["salt"])
        nonce = b64d(on_disk["cipher"]["nonce"])
        ciphertext = b64d(on_disk["ciphertext"])
        stored_verifier = on_disk["verifier"]
    except KeyError as exc:
        raise VaultCorruptError(f"Vault file is missing an expected field: {exc}") from exc

    key = derive_key(master_password, salt)

    if make_verifier(key) != stored_verifier:
        raise WrongPasswordError("Incorrect master password.")

    try:
        plaintext = decrypt(nonce, ciphertext, key)
    except Exception as exc:

        # GCM tag mismatch lands here too, as a second line of defense even
        # though the verifier check above should already have caught it.
        
        raise VaultCorruptError("Decryption failed — file may be corrupted or tampered with.") from exc

    data = json.loads(plaintext.decode("utf-8"))
    vault = Vault(path=path, key=key, entries=data.get("entries", []))
    vault._salt = salt
    return vault


def _next_id(entries: list) -> int:
    return (max((e["id"] for e in entries), default=0)) + 1
