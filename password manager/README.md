# Local Password Manager

A local-only password manager that encrypts all credentials at rest with
AES-256-GCM, protected by a master password. Built as a cybersecurity /
software-engineering project — every design decision below is something
you should be able to explain in a review or interview.

Ships with two front ends over one shared, tested encryption core:
a desktop GUI (`pm_gui.py`) and a CLI (`pm.py`).

## Features

- Create a new encrypted vault protected by a master password
- **Add** a credential (site, username, password, notes), with a built-in
  strong-password generator
- **Retrieve** any entry, including its password
- **Search** by site, username, or notes
- **Delete** an entry (with confirmation)
- Generate a strong random password on demand without saving it

## Setup

Requires Python 3.10+ and the `cryptography` package.

### Linux (including Kali)

Kali and modern Debian block system-wide `pip install` by default (PEP 668),
so use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If Tkinter (needed for the GUI only) isn't already installed:

```bash
sudo apt install python3-tk
```

Every new terminal session needs `source venv/bin/activate` run again
before `python pm_gui.py` or `python pm.py` will find `cryptography`.

### Windows

Tkinter ships with the standard python.org installer, so no extra install
step is needed for the GUI.

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

If `python` isn't recognized, use `py` instead. Use Python from
[python.org](https://python.org) rather than the Microsoft Store build.

## Running It

### GUI (recommended for a demo)

```bash
python pm_gui.py
```

- No `vault.json` in the current folder → shows a **Create Vault** screen
  (master password + confirmation). Creating the vault logs you straight
  in — no separate unlock step.
- An existing `vault.json` → shows an **Unlock** screen.
- Once inside: a searchable table of entries, **+ Add Entry** (with a
  **Generate** button for strong passwords), **View / Copy** to see a full
  entry and copy fields to the clipboard, **Delete** with a confirmation
  prompt, and a standalone **Generate Password…** dialog for one-off
  passwords you don't want to save.
- Dark theme throughout; the master password field is masked.

### CLI

```bash
python pm.py init                    # create ./vault.json
python pm.py add                     # add a credential
python pm.py list                    # list all entries
python pm.py get 1                   # show entry #1 in full
python pm.py search github           # search
python pm.py delete 1                # delete entry #1
python pm.py generate 24             # generate a 24-char password, print only

# use a vault somewhere else / a different vault:
python pm.py --vault /path/to/other-vault.json list
```

## Security Design

| Concern | How it's handled |
|---|---|
| **Encryption at rest** | AES-256-GCM — an *authenticated* cipher, so tampering with the file is detected (wrong tag → decryption fails), not silently accepted. |
| **Key derivation** | PBKDF2-HMAC-SHA256, 480,000 iterations (OWASP's current baseline), with a random 16-byte salt per vault. Makes brute-forcing the master password computationally expensive even if the file leaks. |
| **Nonce handling** | A fresh random 12-byte nonce is generated on every save. AES-GCM security depends entirely on never reusing a nonce with the same key — reuse can leak the authentication key outright. |
| **Password verification** | A SHA-256 hash of the *derived key* (not the password, not the key itself) is stored as a "verifier," so the tool can say "wrong password" without ever storing anything reversible. |
| **Atomic writes** | Saves write to `vault.json.tmp` then `os.replace()` it into place, so a crash mid-write can't leave a half-written, unreadable vault. |
| **No plaintext on disk, ever** | Only the encrypted blob plus non-secret metadata (salt, nonce, KDF params) is written to disk. Decrypted entries exist only in memory for the life of the process. |
| **Secure input** | The CLI reads passwords with `getpass`, so they never echo to the terminal or land in shell history. |
| **Secure randomness** | Generated passwords use the `secrets` module (CSPRNG), never `random`. |

## Known Limitations

Naming these explicitly is good security thinking, not a weakness to hide:

- **No memory protection.** While the vault is open, decrypted secrets sit
  in regular Python objects in RAM. True memory hardening (mlock, zeroing
  buffers) is out of scope for a script in a managed-memory language.
- **No brute-force lockout.** PBKDF2's iteration count is the only throttle
  on guessing; there's no lockout after N failed attempts.
- **Master password strength isn't enforced beyond a length check.** A
  natural next feature is a strength estimator (e.g. `zxcvbn`) with a
  minimum score requirement.
- **No clipboard auto-clear.** The GUI can copy a field to the clipboard,
  but nothing clears it automatically after a timeout.
- **Single-vault, single-user, local file only.** No sync, no multi-device
  merge, no sharing.

## File Format

`vault.json` is not encrypted as a whole file — only the `ciphertext` field
is secret. Everything else is metadata needed to redo the key derivation:

```json
{
  "version": 1,
  "kdf": {"algorithm": "PBKDF2-HMAC-SHA256", "iterations": 480000, "salt": "<base64>"},
  "verifier": "<sha256 hex>",
  "cipher": {"algorithm": "AES-256-GCM", "nonce": "<base64>"},
  "ciphertext": "<base64>"
}
```

## Project Structure

```
password_manager/
├── vault_crypto.py   # key derivation, AES-GCM encrypt/decrypt, verifier logic
├── vault_store.py    # on-disk format, load/unlock/save lifecycle, entry CRUD
├── pm.py             # CLI (argparse-based commands)
├── pm_gui.py          # Tkinter desktop GUI, built on pm.py + vault_store.py
├── requirements.txt
└── .gitignore
```

`pm.py` and `pm_gui.py` are both thin front ends over the same
`vault_crypto.py` + `vault_store.py` core — no encryption or storage logic
is duplicated between them. That's the point worth making in a demo: one
place to audit the crypto, any number of interfaces on top of it.

## Note on the Clipboard

The GUI's copy actions place values on the system clipboard for
convenience. As the confirmation dialog reminds you, nothing here
auto-clears it — clear it yourself after a demo or after real use.