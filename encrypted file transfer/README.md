# Encrypted File Transfer & Secure File Storage (Python)

Client/server file transfer with an authenticated encrypted channel, chunked and resumable transfers,
end-to-end integrity checks, and files encrypted at rest on the server.

## Quick start

```bash
pip install -r requirements.txt            # only dependency: cryptography

python selftest.py                          # runs every security check automatically

# terminal 1 - server
python sft_server.py adduser alice          # create user (password >= 8 chars)
python sft_server.py serve --port 9000      # prints SERVER FINGERPRINT

# terminal 2 - client
python sft_client.py --user alice put bigfile.iso     # confirm fingerprint on first use
python sft_client.py --user alice ls
python sft_client.py --user alice get <file_id> -o restored.iso
python sft_client.py --user alice rm  <file_id>
```

Optional: `set SFT_MASTER_PASSPHRASE=...` (Windows) / `export SFT_MASTER_PASSPHRASE=...` (Linux) before
starting the server so the master key is derived from a passphrase and **never stored on disk**.

## Files

| File | Purpose |
|---|---|
| `sft_common.py` | Handshake, AES-256-CTR + HMAC-SHA256 framing, helpers |
| `sft_server.py` | Authentication, encrypted vault, resumable upload/download |
| `sft_client.py` | CLI + `Client` class: pinning, chunking, resume, retries |
| `selftest.py`   | Automated tests: resume, at-rest encryption, tampering, MITM, auth |

## Design

### 1. Secure channel
1. Client and server exchange **ephemeral X25519** public keys (forward secrecy).
2. Server signs the handshake transcript with its long-term **Ed25519 identity key**.
   The client checks the signature and **pins the key fingerprint** (SHA-256).
3. **HKDF-SHA256** derives four independent keys: encryption + MAC, one pair per direction.
4. Each frame: `len | AES-256-CTR(ciphertext) | HMAC-SHA256(seq || len || ciphertext)`.
   The MAC is checked **before** decrypting (encrypt-then-MAC), using constant-time comparison.
   The implicit sequence number in the MAC defeats replay, reordering and frame deletion.
5. The user logs in *inside* the encrypted channel; passwords are stored as salted **scrypt** hashes.

### 2. Chunking, integrity and resume
* Files are split into 1 MiB chunks; each chunk is its own encrypted frame (low memory use for huge files).
* Integrity layers: per-frame HMAC (in transit) -> AES-GCM tag per chunk (at rest) ->
  whole-file **SHA-256** (checked by the server after upload, and by the client after download).
* **Upload resume:** upload id = hash(name, SHA-256). If the connection drops, the client reconnects, the
  server reports how many complete chunks it already holds (`next_chunk`), and the client continues from there.
  A half-written trailing record is discarded. The server verifies the full file before publishing it.
* **Download resume:** the client keeps `<name>.part` and asks for the chunks after the last complete one.
* The client retries automatically with back-off; security failures (bad MAC, wrong fingerprint,
  integrity errors) are **never** retried.

### 3. Encryption at rest and safe retrieval
* Every file has its own random 256-bit **DEK**. The DEK is wrapped with AES-256-GCM using the **master key (KEK)**.
* Stored as records `nonce | length | AES-256-GCM ciphertext+tag`.
  The GCM AAD binds `file id + chunk index + total chunks`, so chunks cannot be reordered, swapped between
  files or removed from the end without detection.
* Metadata (name, size, SHA-256) is the AAD of the wrapped DEK: editing the `.meta` file breaks decryption.
* Files live under `files/<user>/<random id>.enc`; user-supplied names are never used as paths
  (no path traversal), and the client re-sanitises names coming from the server.
* Retrieval decrypts and authenticates every chunk; any modification aborts the download with an error
  instead of returning corrupted data.

## Threat model

| Threat | Attack | Mitigation here | Residual risk / next step |
|---|---|---|---|
| **Eavesdropping** | Attacker sniffs the network | All traffic is AES-256 encrypted with ephemeral session keys | Traffic *size/timing* still visible |
| **Man-in-the-middle** | Attacker relays/impersonates the server during the handshake | Server signs the transcript; client **pins the fingerprint** (verified out-of-band or TOFU); changed fingerprint aborts | TOFU is weak on the very first connection - distribute the fingerprint through a trusted channel, or use a CA / certificates |
| **Active tampering** | Flip bits, replay, reorder or drop frames | HMAC over seq+len+ciphertext, verified before decryption; SHA-256 of whole file | - |
| **Replay of old sessions** | Re-send a recorded session | Fresh ephemeral keys + nonces per connection | - |
| **Stolen disk / backup** | Read files on the server disk | Files are AES-GCM encrypted; DEKs wrapped by master key kept separate (passphrase mode: not on disk) | If the attacker also gets the master key (or the running process memory) everything is readable |
| **Tampering at rest** | Modify, swap, truncate stored chunks or metadata | GCM tags + AAD binding; failures are reported, never silently served | Attacker can still *delete* files (availability) |
| **Weak/guessed passwords** | Online brute force | scrypt hashes, 1 s delay + 3 attempts per connection, constant-work check for unknown users | Add per-IP/account lockout and rate limiting |
| **Path traversal / malicious names** | `../../etc/passwd` | Random ids on disk, regex-validated ids/users, `clean_name` on both sides | - |
| **Denial of service** | Huge frames, many uploads | Max frame size, max file size, 120 s socket timeout, one active upload per file id | Add per-user quotas and connection limits |
| **Malicious/compromised server** | Server reads plaintext | **Not covered:** the server decrypts in memory to verify and re-encrypt | For zero-knowledge storage, encrypt on the client with a key the server never sees |
| **Key compromise** | Master key or identity key leaks | Owner-only file permissions; passphrase mode | See key management below |

### Key management
* **Types of keys:** session keys (ephemeral, per connection), server identity key (long-term, signs handshakes),
  master key/KEK (wraps per-file keys), DEKs (one per file).
* **Separation:** compromising one DEK exposes only one file; the KEK never touches file data directly.
* **Storage:** the KEK comes from an owner-only key file *or* a passphrase through scrypt (not stored).
  Keep the master key and the encrypted data on **different** media/hosts in real deployments.
* **Rotation:** to rotate the KEK, unwrap and re-wrap each DEK (cheap - file data need not be re-encrypted).
* **Production:** use an HSM or cloud KMS (AWS KMS, Azure Key Vault, HashiCorp Vault) so the KEK never leaves
  hardware, with audit logs and access control.

## Limitations (be honest in your report)
* The channel is a **teaching implementation**. In production use **TLS 1.3** (Python `ssl` module) instead
  of a custom protocol; the design here mirrors TLS (ephemeral ECDH + signed handshake + HKDF + AEAD/MAC).
* No key rotation tool, quotas, audit log or per-IP rate limiting yet.
* Password login only; no client certificates.
* The identity key is stored unencrypted in `identity.key` (permissions are owner-only on Linux; on Windows
  rely on NTFS folder permissions).

## Ideas for extra marks
Client-side encryption (zero-knowledge), TLS option via `ssl.SSLContext`, parallel chunk uploads,
file sharing between users with per-recipient key wrapping, audit log, KEK rotation command.
