# Encrypted Chat App (Python)

A basic client/server chat app where every message is encrypted with
AES before it goes over the network.

## Files
- `shared_crypto.py` — AES encrypt/decrypt functions + TCP framing helpers (used by both sides)
- `server.py` — multi-client TCP server (one thread per client), decrypts, logs, and broadcasts
- `client.py` — TCP client with a listener thread + a send loop

## Setup
```bash
pip install pycryptodome
```

## Run it
1. Start the server:
   ```bash
   python server.py
   ```
2. In separate terminals, start one or more clients:
   ```bash
   python client.py
   ```
3. Type messages and press Enter. Type `/quit` to leave.

To connect from another machine, change `HOST` in `client.py` to the
server's IP address, and make sure port `5555` is reachable.

## How the crypto works
- **Algorithm**: AES-256 in CBC mode.
- **Key**: a pre-shared key (`PSK` in `shared_crypto.py`) that both the
  server and every client already know. Change it to your own 32-byte
  secret before real use — never keep the default in production.
- **IV (Initialization Vector)**: a fresh random 16-byte IV is
  generated for *every* message. It doesn't need to be secret, so it's
  simply prepended to the ciphertext (`iv + ciphertext`) and stripped
  off again on the receiving end. Reusing an IV with the same key is
  the main mistake to avoid with CBC mode — this app never does that.
- **Padding**: PKCS7, so messages of any length fit AES's 16-byte
  block size.
- **Framing**: TCP is just a byte stream, so each message is prefixed
  with a 4-byte length so the receiver knows exactly where it ends.

## Concurrency & logging
- The server spawns one thread per connected client (`threading`), so
  multiple people can chat at once.
- Every decrypted message is timestamped and appended to
  `chat_log.txt` on the server, and also printed to the server console.

## Notes / possible upgrades
- This uses a **pre-shared key** for simplicity. A more advanced
  version could use **Diffie-Hellman key exchange** so the server and
  each client negotiate a fresh shared secret on connect, instead of
  both sides hardcoding the same key.
- This is a learning project, not a production-grade secure protocol
  (no authentication of who holds the key, no protection against
  replay attacks, etc.).
