import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# pre shared key(32 bytes to aes-256)
# change this to ur own 32 bytes secret, both server and client must
#use the exact same key
PSK = b"0123456789abcdef0123456789abcdef"
BLOCK_SIZE = AES.block_size    # 16 bytes

# encryption
def encrypt_message(plaintext: str, key: bytes = PSK) -> bytes:
    """Encrypt a plaintext string. Returns iv + ciphertext as bytes."""
    iv = get_random_bytes(BLOCK_SIZE)              # fresh, random IV every time
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode("utf-8"), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext                         # send the IV with the message


def decrypt_message(data: bytes, key: bytes = PSK) -> str:
    """Decrypt iv + ciphertext bytes back into the original string."""
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_data, BLOCK_SIZE)
    return plaintext.decode("utf-8")

# tcp length-prefixted framing
def send_data(sock, data: bytes):
    """Send data over a socket, prefixed with its length."""
    length_prefix = struct.pack(">I", len(data))   # 4-byte big-endian length
    sock.sendall(length_prefix + data)


def recv_exact(sock, num_bytes: int):
    """Read exactly num_bytes from the socket, or None if it closes early."""
    data = b""
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes 
                          - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_data(sock):
    """Read one length-prefixed message from the socket."""
    raw_length = recv_exact(sock, 4)
    if raw_length is None:
        return None
    length = struct.unpack(">I", raw_length)[0]
    return recv_exact(sock, length)
