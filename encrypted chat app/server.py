import socket
import threading
import datetime
from shared_crypto import encrypt_message, decrypt_message, send_data, recv_data

HOST = "0.0.0.0" # listen all network interfaces
PORT = 5555
LOG_FILE = "chat_log.txt"

clients = []     # list of connected client sockets
clients_lock = threading.Lock() # protects clients form race conditions

def log_message(name: str, message: str):
    """Print and save a timestamped chat line."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {name}: {message}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(line + "\n")


def broadcast(message: str, sender_socket):
    """Encrypt `message` and send it to every client except the sender."""
    encrypted = encrypt_message(message)
    with clients_lock:
        for client_socket  in clients:
            if client_socket is not sender_socket:
                try:
                    send_data(client_socket, encrypted)
                except OSError:
                    pass   # that client will be cleaned up in its own thread


def handle_client(client_socket, address):
    """Runs in its own thread for each connected client."""
    name = f"{address[0]}:{address[1]}"
    print(f"[+] {name} connected")

    with clients_lock:
        clients.append(client_socket)

    try:
        while True:
            data = recv_data(client_socket)
            if data is None:
                break  # client closed the connection
            message = decrypt_message(data)
            log_message(name, message)
            broadcast(f"{name}: {message}", client_socket)
    except Exception as error:
        print(f"[!] Error with {name}:{error}")

    finally:
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        client_socket.close()
        print(f"[-] {name} disconnected")



def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[*] Server listening on {HOST}: {PORT}")

    while True:
        client_socket, address = server_socket.accept()
        thread = threading.Thread(
            target=handle_client, args=(client_socket, address), daemon=True
        )
        thread.start()

if __name__ == "__main__":
    main()
