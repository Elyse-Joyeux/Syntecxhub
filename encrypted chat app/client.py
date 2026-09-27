import socket 
import threading 
from shared_crypto import encrypt_message, decrypt_message, send_data, recv_data

HOST = "127.0.0.1" # when remote change it to the server's ip address
PORT = 5555

def receive_messages(sock):
    """Background thread: keep receiving and encrypting incoming messages."""
    while True:
        data = recv_data(sock)
        if data is None:
            print("\n[!] Disconnected from server.")
            break
        message = decrypt_message(data)
        print(f"\n{message}\nYou: ", end="", flush=True)

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"[*] Connected to server at {HOST}:{PORT} (type /quit to leave)")

    listener_thread = threading.Thread(
        target = receive_messages, args = (client_socket, ), daemon=True
    )
    listener_thread.start()
    try:
        while True:
            message = input("You: ")
            if message.strip().lower() == "/quit":
                break
            encrypted = encrypt_message(message)
            send_data(client_socket, encrypted)

    except KeyboardInterrupt:
        pass
    finally:
        client_socket.close()


if __name__ == "__main__":
    main()


