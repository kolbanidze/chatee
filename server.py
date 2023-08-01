from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from nacl.public import SealedBox, PrivateKey
from Crypto.Cipher import AES
import os
from sys import stdout
from settings import MAX_MESSAGE_LENGTH
from base64 import b64encode
from hash_storage import HashStorage


class Server:
    """Server class. Private key is getting from login (main.py)"""

    def __init__(self, private_key: PrivateKey):
        # Encrypted connection in progress
        self.ecip = True
        self.private_key = private_key
        self.public_key = self.private_key.public_key

        self.host = input("Enter your IP: ")
        self.port = int(input("Enter your port: "))

        self.start_chat()

    def receive_messages(self, sock: socket) -> None:
        """Receiving and decrypting (with verifying) messages.
        Handles leaving when client denies server's public key.
        Decrypts session key from client."""

        while True:
            if self.ecip:
                data = sock.recv(MAX_MESSAGE_LENGTH)
                if data == b'PK_DENIED':
                    print("Oops. Client has denied your public key.")
                    print("May be it's a MITM attack?")
                    os._exit(0)
                else:
                    box = SealedBox(self.private_key)
                    self.session_key = box.decrypt(data)
                    self.ecip = False
            else:
                data = sock.recv(MAX_MESSAGE_LENGTH)

                # Getting nonce, tag and ciphertext
                nonce = data[:16]
                tag = data[16:32]
                ciphertext = data[32:]

                # Decrypting
                cipher = AES.new(self.session_key, AES.MODE_EAX, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext)

                # Checking integrity
                try:
                    cipher.verify(tag)
                    message = plaintext.decode('utf-8')
                    if message == "/leave":
                        print("Client has issued /leave command. Exiting...")
                        os._exit(0)
                    else:
                        # Removing one space
                        stdout.write('\b')
                        print(">", message)
                        print("\n> ", end="")
                except ValueError:
                    print("An error occurred while decryption of message.")

    def send_message(self, sock: socket) -> None:
        """Sending and encrypting messages.
        Sends server's public key when client connects."""

        sock.send(bytes(self.public_key))
        while True:
            print("\n> ", end="")
            message = bytes(input(), 'utf-8')

            if message == b"/connectioninfo":
                print(f"IP: {self.host}, Port: {self.port}")
                print(f"Session key (base64): {b64encode(self.session_key).decode('utf-8')}")
                print(f"My public key (sha256): {HashStorage.get_hash(bytes(self.public_key))}")
                continue

            # Shows help
            if message == b"/help":
                print("/help - show help")
                print("/leave - you and your interlocutor will leave chat.")
                print("/connectioninfo - shows connection info (ip, port, public_key, session_key)")
                continue

            # Encrypting a message
            cipher = AES.new(self.session_key, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(message)

            # Preparing message for sending
            to_send = nonce + tag + ciphertext

            sock.send(to_send)
            if message == b"/leave":
                os._exit(0)

    def start_chat(self):
        """Creation of socket and starting receive/send threads"""

        # Creating socket
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.host, self.port))
        # 1 - means only 1 client can connect
        sock.listen(1)

        print("Waiting for a connection...")

        conn, addr = sock.accept()
        print("Connected to:", addr[0])

        receive_thread = Thread(target=self.receive_messages, args=(conn,))
        send_thread = Thread(target=self.send_message, args=(conn,))

        # Starting threads
        receive_thread.start()
        send_thread.start()
