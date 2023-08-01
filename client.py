from base64 import b64encode
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from nacl.public import PublicKey, SealedBox
from Crypto.Cipher import AES
from secrets import token_bytes
import os
from hash_storage import HashStorage
from sys import stdout
from settings import MAX_MESSAGE_LENGTH


class Client:
    """Client class. """
    def __init__(self):
        # Encrypted connection in progress
        # ECIP is being used while establishing an encrypted connection
        self.ecip = True

        self.host = input("Enter server IP: ")
        try:
            self.port = int(input("Enter server port: "))
        except ValueError:
            print("Error. Invalid input, only integers allowed.")
            exit(1)

        self.start_chat()

    def receive_messages(self, sock: socket) -> None:
        """Receiving and decrypting (with verifying) messages.
        Handles initial connection (while ecip is True):
        Generates session key and encrypting it with server's public key"""

        while True:
            if self.ecip:
                data = sock.recv(MAX_MESSAGE_LENGTH)
                raw_pk = bytes(data)
                self.server_pk = PublicKey(raw_pk)

                HashStorage(ip_address=self.host, port_number=self.port, public_key=raw_pk, sock=sock)

                box = SealedBox(self.server_pk)
                # Creation of random 256-bit session key (for future AES encryption)
                self.session_key = token_bytes(32)
                # Encryption of session key with server's public key
                encrypted_session_key = box.encrypt(self.session_key)

                # Sending it and changing state to 'after key exchange'
                sock.send(encrypted_session_key)
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
                        print("Server has issued /leave command. Exiting...")
                        os._exit(0)

                    else:
                        # Removing one space
                        stdout.write('\b')
                        print(">", message)
                        print("\n> ", end="")
                except ValueError:
                    print("An error occurred while decryption of message.")

    def send_message(self, sock: socket) -> None:
        """Sending and encrypting messages. Handles / commands"""
        while True:
            print("\n> ", end="")
            message = bytes(input(), 'utf-8')

            if message == b"/connectioninfo":
                print(f"IP: {self.host}, Port: {self.port}")
                print(f"Session key (base64): {b64encode(self.session_key).decode('utf-8')}")
                print(f"Server public key (sha256): {HashStorage.get_hash(bytes(self.server_pk))}")
                continue

            # Shows help
            if message == b"/help":
                print("/help - show help")
                print("/leave - you and your interlocutor will leave chat.")
                print("/connectioninfo - shows connection info (ip, port, public_key, session_key)")
                continue

            # Encrypting message
            cipher = AES.new(self.session_key, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(message)

            # Preparing message for sending
            to_send = nonce + tag + ciphertext

            # Sending message
            sock.send(to_send)
            if message == b"/leave":
                os._exit(0)

    def start_chat(self):
        """Creation of socket and starting receive/send threads"""

        # Creating socket
        sock = socket(AF_INET, SOCK_STREAM)
        try:
            sock.connect((self.host, self.port))
        except ConnectionRefusedError:
            print("Connection Refused. Check your internet connection, IP and port.")
            exit(1)
        except Exception as e:
            print("An error occurred.")
            print("Error:", e)

        print("Connected to:", self.host)

        receive_thread = Thread(target=self.receive_messages, args=(sock,))
        send_thread = Thread(target=self.send_message, args=(sock,))

        # Starting threads
        receive_thread.start()
        send_thread.start()
