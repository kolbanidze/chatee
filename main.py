from settings import SALT_SIZE, ACCOUNT_STORAGE_DB_NAME, ACCOUNT_STORAGE_DB_TABLE,\
                     ARGON2ID_PARALLELISM, ARGON2ID_MEMORY_COST, ARGON2ID_TIME_COST
from nacl.public import PrivateKey
from secrets import token_bytes
from getpass import getpass
from gc import collect as collect_garbage
from sqlite3 import connect as sql_connect
from Crypto.Cipher import AES
from client import Client
from server import Server
from hash_storage import HashStorageEditor
from account_editor import AccountEditor
from argon2.low_level import hash_secret_raw
from argon2 import Type


def login(username: str) -> None:
    """Login into account"""
    print("# LOGIN #")

    # Getting password (in bytes)
    password = getpass("Password: ").encode('utf-8')

    # Getting BLOB entries from db
    db = sql_connect(ACCOUNT_STORAGE_DB_NAME)
    c = db.cursor()
    c.execute(f"SELECT * FROM {ACCOUNT_STORAGE_DB_TABLE} "
              f"WHERE username='{username}'")
    output = c.fetchall()[0]
    encrypted_private_key = output[1]
    password_salt = output[2]
    nonce = output[3]
    tag = output[4]
    db.close()

    # Getting 256-bit AES key with Argon2id
    key = hash_secret_raw(secret=password,
                          salt=password_salt,
                          time_cost=ARGON2ID_TIME_COST,
                          memory_cost=ARGON2ID_MEMORY_COST,
                          parallelism=ARGON2ID_PARALLELISM,
                          hash_len=32,
                          type=Type.ID)

    # Deleting plaintext password from memory
    del password
    collect_garbage()

    # Decrypting private key
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    private_key = PrivateKey(cipher.decrypt(encrypted_private_key))

    # Checking integrity of private key
    try:
        cipher.verify(tag)
        print("Private key integrity verification pass.")
    except ValueError:
        print("Error. Password incorrect or private key corrupted.")
        exit(0)

    Server(private_key)


def create_account(username: str) -> None:
    """Creation of account.
    KDF: Argon2id (Time Cost: 3, Memory: 65536, Parallelism: 4) returns 256-bit hash"""
    print("# CREATING ACCOUNT #")

    # Initialization of db
    db = sql_connect(ACCOUNT_STORAGE_DB_NAME)
    c = db.cursor()

    # Getting password (in bytes) and adding salt (also in bytes)
    password = getpass("Password: ").encode('utf-8')
    salt = token_bytes(SALT_SIZE)

    # Creating 256-byte key for AES (with Argon2id)
    key = hash_secret_raw(secret=password,
                          salt=salt,
                          time_cost=ARGON2ID_TIME_COST,
                          memory_cost=ARGON2ID_MEMORY_COST,
                          parallelism=ARGON2ID_PARALLELISM,
                          hash_len=32,
                          type=Type.ID)

    # Deleting plaintext password from memory
    del password
    collect_garbage()

    # Generating Ed25519 private key
    private_key = PrivateKey.generate()

    # Encryption with AES-EAX (256)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    encrypted_private_key, tag = cipher.encrypt_and_digest(bytes(private_key))

    # Saving into db
    c.execute(f"INSERT INTO {ACCOUNT_STORAGE_DB_TABLE} "
              f"VALUES ('{username}', ?, ?, ?, ?)",
              [memoryview(encrypted_private_key),
               memoryview(salt),
               memoryview(nonce),
               memoryview(tag)])
    db.commit()
    db.close()

    print("Account was successfully created and encrypted.")


def check_account_existence() -> None:
    """Check account existence and if not exist then creates account.
    Creates account storage db."""

    db = sql_connect(ACCOUNT_STORAGE_DB_NAME)
    c = db.cursor()

    def _create_db() -> None:
        c.execute(f"""CREATE TABLE IF NOT EXISTS {ACCOUNT_STORAGE_DB_TABLE} (
                        username text,
                        encrypted_private_key BLOB,
                        password_salt BLOB,
                        nonce BLOB,
                        tag BLOB)""")
        db.commit()

    def _check_if_username_exists(username: str) -> bool:
        c.execute(f"SELECT * FROM {ACCOUNT_STORAGE_DB_TABLE} WHERE username='{username}'")
        output = c.fetchall()

        if len(output) != 0:
            # Account exists
            return True
        else:
            # Account don't exist
            return False

    _create_db()

    user_name = input("Username: ")
    if _check_if_username_exists(user_name):
        db.close()
        login(user_name)
    else:
        db.close()
        create_account(user_name)


def menu() -> None:
    """Main menu. Handles user input."""
    print("[1] - Client\n"
          "[2] - Server\n"
          "[3] - Account Editor\n"
          "[4] - Hash Storage Editor\n"
          "[0] - Exit")
    client_or_server = input("> ")
    match client_or_server:
        case "1":
            Client()
        case "2":
            check_account_existence()
        case "3":
            AccountEditor()
        case "4":
            HashStorageEditor()
        case "0":
            exit(0)


if __name__ == "__main__":
    menu()
