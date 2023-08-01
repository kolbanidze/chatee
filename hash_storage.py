from settings import HASH_DB_NAME, HASH_DB_TABLE_NAME
import sqlite3
from hashlib import sha256
import os


class HashStorage:
    """Hash Storage. Stores server's ip, port and public key hash."""

    def __init__(self, ip_address, port_number, public_key, sock):
        self.hash_db = HASH_DB_NAME
        self.ip_address = ip_address
        self.port_number = port_number
        self.public_key = public_key
        self.pk_hash = self.get_hash(self.public_key)
        self.sock = sock
        self.create_db()
        self.add_and_verify()

    @staticmethod
    def get_hash(public_key: bytes) -> str:
        """Just returns hex sha256 hash of gives bytes"""
        return sha256(public_key).hexdigest()

    def create_db(self):
        """Creates db"""
        db = sqlite3.connect(self.hash_db)
        c = db.cursor()
        c.execute(f"""CREATE TABLE IF NOT EXISTS {HASH_DB_TABLE_NAME} (
                            ip text,
                            port text,
                            pk_hash text)""")
        db.commit()
        db.close()

    def add_and_verify(self):
        """Verifies public key hash.
        If hash mismatches it will stop app and notify user.
        If user hasn't connected before it will add hash"""

        def _check_if_exist():
            c.execute(f"SELECT * FROM {HASH_DB_TABLE_NAME} "
                      f"WHERE ip='{self.ip_address}' AND port='{self.port_number}'")
            output = c.fetchall()
            if len(output) == 0:
                # Entry don't exist
                return False, output
            else:
                # Entry exists
                return True, output

        def _add_to_db():
            c.execute(f"INSERT INTO {HASH_DB_TABLE_NAME} "
                      f"VALUES ('{self.ip_address}', '{self.port_number}', '{self.pk_hash}')")
            db.commit()

        db = sqlite3.connect(self.hash_db)
        c = db.cursor()

        if _check_if_exist()[0]:
            print("You have connected to that server before.", end=" ")
            pk_hash_in_db = _check_if_exist()[1][0][2]
            if self.pk_hash == pk_hash_in_db:
                print("Server's public key verification success.\n"
                      "> ", end="")
            else:
                print("\n\t\tWARNING!")
                print("Server's public key has changed!")
                print("Someone may be doing a MITM attack!")
                print("Or server has logged with different account (with different keys of course)")
                print(f"Saved public key hash in db: {pk_hash_in_db}\nCurrent public key hash: {self.pk_hash}")
                print("If you want to reset that key start Hash Storage and delete it.")
                self.sock.send(b"PK_DENIED")
                os._exit(1)
        else:
            print("You haven't connected to this server before.\n"
                  "Saving server's public key into database\n"
                  f"Server's public key hash: {self.pk_hash}\n"
                  "> ", end="")
            _add_to_db()


class HashStorageEditor:
    def __init__(self):
        # Connecting to db
        self.db = sqlite3.connect(HASH_DB_NAME)
        self.c = self.db.cursor()

        # Showing menu
        self.menu()

    def _check_if_db_empty(self) -> bool:
        """Checks if database empty.
                Returns True if database is empty. Returns False if db isn't empty.
                Checks for tables and entries (if tables exist)."""

        # Check if there are tables
        self.c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        output = self.c.fetchall()
        if len(output) == 0:
            # Database is empty
            return True

        self.c.execute(f"SELECT * FROM {HASH_DB_TABLE_NAME}")
        output = self.c.fetchall()

        if len(output) == 0:
            # Database is empty
            return True
        else:
            # Database isn't empty
            return False

    def _check_if_entry_exist(self, ip_address: str, port_number: str) -> bool:
        """Checks account existence.
        If account exists returns True
        If account don't exist return False"""

        # Checking existence of entry with same ip and port
        self.c.execute(f"SELECT * FROM {HASH_DB_TABLE_NAME} "
                       f"WHERE ip='{ip_address}' AND port='{port_number}'")
        output = self.c.fetchall()

        if len(output) != 0:
            # Entry exists
            return True
        else:
            # Entry don't exist
            return False

    def get_saved_entries(self) -> list:
        """Displays all saved ip, port and hashes"""

        self.c.execute(f"SELECT * FROM {HASH_DB_TABLE_NAME}")
        return self.c.fetchall()

    def remove_entry(self, ip_address: str, port_number: str) -> None:
        """Checking entry existence, deleting it and verifying deleting"""

        # Checking entry existence
        if not self._check_if_entry_exist(ip_address, port_number):
            print(f"There is no entry with {ip_address}:{port_number}")
            self.menu()

        # Deleting entry
        self.c.execute(f"DELETE FROM {HASH_DB_TABLE_NAME} "
                       f"WHERE ip='{ip_address}' AND port='{port_number}'")
        self.db.commit()

        # Checking that entry was successfully deleted
        if not self._check_if_entry_exist(ip_address, port_number):
            print("Entry was successfully removed.")
        else:
            print("An error occurred while deleting entry.")

    def delete_all_entries(self) -> None:
        """Deletes all entries in Hash Storage database"""

        # Check that db isn't empty
        if not self._check_if_db_empty():
            print("Deleting all entries")
            self.c.execute(f"DELETE FROM {HASH_DB_TABLE_NAME}")
            self.db.commit()
        else:
            print("DB is already empty.")
            self.menu()

        # Check that db is empty now
        if self._check_if_db_empty():
            print("DB was cleared successfully.")
        else:
            print("An error occurred while clearing db.")

    def menu(self) -> None:
        """Show menu and handle user input"""

        print(f"[1] - Show saved entries\n"
              f"[2] - Delete entry\n"
              f"[3] - Delete all entries\n"
              f"[0] - Exit")
        choice = input("> ")
        match choice:
            case "1":
                saved_entries = self.get_saved_entries()
                if self._check_if_db_empty():
                    print("Hash storage is empty")
                    self.menu()

                for i in saved_entries:
                    ip = i[0]
                    port = i[1]
                    public_key_hash = i[2]
                    print('='*32)
                    print(f"IP: {ip}")
                    print(f"Port: {port}")
                    print(f"Hash: {public_key_hash}")
                print("="*32)
                self.menu()

            case "2":
                ip = input("IP: ")
                port = input("Port: ")
                self.remove_entry(ip_address=ip, port_number=port)
                self.menu()

            case "3":
                self.delete_all_entries()
                self.menu()

            case "0":
                self.db.close()
                exit(0)


if __name__ == "__main__":
    HashStorageEditor()
