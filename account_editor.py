from sqlite3 import connect as sql_connect
from settings import ACCOUNT_STORAGE_DB_NAME, SALT_SIZE,\
                     ARGON2ID_PARALLELISM, ARGON2ID_MEMORY_COST, ARGON2ID_TIME_COST
from getpass import getpass
from gc import collect as collect_garbage
from Crypto.Cipher import AES
from secrets import token_bytes
from argon2.low_level import hash_secret_raw
from argon2 import Type


class AccountEditor:
    def __init__(self):
        self.db = sql_connect(ACCOUNT_STORAGE_DB_NAME)
        self.c = self.db.cursor()
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

        # Check if there are entries
        self.c.execute("SELECT * FROM accounts")
        output = self.c.fetchall()
        if len(output) == 0:
            # Database is empty
            return True
        else:
            # Database isn't empty
            return False

    def _get_accounts_names(self) -> list:
        """Gets account names. If db is empty returns:
        Database
        is
        empty
        =D"""

        if self._check_if_db_empty():
            return [['Database'], ['is'], ['empty'], ['=D']]
        self.c.execute("SELECT username FROM accounts")
        output = self.c.fetchall()

        return output

    def _check_if_user_exists(self, username) -> bool:
        """Checks if user exists.
        If user exists returns True. If user don't exist returns False"""

        users = self._get_accounts_names()[0]
        if username in users:
            return True
        else:
            return False

    def _decrypt_data_from_account_storage(self, username: str, password: bytes) -> dict:
        """Gets user data from database and decrypts it with given password.
        Then returns decrypted data as dictionary."""

        # Getting user info from db
        self.c.execute("SELECT * FROM accounts WHERE username=?", (username,))
        output = self.c.fetchall()[0]
        encrypted_private_key = output[1]
        password_salt = output[2]
        nonce = output[3]
        tag = output[4]

        # Getting 256-bit key with Argon2id
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

        # return key, encrypted_private_key, password_salt, nonce, tag
        return {'key': key, 'encrypted_private_key': encrypted_private_key,
                'password_salt': password_salt, 'nonce': nonce, 'tag': tag}

    def _check_current_password(self, username: str, password: bytes) -> bool:
        """Checks current user password.
        If password incorrect returns False. If password correct returns True"""
        # Getting data from db
        data = self._decrypt_data_from_account_storage(username, password)

        key = data['key']
        encrypted_private_key = data['encrypted_private_key']
        nonce = data['nonce']
        tag = data['tag']

        # Verifying password
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        cipher.decrypt(encrypted_private_key)
        try:
            cipher.verify(tag)
            # If there is no errors i.e. that password is correct
            return True
        except ValueError:
            # If ValueError i.e. that password is incorrect (99.9%) or private key corrupted (0.01%)
            return False

    def _change_password(self, username: str, old_password: bytes, new_password: bytes) -> None:
        """Changes password.
        Gets decrypted account data. Creates new 256 key (KDF: Argon2id, with new salt) and then
        encrypts Private Key with new key. Saves new encrypted_private_key, tag, nonce and
        password_salt into db"""

        # Getting current account data (decrypted)
        current_account_data = self._decrypt_data_from_account_storage(username, old_password)

        current_key = current_account_data['key']
        encrypted_private_key = current_account_data['encrypted_private_key']
        nonce = current_account_data['nonce']
        tag = current_account_data['tag']

        cipher = AES.new(current_key, AES.MODE_EAX, nonce=nonce)

        # Current Private Key (in bytes format)
        current_private_key = cipher.decrypt(encrypted_private_key)

        # Verifying private key integrity
        try:
            cipher.verify(tag)
            print("Private key integrity verification pass.")
        except ValueError:
            print("Error. Password incorrect or private key corrupted.")
            self.menu()

        # Generating salt
        new_password_salt = token_bytes(SALT_SIZE)

        # Generating new key (Argon2id)
        new_key = hash_secret_raw(new_password,
                                  new_password_salt,
                                  time_cost=ARGON2ID_TIME_COST,
                                  memory_cost=ARGON2ID_MEMORY_COST,
                                  parallelism=ARGON2ID_PARALLELISM,
                                  hash_len=32,
                                  type=Type.ID)

        # Clearing plaintext passwords and AES key from memory
        del old_password
        del new_password
        del cipher
        del current_key
        collect_garbage()

        # Encrypting private key with new password
        new_cipher = AES.new(new_key, AES.MODE_EAX)
        new_nonce = new_cipher.nonce
        new_encrypted_private_key, new_tag = new_cipher.encrypt_and_digest(current_private_key)

        # Saving into db
        # self.c.execute(f"UPDATE {ACCOUNT_STORAGE_DB_TABLE} SET "
        #                f"encrypted_private_key=?,"
        #                f"password_salt=?,"
        #                f"nonce=?,"
        #                f"tag=? "
        #                f"WHERE username='{username}'", [memoryview(new_encrypted_private_key),
        #                                                 memoryview(new_password_salt),
        #                                                 memoryview(new_nonce),
        #                                                 memoryview(new_tag)])
        self.c.execute("UPDATE accounts SET "
                       "encrypted_private_key=?,"
                       "password_salt=?,"
                       "nonce=?,"
                       "tag=? "
                       "WHERE username=?", (new_encrypted_private_key,
                                            new_password_salt,
                                            new_nonce,
                                            new_tag,
                                            username))
        self.db.commit()

        # Checking entry
        self.c.execute("SELECT * FROM accounts WHERE username=? AND "
                       "encrypted_private_key=? AND password_salt=? AND "
                       "nonce=? AND tag=?", (username, new_encrypted_private_key,
                                             new_password_salt, new_nonce, new_tag))
        output = self.c.fetchall()

        if len(output) != 0:
            print("Account password changed successfully!")
        else:
            print("Oops. An error occurred while checking your account. Try again.")

        self.menu()

    def change_password(self) -> None:
        """Changes user password (re-encrypts private key with new password, creates new salt, nonce, tag)"""

        # Check if db is empty
        if self._check_if_db_empty():
            print("Oops. Database is empty.")
            self.menu()

        # Getting username
        username = input("Username: ")

        # Check if user don't exist
        if not self._check_if_user_exists(username):
            print("Oops. User don't exist.")
            self.menu()

        # Getting old password
        old_password = getpass("Old password: ").encode('utf-8')

        # Checking old password
        if not self._check_current_password(username, old_password):
            print("Password that you have entered is incorrect.")
            self.menu()

        # Getting new password (with checking for errors)
        new_password_first = getpass("New password (1/2): ").encode('utf-8')
        new_password_second = getpass("New password (2/2): ").encode('utf-8')

        # Check that input passwords are same
        if new_password_first != new_password_second:
            print("Passwords are different.")
            self.menu()

        self._change_password(username, old_password, new_password_second)

    def show_all_accounts(self) -> None:
        """Shows all accounts. If there isn't any account it will show:
        Database
        is
        empty
        =D"""

        print('='*32)
        for i in self._get_accounts_names():
            username = i[0]
            print(username)
        print('='*32)
        self.menu()

    def change_username(self) -> None:
        """Changes username and checks it"""

        username = input("Username: ")
        if not self._check_if_user_exists(username):
            print("That user don't exist. Check your input")
            self.menu()

        new_username = input("New username: ")

        # Changing username
        self.c.execute("UPDATE accounts SET "
                       "username=? WHERE username=?", (new_username, username))
        self.db.commit()

        # Checking
        self.c.execute("SELECT * FROM accounts WHERE username=?", (username,))
        if len(self.c.fetchall()) != 0:
            print("Hmm. Something went wrong, your old username is still in db.")
            self.menu()

        self.c.execute("SELECT * FROM accounts WHERE username=?", (new_username,))
        if len(self.c.fetchall()) != 0:
            print("Username changed successfully!")
        else:
            print("Hmm. Something went wrong, there isn't new username in database")
        self.menu()

    def delete_account(self) -> None:
        """Deletes account and checks it"""

        username = input("Username: ")

        if not self._check_if_user_exists(username):
            print("That account don't exist.")
            self.menu()

        check = input("Are you sure (y/n)? ")
        if check == "n":
            self.menu()

        self.c.execute(f"DELETE FROM accounts "
                       f"WHERE username=?", (username,))
        self.db.commit()

        # Checking deleting
        self.c.execute(f"SELECT * FROM accounts "
                       f"WHERE username=?", (username,))
        if len(self.c.fetchall()) != 0:
            print("Oops. Something went wrong while deleting your account.")
        else:
            print("Account removal was successful.")
        self.menu()

    def delete_all_accounts(self) -> None:
        """Deletes all accounts and then check it"""

        if self._check_if_db_empty():
            print("Database is already empty")
            self.menu()
        else:
            print("Deleting all entries")
            self.c.execute(f"DELETE FROM accounts")
            self.db.commit()

        # Checking deletion
        if self._check_if_db_empty():
            print("Database deleting was successful.")
        else:
            print("Oops. Something went wrong while deleting database.")

        self.menu()

    def menu(self) -> None:
        """Shows menu and handles user input"""

        print("[1] - Show all accounts\n"
              "[2] - Change password\n"
              "[3] - Change username\n"
              "[4] - Delete account\n"
              "[5] - Delete all accounts\n"
              "[0] - Exit")
        choice = input("> ")

        match choice:
            case "1":
                self.show_all_accounts()
            case "2":
                self.change_password()
            case "3":
                self.change_username()
            case "4":
                self.delete_account()
            case "5":
                self.delete_all_accounts()
            case "0":
                self.db.commit()
                exit(0)


if __name__ == "__main__":
    AccountEditor()
