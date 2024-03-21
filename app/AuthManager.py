import os

import tink
from argon2 import PasswordHasher
from flask_login import login_user
from tink import daead

from .models import Users


class TinkKeyManager:
    def __init__(self):
        try:
            KEYSET_FILENAME = os.getenv("PATH_KEYSET", "my_keyset.json")
            # if os.path.exists(KEYSET_FILENAME):
            #     self.tink_keyset_handle = TinkKeyManager.load_keyset(KEYSET_FILENAME)
            # else:
            self.tink_keyset_handle = self.create_keyset()
            # TinkKeyManager.save_keyset(self.tink_keyset_handle, KEYSET_FILENAME)
        except Exception as e:
            print(e)
            raise Exception("Error while initializing TinkKeyManager")

    def load_keyset(self, filename):
        """
        Load the keyset from a file.
        Args:
            filename: str
        """
        try:
            with open(filename, "rb") as keyset_file:
                keyset_bytes = keyset_file.read()
                keyset_handle = tink.read_keyset_handle(keyset_bytes)
            return keyset_handle
        except Exception as e:
            print(e)
            raise Exception("Error loading keyset from file")

    def save_keyset(self, keyset_handle, filename):
        """
        Save the keyset to a file.
        Args:
            keyset_handle: tink.KeysetHandle
            filename: str
        """
        try:
            keyset_bytes = tink.new_keyset_handle().write()
            with open(filename, "wb") as keyset_file:
                keyset_file.write(keyset_bytes)
        except Exception as e:
            print(e)
            raise Exception("Error saving keyset to file")

    def create_keyset(self):
        """
        Create a new keyset.
        Returns:
            tink.KeysetHandle
        """
        try:
            daead.register()
            keyset_handle = tink.new_keyset_handle(daead.deterministic_aead_key_templates.AES256_SIV)
            return keyset_handle
        except Exception as e:
            print(e)
            raise Exception("Error while creating keyset")


class PakeManager:
    def __init__(self):
        try:
            pass
        except Exception as e:
            print(e)
            raise Exception("Error while initializing PakeManager")


class AuthManager:
    def __init__(self, db: object):
        """
        Initializes the AuthManager object.

        Args:
            db: The database object used for authentication.

        Raises:
            Exception: If there is an error while initializing AuthManager.
        """
        try:
            self.db = db
            self.password_hasher = PasswordHasher()
            tink_key_manager = TinkKeyManager()
            self.tink_keyset_handle = tink_key_manager.tink_keyset_handle
        except Exception as e:
            print(e)
            raise Exception("Error while initializing AuthManager")

    def hash_password(self, password):
        """
        Hash a password using a salt, using the argon2.
        args:
            password: str
        """
        # No need to store the salt in DB, it is already included in the hash
        try:
            return self.password_hasher.hash(password)
        except Exception:
            Exception("Error while hashing password")

    def encrypt_password(self, hashed_password):
        """
        Encrypt a hashed password
        args:
            hashed_password: str
        """
        try:
            daead_primitive = self.tink_keyset_handle.primitive(daead.DeterministicAead)
            encrypted_hash = daead_primitive.encrypt_deterministically(hashed_password.encode(), b"")
            return encrypted_hash
        except Exception as e:
            print(e)
            Exception("Error while encrypting password")

    def register(self, email, password):
        """
        Register a new user
        args:
            email: str
            password: str
        return:
            bool
        """
        try:
            hashed_password = self.hash_password(password)
            encrypted_hash = self.encrypt_password(hashed_password)
            user = Users(
                email=email,
                password=encrypted_hash,
            )
            self.db.session.add(user)
            self.db.session.commit()
            return True
        except Exception as e:
            print(e)
            Exception("Error while registering user")

    def decrypt_password(self, encrypted_hash):
        """
        Decrypt an encrypted password
        args:
            encrypted_hash: str
        """
        try:
            daead_primitive = self.tink_keyset_handle.primitive(daead.DeterministicAead)
            decrypted_hash = daead_primitive.decrypt_deterministically(encrypted_hash, b"")
            return decrypted_hash.decode()
        except Exception as e:
            print(e)
            Exception("Error while decrypting password")

    def login(self, email, password):
        """
        Login a user
        args:
            email: str
            password: str
        return:
            User object on success, None otherwise.
        """
        try:
            user = self.db.session.query(Users).filter_by(email=email).first()
            if user:
                decrypted_hash = self.decrypt_password(user.password)
                if self.password_hasher.verify(decrypted_hash, password):
                    login_user(user)
                    return user
            return None
        except Exception as e:
            print(e)
            return None
