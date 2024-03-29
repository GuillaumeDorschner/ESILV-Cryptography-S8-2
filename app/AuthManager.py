import secrets
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy.orm import Session


class AuthManager:
    # Parameters for the 2048-bit group from RFC 3526
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16,
    )  # The hexadecimal value of p for the 2048-bit group, to be replaced by the exact value
    g = 2

    # generate key pair for the server (Diffie-Hellman)
    parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()

    def __init__(self, db: Session):
        """
        Initialize the AuthManager to manage authentication processes, including login and registration using PAKE (Password Authenticated Key Exchange).

        Args:
            db (Session): The SQLAlchemy session instance to interact with the database.
        """
        self.db = db
        self.shared_key: Optional[bytes] = None

    def generate_user_key(self) -> int:
        """
        Generate a user-specific private key (salt) for the OPRF (Oblivious Pseudo-Random Function) and return it as int.

        Returns:
            int: The private key serialized as int.
        """

        salt_size_bits = 128

        salt = secrets.randbits(salt_size_bits)

        return salt

    def perform_oprf(self, C: int, user_salt: int) -> int:
        """
        Perform the OPRF operation for a given user and input C.

        Args:
            C (int): The client's C, as an integer derived from their password.
            user_salt (int): The server's salt for this specific user, acting as the secret s.

        Returns:
            int: The resulting R from the OPRF operation.
        """

        R = pow(C, user_salt, AuthManager.p)

        return R

    # --------------- Diffie Hellman ---------------

    def AKE(self, client_public_key_pem: bytes) -> bytes:
        """
        Perform the Authenticated Key Exchange (AKE) using the Diffie-Hellman protocol.

        Args:
            client_public_key_pem (bytes): The PEM-encoded client's public key.

        Returns:
            bytes: The derived shared key.
        """
        client_public_key = serialization.load_pem_public_key(
            client_public_key_pem, backend=default_backend()
        )

        shared_key = self.server_private_key.exchange(client_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
            backend=default_backend(),
        ).derive(shared_key)

        self.shared_key = derived_key

        return derived_key

    # --------------- PAKE ---------------

    def clear_shared_key(self):
        """
        Clear the shared key not ideal for mult user. But it's a simple example.
        """
        self.shared_key = None

    # # not like that because the user don't send the shared key (use for encryption) the login should be with something else
    # def login_required(self, shared_key: str):
    #     return self.shared_key == shared_key

    def decrypt_data(self, encrypted_data: bytes) -> str:
        """
        Decrypt the encrypted data using the shared key.

        Args:
            encrypted_data (bytes): The encrypted data to decrypt.

        Returns:
            str: The decrypted data as a string.
        """
        if self.shared_key is None:
            raise Exception("Shared key not set")

        f = Fernet(self.shared_key)

        data = f.decrypt(encrypted_data)

        return data.decode("utf-8")
