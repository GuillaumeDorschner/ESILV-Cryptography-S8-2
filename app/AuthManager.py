from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from sqlalchemy.orm import Session


class AuthManager:
    # generate key pair for the server (Diffie-Hellman)
    dh_parameters = dh.generate_parameters(
        generator=2, key_size=2048, backend=default_backend()
    )
    server_private_key = dh_parameters.generate_private_key()
    server_public_key = server_private_key.public_key()

    def __init__(self, db: Session):
        """
        Initialize the AuthManager to manage authentication processes, including login and registration using PAKE (Password Authenticated Key Exchange).

        Args:
            db (Session): The SQLAlchemy session instance to interact with the database.
        """
        self.db = db
        self.shared_key: Optional[bytes] = None

    def generate_user_key(self) -> bytes:
        """
        Generate a user-specific private key for the OPRF (Oblivious Pseudo-Random Function) and return it as bytes.

        ?? the key is a salt (how do the salt) or an ellipticcurve ??

        Returns:
            bytes: The private key serialized as bytes.
        """

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return private_key_bytes

    def perform_oprf(self, C_bytes: bytes, s_bytes: bytes) -> bytes:
        """
        Perform an OPRF operation using a private key and an input C, both provided as bytes.

        Args:
            C_bytes (bytes): The input C for the OPRF, encoded as bytes.
            s_bytes (bytes): The server's OPRF private key, encoded as bytes.

        Returns:
            bytes: The result of the OPRF operation (R) encoded as bytes.
        """

        s_key = load_pem_private_key(s_bytes, password=None, backend=default_backend())

        # Convert C_bytes into an EC point
        C_point = ec.EllipticCurvePublicNumbers.from_encoded_point(
            ec.SECP256R1(), C_bytes
        ).public_key(default_backend())

        R_point = s_key.exchange(ec.ECDH(), C_point)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"oprf result",
            backend=default_backend(),
        ).derive(R_point)

        R_bytes = derived_key

        return R_bytes

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
