from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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
        self.shared_key: bytes = None

    def generate_user_key(self) -> ec.EllipticCurvePrivateKey:
        """
        Generate a user-specific elliptic curve private key for the OPRF (Oblivious Pseudo-Random Function).

        Returns:
            ec.EllipticCurvePrivateKey: The generated elliptic curve private key.
        """
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        return private_key

    def perform_oprf(self, C: str, s: ec.EllipticCurvePrivateKey) -> str:
        """
        Perform an Oblivious Pseudo-Random Function (OPRF) with the user-specific key.

        Calcul is the following: R = C^s

        Args:
            C (str): The input data for the OPRF.
            s (ec.EllipticCurvePrivateKey): The user-specific private key used in the OPRF.

        Returns:
            R (str): The result of the OPRF.
        """

        R = pow(int(C), s.private_numbers().private_value, s.curve().field().n)

        return str(R)

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
        self.shared_key = None

    # # not like that because the user don't send the shared key (use for encryption) the login should be with something else
    # def login_required(self, shared_key: str):
    #     return self.shared_key == shared_key

    def decrypt_data(self, encrypted_data: bytes) -> str:
        if self.shared_key is None:
            raise Exception("Shared key not set")

        f = Fernet(self.shared_key)

        data = f.decrypt(encrypted_data)

        return data.decode("utf-8")
