from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy.orm import Session


class AuthManager:
    def __init__(self, db: Session):
        """
        Initialize the AuthManager to manage authentication processes, including login and registration using PAKE (Password Authenticated Key Exchange).

        Args:
            db (Session): The SQLAlchemy session instance to interact with the database.
        """
        self.db = db
        self.server_private_key, self.server_public_key = self.generate_server_keys()
        self.secrect = None

    @staticmethod
    def generate_server_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate RSA public/private key pair for the server.

        Returns:
            tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]: The generated RSA private and public keys.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

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

    # --------------- PAKE ---------------

    def clear_secrect(self):
        self.secrect = None
        pass

    def login_required(self, secrect: str):
        return self.secrect == secrect

    def decrypt_data(self, data: bytes):
        cipher_key = Fernet.generate_key()
        cipher = Fernet(cipher_key)
        decrypted_data = cipher.decrypt(data)
        return decrypted_data

    # --------------- Diffie Hellman ---------------

    def AKE(self):
        self.secrect = "ljdslkfjlkd"
        pass
