import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import requests
import base64



C_priv_key = rsa.generate_private_key(
public_exponent=65537,
key_size=2048
)
C_pub_key = C_priv_key.public_key()

# Envellope (M)
# avec M =  Encrypt(K=rwd, C_priv_key || S_pub_key)


# Serialization des clées pour obtenir les représentation en bytes
C_priv_key_bytes = C_priv_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  
)

print(C_priv_key_bytes)
print(type(C_priv_key_bytes))
