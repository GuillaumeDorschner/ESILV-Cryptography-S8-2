from flask import Flask, request, jsonify
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os

app = Flask(__name__)


# https://datatracker.ietf.org/doc/html/rfc3526#page-3
# Pour l'instant il manque la fonction qui calcule "q" ....
# calcule H(p), le hash du password selon la méthode définie dans l'énoncé
def H(password, q):
    # pas sur de la nécessité de hasher, on peut juste str => int je pense
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode())
    hashed = digest.finalize()

    # Convert hash to an integer
    s = int.from_bytes(hashed, byteorder="big")

    # Ensure s is in the range [2, q]
    s = 2 + (s % (q - 2))

    Hp = pow(s, 2, 2 * q + 1)

    return Hp


# Récupère G (cf Concrete Implemention p.12) : le groupe cyclique de premiers d'ordre q
# En utilisant l'algo DC 3526
def C(Hp, q):
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    p = parameters.parameter_numbers().p

    global r
    r = int.from_bytes(os.urandom(256), byteorder="big") % (q) + 1

    # Step 3: Compute C = H(P)^r mod p
    C = pow(Hp, r, p)

    return C


def IniCom():
    username = input("username :")
    password = input("password :")
    # on ne connait pas encore q...
    q = 0
    Hp = H(password, q)
    C = C(Hp, q)
    # on envoit c au serveur


# soit R la réponse du serveur
def computeOPRF(R, S_pub_key):
    # calculer la rwd à partir de la réponse du serveur
    # "compute z = r^(-1)"
    z = 1 / r
    rwd = pow(R, z)
    # rwd : la random key

    # suite : genérer la public and private key
    global C_priv_key, C_pub_key

    C_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    C_pub_key = C_priv_key.public_key()

    # Envellope (M)
    # avec M =  Encrypt(K=rwd, C_priv_key || S_pub_key)

    # TO DO : convertir ici rwd en bytes
    if len(rwd) not in [16, 24, 32]:
        raise ValueError("Invalid key size for AES-GCM.")

    # Serialization des clées pour obtenir les représentation en bytes
    C_priv_key_bytes = C_priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    S_pub_key_bytes = S_pub_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    concatenated_keys = C_priv_key_bytes + S_pub_key_bytes
    aesgcm = AESGCM(rwd)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, concatenated_keys, None)
    M = nonce + ciphertext
    return M

    # Encrypt the concatenated keys using AES-GCM, producing ciphertext and tag
    ciphertext = aesgcm.encrypt(nonce, concatenated_keys, None)


# ------------------- Login -------------------


# decrypt envelop
def decrypt_envelop(rwd, M):
    # Validate key size for AES-GCM
    if len(rwd) not in [16, 24, 32]:
        raise ValueError("Invalid key size for AES-GCM.")

    # Extract the nonce and ciphertext from M
    nonce = M[:12]  # Assuming the nonce is the first 12 bytes of M
    ciphertext = M[12:]  # The rest is the ciphertext

    # Initialize AES-GCM with the same key used for encryption
    aesgcm = AESGCM(rwd)

    # Decrypt the ciphertext using AES-GCM
    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)  # Associated data is set to None
        return decrypted_data
    except Exception as e:
        # Handle decryption failure (e.g., due to tampering or incorrect key)
        print(f"Decryption failed: {e}")
        return None


# ------------------- AKE -------------------


def AKE(request_step, username, signed_hash):
    print("The following hash should be the same on the server and the client: ")
    print("Singed hash with private key: ", request.form.get("signed_hash"))
    pass
