import ast
import json
import os

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key

p = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)  # The hexadecimal value of p for the 2048-bit group, to be replaced by the exact value
g = 2
parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
q = (p - 1) // 2
r = int.from_bytes(os.urandom(256), byteorder="big") % (q) + 1
# generate the clinet's key pair.
C_priv_key = parameters.generate_private_key()
C_pub_key = C_priv_key.public_key()
nonce = 0
current = 1


# calcule H(p), le hash du password selon la méthode définie dans l'énoncé
def H(password):
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


def SignUp():
    global r, p, q, C_priv_key, C_pub_key, current
    C = 0

    print("\n Thank you for signing up, please enter your credentials below : \n")
    username = input("username : ")
    password = input("password : ")

    # A checker
    server_url = "http://localhost:8080"
    signup_route = "/signup"
    url = server_url + signup_route
    if current == 1:
        Hp = H(password)
        C = pow(Hp, r, p)

        data = {
            "request_step": 1,  # Assuming we're doing the first step of the signup process
            "username": username,
            "oprf_begin": C,
        }

        print(f'\n you are signing up as "{username}" with password : "{password}"')
        print("\n initiating first step of OPRF :")
        print(f'\n posting : {str(data)}, \nto "{url}" : \n')

        # Convert the Python dictionary to a JSON string
        data_json = json.dumps(data)
        # Set the headers to indicate JSON content
        headers = {"Content-Type": "application/json"}

        response = requests.post(url, data=data_json, headers=headers)
        if response.ok:
            data = response.json()

            print("Signup request, step 1, was successful.")
            print("Response:", data)

            R = data["oprf"]
            S_pub_key = data["server_public_key"]
            current += 1
            print("Engaging Step 2")
        else:
            print("Signup request failed.")
            print("Status Code:", response.status_code)
            print("Response:", response.text)

            Exception("Signup request failed.")
        # Step 2 of OPRF
        # to do check types

        print("INFO : entering stage 2 of the OPRF")

        print("encrypting envelop ...")
        encrypted_envelope = str(computeOPRF(R, S_pub_key))
        print("serializing Client pulic key")
        C_pub_key_bytes = serialize_key(public_key=C_pub_key)

        data = {
            "request_step": 2,
            "username": str(username),
            "encrypted_envelope": encrypted_envelope,
            "client_public_key": C_pub_key_bytes,
        }

        data_json = json.dumps(data)
        headers = {"Content-Type": "application/json"}

        response = requests.post(url, data=data_json, headers=headers)
        if response.ok:
            print("Signup request, step 2, was successful.")
            print("Response:", response.json())
            return 1
        else:
            print("Signup request failed.")
            print("Status Code:", response.status_code)
            print("Response:", response.text)


def Login():
    global r, p, q, C_priv_key, C_pub_key, current
    C = 0

    print("\n Thank you for signing up, please enter your credentials below : \n")
    username = input("username : ")
    password = input("password : ")

    server_url = "http://localhost:8080"
    signup_route = "/login"
    url = server_url + signup_route

    Hp = H(password)
    C = pow(Hp, r, p)

    data = {
        "username": username,
        "oprf_begin": C,
    }

    print(f'\n you are signing up as "{username}" with password : "{password}"')
    print("\n initiating first step of OPRF :")
    print(f'\n posting : {str(data)}, \nto "{url}" : \n')

    data_json = json.dumps(data)
    headers = {"Content-Type": "application/json"}

    response = requests.post(url, data=data_json, headers=headers)
    if response.ok:
        data = response.json()

        print("Signup request, step 1, was successful.")
        print("Response:", data)

        OPRFoutput = data["oprf"]
        encrypted_envelope = data["encrypted_envelope"]

        print("INFO : received OPRF output :\n", type(OPRFoutput), OPRFoutput)
        print(
            "INFO : received encrypted envelope :\n",
            type(encrypted_envelope),
            encrypted_envelope,
        )
        print("Engaging Step 2")
    else:
        print("Signup request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)

        Exception("Signup request failed.")

    print("INFO : deriving rwd form OPRF output : ")
    z = pow(int(r), -1, p)
    rwd = pow(int(OPRFoutput), int(z), int(p))
    rwd = derive_encryption_key(rwd)
    print("INFO : rwd successfully derived from OPRF")
    print("...........................")
    print("INFO : decrypting envelope")
    encrypted_envelope = ast.literal_eval(encrypted_envelope)
    try:
        decrypted_envelope = decrypt_personal_envelope(rwd, nonce, encrypted_envelope)
    except Exception as e:
        print(e)
    print("INFO : envelope successfully decrypted :\n\n")
    print(decrypted_envelope)

    decrypted_envelope_str = decrypted_envelope.decode("utf-8")

    keys = decrypted_envelope_str.split("DELIMITATION")
    private_key_str = keys[0]
    public_key_str = keys[1]

    # Convert the keys back to byte strings
    C_priv_key_bytes = private_key_str.encode("utf-8")

    S_pub_key = deserialize_key(public_key_str)
    # C_priv_key = deserialize_private_key(C_priv_key)
    # Variable names as requested are already assigned:
    # C_private_key will contain the private key object.
    # S_pub_key will contain the public key object.

    # Below is a demonstration that the keys have been loaded by printing their types
    print("Private Key type:", type(C_priv_key))
    print("Public Key type:", type(S_pub_key))

    shared_key = AKE(C_priv_key, S_pub_key)
    print(shared_key)

    print("INFO : initiating AKE")

    server_url = "http://localhost:8080"
    signup_route = "/AKE"
    url = server_url + signup_route

    data = {
        "username": username,  # The desired username
    }

    data_json = json.dumps(data)
    headers = {"Content-Type": "application/json"}

    response = requests.post(url, data=data_json, headers=headers)
    if response.ok:
        data = response.json()

        print("INFO : AKE successfuly initiated")

    else:
        print("AKE request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)

        Exception("AKE request failed.")

    return shared_key


def computeOPRF(R, S_pub_key_bytes):
    global nonce
    # calculer la rwd à partir de la réponse du serveur
    # "compute z = r^(-1)"
    z = pow(int(r), -1, p)
    rwd = pow(int(R), int(z), int(p))
    rwd = derive_encryption_key(rwd)
    # rwd : la random key

    C_private_key_bytes = serialize_private_key(C_priv_key)

    concatenated_keys = C_private_key_bytes + "DELIMITATION" + S_pub_key_bytes
    nonce, encrypted_envelope = encrypt_personal_envelope(rwd, concatenated_keys)
    print("INFO : envelope encrypted :\n", encrypted_envelope)
    return encrypted_envelope


# --------------- Diffie Hellman ---------------


def AKE(C_priv_key, S_pub_key) -> bytes:
    """
    Perform the Authenticated Key ENonetes): The PEM-encoded client's private key.
        server_public_key_pem (bytes): The PEM-encoded server's public key.

    Returns:
        bytes: The derived shared key.
    """

    print("\n\nALERT :", "C_priv_key :", C_priv_key)
    print("\n\nALERT :", "S_pub_key :", S_pub_key)

    shared_key = C_priv_key.exchange(S_pub_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend(),
    ).derive(shared_key)

    return derived_key


# ------------ utile pour la suite ------------


def serialize_key(public_key):
    # Convert the public key to PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Decode to string for JSON serialization
    pem_public_key_str = pem_public_key.decode("utf-8")
    return pem_public_key_str


def deserialize_key(pem_public_key_str):
    # Convert the string back to bytes
    pem_public_key_bytes = pem_public_key_str.encode("utf-8")
    # Load the public key from PEM format
    public_key = load_pem_public_key(pem_public_key_bytes, backend=default_backend())
    return public_key


def derive_encryption_key(rwd, salt=b"", info=b"personal_envelope_encryption"):
    """
    Derives an encryption key from the rwd using HKDF.
    """
    backend = default_backend()
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=info, backend=backend
    )
    key = hkdf.derive(rwd.to_bytes((rwd.bit_length() + 7) // 8, "big"))
    return key


def encrypt_personal_envelope(encryption_key, message):
    """
    Encrypts a message using AES-GCM with the given encryption key.
    """
    aesgcm = AESGCM(encryption_key)
    nonce = os.urandom(12)  # 96-bit nonce is recommended for AES-GCM
    encrypted = aesgcm.encrypt(nonce, message.encode(), None)
    return nonce, encrypted


def serialize_private_key(private_key, passphrase=None):
    # Choose encryption based on whether a passphrase was provided
    encryption_algorithm = serialization.NoEncryption()
    if passphrase is not None:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase)

    # Serialize the private key to PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )

    # Decode to string if necessary
    pem_private_key_str = pem_private_key.decode("utf-8")
    return pem_private_key_str


def decrypt_personal_envelope(encryption_key, nonce, encrypted_message):
    """
    Decrypts the encrypted message using AES-GCM with the given encryption key and nonce.
    """
    aesgcm = AESGCM(encryption_key)
    try:
        decrypted_message = aesgcm.decrypt(nonce, encrypted_message, None)
        return decrypted_message
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return None


def deserialize_private_key(pem_private_key_bytes, password=None):
    """
    Deserialize a PEM-encoded private key into a private key object.

    Args:
        pem_private_key_bytes (bytes): The PEM-encoded private key as a byte string.
        password (bytes, optional): The password to decrypt the key, if it is encrypted.
                                    Should be `None` if the key is not encrypted.

    Returns:
        Private key object: The deserialized private key.
    """
    try:
        # Attempt to load the private key
        private_key = serialization.load_pem_private_key(
            pem_private_key_bytes, password=password, backend=default_backend()
        )
        return private_key
    except ValueError as e:
        # Handle the case where the password is incorrect or the key encoding is invalid
        print("Error deserializing the private key:", str(e))
    except Exception as e:
        # Handle other potential exceptions
        print(
            "An unexpected error occurred while deserializing the private key:", str(e)
        )

    return None  # Returning None to indicate failure
