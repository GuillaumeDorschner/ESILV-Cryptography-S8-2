import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import requests
import base64
import json

global r, p, q, C_priv_key, C_pub_key

# donc dans les posts les types nommés bytes 

parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
p = parameters.parameter_numbers().p
print (p, "\n type p : ", type (p))
q = (p-1)//2


#calcule H(p), le hash du password selon la méthode définie dans l'énoncé
def H(password):
    #pas sur de la nécessité de hasher, on peut juste str => int je pense
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode())
    hashed = digest.finalize()
    # Convert hash to an integer
    s = int.from_bytes(hashed, byteorder='big')
    # Ensure s is in the range [2, q]
    s = 2 + (s % (q - 2))
    Hp = pow(s, 2, 2*q + 1)
    return Hp

# Récupère G (cf Concrete Implemention p.12) : le groupe cyclique de premiers d'ordre q
# En utilisant l'algo DC 3526

def SignUp_step1():
    global username
    C = 0

    print("\n Thank you for signing up, please enter your credentials below : \n")
    username = input("username : ")
    password = input("password : ")

    # A checker
    server_url = "http://localhost:8080"
    signup_route = "/signup"
    url = server_url + signup_route

    Hp = H(password) 
    r = int.from_bytes(os.urandom(256), byteorder='big') % (q) + 1
    C = pow(Hp, r, p)
    print(type(C))

    data = {
    'request_step': 1,  # Assuming we're doing the first step of the signup process
    'username': username,  # The desired username
    'oprf_begin': C,  
    "p_value" : p, #p est un int
    "q_value" : q  #q est un int
    }



    print (C)
    print(f"\n you are signing up as \"{username}\" with password : \"{password}\"")
    print (f"\n initiating first step of OPRF :")
    print (f"\n posting : {str(data)}, \nto \"{url}\" : \n")

        # Convert the Python dictionary to a JSON string
    data_json = json.dumps(data)

    # Set the headers to indicate JSON content
    headers = {'Content-Type': 'application/json'}

    response = requests.post(url, data=data_json,headers=headers)
    if response.ok:
        print("Signup request was successful.")
        print("Response:", response.json())
    else:
        print("Signup request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)
    # Step 2 of OPRF
        
    R = response['oprf']
    S_pub_key = response["server_public_key"]

    #to do check types
    M = computeOPRF(R,S_pub_key)

    data = {
    'request_step': 2,  # int
    'username': str(username),  # str
    'encrypted_envelope': M.encode() #bytes 
    }

    response = requests.post(url, data=data)
    if response.ok:
        print("Signup request was successful.")
        print("Response:", response.json())
    else:
        print("Signup request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


#soit R la réponse du serveur
def computeOPRF(R,S_pub_key) :
    #calculer la rwd à partir de la réponse du serveur
    # "compute z = r^(-1)"
    z = 1/r
    rwd = pow(R,z)
    # rwd : la random key

    #suite : genérer la public and private key
    global C_priv_key, C_pub_key

    SignUp_step1()
    
    S_pub_key_bytes = S_pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    concatenated_keys = C_priv_key_bytes + S_pub_key_bytes
    aesgcm = AESGCM(rwd)
    nonce = os.urandom(12) 
    ciphertext = aesgcm.encrypt(nonce, concatenated_keys, None) 
    M = nonce + ciphertext
    return M

    # Encrypt the concatenated keys using AES-GCM, producing ciphertext and tag
    ciphertext = aesgcm.encrypt(nonce, concatenated_keys, None)




#login
    
#decrypt envelop
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
    


# --------------- Diffie Hellman ---------------


def AKE(client_private_key_pem: bytes, server_public_key_pem: bytes) -> bytes:
    """
    Perform the Authenticated Key ENonetes): The PEM-encoded client's private key.
        server_public_key_pem (bytes): The PEM-encoded server's public key.

    Returns:
        bytes: The derived shared key.
    """
    client_private_key = serialization.load_pem_public_key(
        client_private_key_pem, backend=default_backend()
    )

    server_public_key = serialization.load_pem_public_key(
        server_public_key_pem, backend=default_backend()
    )

    shared_key = client_private_key.exchange(server_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend(),
    ).derive(shared_key)

    return derived_key


# --------------- In the futur ---------------


def encrypt_data(shared_key: bytes, data: str) -> bytes:
    if shared_key is None:
        raise Exception("Shared key not set")

    f = Fernet(shared_key)

    encrypted_data = f.decrypt(data)

    return encrypted_data

    
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
    


# --------------- Diffie Hellman ---------------


def AKE(client_private_key_pem: bytes, server_public_key_pem: bytes) -> bytes:
    """
    Perform the Authenticated Key ENonetes): The PEM-encoded client's private key.
        server_public_key_pem (bytes): The PEM-encoded server's public key.

    Returns:
        bytes: The derived shared key.
    """
    client_private_key = serialization.load_pem_public_key(
        client_private_key_pem, backend=default_backend()
    )

    server_public_key = serialization.load_pem_public_key(
        server_public_key_pem, backend=default_backend()
    )

    shared_key = client_private_key.exchange(server_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend(),
    ).derive(shared_key)

    return derived_key


# --------------- In the futur ---------------


def encrypt_data(shared_key: bytes, data: str) -> bytes:
    if shared_key is None:
        raise Exception("Shared key not set")

    f = Fernet(shared_key)

    encrypted_data = f.decrypt(data)

    return encrypted_data
