<div style="display: flex; justify-content: center; align-items: center; width: 500px; margin: 0 auto;">
    <img src="https://avatars.githubusercontent.com/u/44686652?v=4" height=100 style="align-self: center;">
    <img src="https://media.discordapp.net/attachments/1172462760530034742/1215056991190392893/image.png?ex=65fb5d01&is=65e8e801&hm=9bdd484fcc715d50b973f4d8feab28ad0862fa68dc7ff435b1b46e8fa6902900&=&format=webp&quality=lossless&width=920&height=936" height=100 style="align-self: center;">
    <div style="padding: 20px; text-align: center;">
        <h3 style="font-size: 16px;">Project CryptoGraphie - 2</h3>
        <h3 style="font-size: 16px;">Guillaume Dorschner & Jules Deleuse</h3>
        <h3 style="font-size: 16px;">A4 - CCC</h3>
    </div>
    <img src="https://www.esilv.fr/ecole-ingenieur/logos/logo_esilv_png_couleur.png" width="100" style="align-self: center;">
</div>

# Introduction

This project is a comprehensive exploration of cryptographic principles and their application in securing user data. Through a two-part implementation focusing on **password storage** [see her](https://github.com/GuillaumeDorschner/ESILV-Cryptography-S8-1) and **Password-Authenticated Key Exchange (PAKE)**, this project demonstrates robust security practices in application development.


# Project Implementation

The second part of your project involves Password-Authenticated Key Exchange (PAKE), focusing on securely authenticating users without transmitting passwords in cleartext, even without an encrypted channel. This part delves into Asymmetric PAKE, a method to store user secrets on a server without giving the server access to those secrets. It employs a cryptographic exchange allowing the server to store a "locked" secret envelope, which the user can unlock using their password and a server-known secret key. The process involves Oblivious Pseudo-Random Functions (OPRF) for secure exchanges and outlines steps for registration and login phases, emphasizing the importance of not revealing any additional information beyond whether the password matches the expected value.

# Getting Started

## Installation

> [!NOTE]
> Temporary instructions for running the project locally.
> 1. terminal 1
>    ```bash
>     python -m client.main
>     ```
> 2. terminal 2
>    ```bash
>     uvicorn server.main:app --reload
>     ```
> 3. docker compose up
>    ```bash
>     docker-compose up
>     ```

We use docker to run the application for simplicity. You can install docker from [here](https://docs.docker.com/get-docker/).

1. Download docker on your computer
2. Download the [release](https://github.com/GuillaumeDorschner/ESILV-Cryptography-S8/releases/latest) of the project
3. Change the example.env to .env and fill in the environment variables. Then run the following command to start the application:

```bash
docker compose up
```

# What we will be using

All the code is written in Python, and we will be using the following libraries:
- [FastAPI](https://fastapi.tiangolo.com/)
- [requests](https://docs.python-requests.org/en/master/)
- [PostgreSQL database](https://www.postgresql.org/)
- [cryptography.io](https://cryptography.io/)

```mermaid
graph LR
    Client[Client terminal] <--> Server
    Server[Backend] --> Postgres[PostgreSQL database]
    Server --> cryptography[cryptography.io]
```


# Diagrams and Explanations

Example of Sequence Diagram.

```mermaid
    sequenceDiagram
    participant U as User (Alice)
    participant S as Server (Bob)

    Note over U,S: Registration Phase
        Note over U: User chooses a password, tells its username
        U->>U: Initiate OPRF (deterministic) flow
        U->>U: Get Password (pwd) from client in OPRF exchange
        U->>+S: current state of OPRF : F (pwd, ?)
        Note over S: Generates a user specific OPRF key for the user
        S->>S: Completes OPRF using the user-specific key
        S->>-U: current state of OPRF : F (pwd, key) && server's public key (OPAQUE identity)
        U->>U: Generates the client's key pair (public U/private U) (OPAQUE identity)
        U->>U: Computes random key (rwd) from OPRF output
        U->>U: Encrypts CLIENT private Key & SERVER public key S with rwd -> encrypted envelope
        U->>+S: Sends encrypted envelope + client unencrypted public key
        S->>-S: Stores the envelope, U public key, OPRF user specific key, indexed by username


    Note over U,S: Login Phase
        U->>U: Initiate OPRF (deterministic) flow
        U->>+S: Requests connection (provides username) <br> Current state of OPRF : F (pwd, ?)
        S->>S: Fetch Client related data using Username
        S->>S: Completes OPRF using the client specific key
        S->>-U: Sends back encrypted envelope <br> Current state of OPRF : F (pwd, key)
        U->>U: Decrypts envelope using OPRF result
        U->>U: If decryption fails, abort login (cause : wrong password or server spoofing)
        U->>U: Has : client secret key, server public key
        U->>U: Has : begin AKE protocole
        U->>S: AKE : Inputs client's private key + server public key
        S->>S: Receives AKE demand
        S->>U: AKE : Inputs server's private key + client public key
        U->>U: if AKE  successful :
        U->>U: receives fresh shared key from AKE
        S->>S: receives fresh shared key from AKE

    Note over U,S: Now both sides have : their private key, the other side's pubblic key, and the shared key
        U->>U: Initiate Login
        U->>U: Hashes shared key (K) using SHA256
        U->>U: Signs the hash with client private key
        U->>S: Sends the signed hash to server
        S->>S: Verifies the signature using Client public key
        S->>S: Verifies the hash using shared key (K)
```
