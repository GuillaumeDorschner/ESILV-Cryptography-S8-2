<div style="display: flex; justify-content: center; align-items: center; width: 500px; margin: 0 auto;">
    <img src="https://avatars.githubusercontent.com/u/44686652?v=4" height=100 style="align-self: center;">
    <img src="https://media.discordapp.net/attachments/1172462760530034742/1215056991190392893/image.png?ex=65fb5d01&is=65e8e801&hm=9bdd484fcc715d50b973f4d8feab28ad0862fa68dc7ff435b1b46e8fa6902900&=&format=webp&quality=lossless&width=920&height=936" height=100 style="align-self: center;">
    <div style="padding: 20px; text-align: center;">
        <h3 style="font-size: 16px;">Project CryptoGraphie part 2</h3>
        <h3 style="font-size: 16px;">Guillaume Dorschner & Jules Deleuse</h3>
        <h3 style="font-size: 16px;">A4 - CCC</h3>
    </div>
    <img src="https://www.esilv.fr/ecole-ingenieur/logos/logo_esilv_png_couleur.png" width="100" style="align-self: center;">
</div>

# Introduction

This project is a comprehensive exploration of cryptographic principles and their application in securing user data. Through a two-part implementation focusing on **password storage** and **Password-Authenticated Key Exchange (PAKE)**, this project demonstrates robust security practices in application development.


# Project Implementation

The second part of your project involves Password-Authenticated Key Exchange (PAKE), focusing on securely authenticating users without transmitting passwords in cleartext, even without an encrypted channel. This part delves into Asymmetric PAKE, a method to store user secrets on a server without giving the server access to those secrets. It employs a cryptographic exchange allowing the server to store a "locked" secret envelope, which the user can unlock using their password and a server-known secret key. The process involves Oblivious Pseudo-Random Functions (OPRF) for secure exchanges and outlines steps for registration and login phases, emphasizing the importance of not revealing any additional information beyond whether the password matches the expected value.

# Getting Started

## Installation

We use docker to run the application for simplicity. You can install docker from [here](https://docs.docker.com/get-docker/).

1. Download docker on your computer
2. Download the [release](https://github.com/GuillaumeDorschner/ESILV-Cryptography-S8/releases/latest) of the project
3. Change the example.env to .env and fill in the environment variables. Then run the following command to start the application:

```bash
docker compose up
```

# Diagrams and Explanations

Example of Sequence Diagram.

```mermaid
    sequenceDiagram
    participant U as User (Alice)
    participant S as Server (Bob)

    Note over U,S: Registration Phase
    Note over U: User chooses a password
    U->>U: Computes 1/2 OPRF using the password
    U->>+S: Submits username and OPRF(password)
    Note over S: Generates OPRF key for the user
    S->>S: Completes OPRF using the user-specific key
    S->>-U: Returns user-specific OPRF Key
    U->>U: Generates a key pair (public U/private U)
    U->>U: Encrypts private key U + public key S (BpkO) with OPRF -> Envelope
    U->>+S: Sends encrypted envelope + public key U
    S->>-S: Stores the envelope, U public key, OPRF key

    Note over U,S: Login Phase
    U->>U: Computes 1/2 OPRF using the password
    U->>+S: Requests connection (provides username)
    U->>+S: Submits OPRF(password) for login
    S->>S: Completes OPRF using the stored key
    S->>-U: Returns OPRF result for login
    S->>-U: Sends back encrypted envelope
    U->>U: Decrypts envelope using OPRF result
    Note over U,S: Demonstration (via Diffie-Hellman or ...)
    U->>+S: Demonstrates possession of the private key
    S->>-S: Verifies proof, establishes shared secret key
    Note over U,S: Secure communication established
```