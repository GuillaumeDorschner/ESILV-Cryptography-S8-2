CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    oprf_key int NOT NULL,
    encrypted_envelope BYTEA NOT NULL
    client_public_key BYTEA NOT NULL,
);
