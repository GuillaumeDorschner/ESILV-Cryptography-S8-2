CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    oprf_key NUMERIC NOT NULL,
    encrypted_envelope BYTEA,
    client_public_key BYTEA,
);