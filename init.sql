CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    oprf_key BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    encrypted_envelope BYTEA NOT NULL
);
