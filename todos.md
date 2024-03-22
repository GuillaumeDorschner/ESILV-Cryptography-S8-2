# Todos

## Client

- [ ] Get password, username from client
- [ ] OPRF : 1st step : F(pwd,?)
- [ ] send : OPRF : 1st step : F(pwd,?)
  /--
- [ ] receive : OPRF output
- [ ] Generate the client's asymetric key pair 
- [ ] Compute random key (rwd) from OPRF output
- [ ] Encrypt CLIENT private Key & SERVER public key S with rwd -> encrypted envelope
- [ ] send : encrytped envelope + unencrypted public key
/--
- [ ] Decrypt envelop from OPRF
- [ ] Case : if decryption fails => abort login
- [ ] Formulate AKE demand.
- [ ] AKE protocol : Inputs client's private key, server public key
- [ ] generate share key from successful AKE
/--
- [ ] Hash shared key (K) using SHA256
- [ ] sign hash with client private key
- [ ] send : signed hash

## Client

- [ ] Get password, username from client
- [ ] OPRF : 1st step : F(pwd,?)
- [ ] send : OPRF : 1st step : F(pwd,?)
  /--
- [ ] receive : OPRF output
- [ ] Generate the client's asymetric key pair 
- [ ] Compute random key (rwd) from OPRF output
- [ ] Encrypt CLIENT private Key & SERVER public key S with rwd -> encrypted envelope
- [ ] send : encrytped envelope + unencrypted public key
/--
- [ ] Decrypt envelop from OPRF
- [ ] Case : if decryption fails => abort login
- [ ] Formulate AKE demand.
- [ ] AKE protocol : Inputs client's private key, server public key
- [ ] generate share key from successful AKE
/--
- [ ] Hash shared key (K) using SHA256
- [ ] sign hash with client private key
- [ ] send : signed hash

## Server

- [ ] receive : F(pwd,?)
- [ ] Generate a user specific OPRF key for the user
- [ ] OPRF : 2nd step : F(pwd,key)
- [ ] Generate server's asymetric key pair
- [ ] Send :  F (pwd, key) && server's public key
/-- 
- [ ] receive : encrytped envelope + unencrypted public key
- [ ] store : envelope, U public key, OPRF user specific key, indexed by username
/-- 
- [ ] fetch : Client related data using Username
- [ ] send : encrypted envelope
/-- 
- [ ] receive : AKE demand
- [ ] AKE protocol : input server's private key & client public key
- [ ] generate share key from successful AKE
/-- 
- [ ] Verify signature using client public key 
- [ ] Verify hash using shared key