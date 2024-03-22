# Todos

## Client

### Initial Communication
- [ ] Get password, username from client

**OPRF - 1st Step**
- [ ] Compute: `F(pwd, ?)`
- [ ] Send: `F(pwd, ?)`

---

### Processing OPRF Output
- [ ] Receive: OPRF output
- [ ] Generate the client's asymmetric key pair
- [ ] Compute random key (rwd) from OPRF output
- [ ] Encrypt CLIENT private Key & SERVER public key with rwd -> encrypted envelope
- [ ] Send: encrypted envelope + unencrypted public key

---

### Finalizing Authentication
- [ ] Decrypt envelope with OPRF output
- [ ] Case: if decryption fails => abort login
- [ ] Formulate AKE demand
- [ ] **AKE Protocol**
- [ ] Inputs: client's private key, server public key
- [ ] Generate shared key from successful AKE
- [ ] Hash shared key (K) using SHA256
- [ ] Sign hash with client's private key
- [ ] Send: signed hash

## Server

### Receiving Initial Request
- [ ] Receive: `F(pwd, ?)`
- [ ] Generate a user-specific OPRF key for the user
- **OPRF - 2nd Step**
- [ ] Compute: `F(pwd, key)`
- [ ] Generate server's asymmetric key pair
- [ ] Send: `F(pwd, key)` && server's public key

---

### Handling Encrypted Envelope
- [ ] Receive: encrypted envelope + unencrypted public key
- [ ] Store: envelope, user's public key, OPRF user-specific key, indexed by username

---

### Processing Authentication
- [ ] Fetch: Client-related data using Username
- [ ] Send: encrypted envelope
- [ ] Receive: AKE demand
- [ ] **AKE Protocol**
- [ ] Inputs: server's private key & client public key
- [ ] Generate shared key from successful AKE

---

### Verifying Client
- [ ] Verify signature using client public key
- [ ] Verify hash using shared key
