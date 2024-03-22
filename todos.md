# Todos

## Shared Functionnality

- [ ] 
- [ ] 
- [ ] 
- [ ] 
- [ ] 

## Client

- [ ] get password from client
- [ ] OPRF : 1st step : F(pwd,?)
- [ ] send : OPRF : 1st step : F(pwd,?)
  /--
- [ ] receive : OPRF output
- [ ] Generate the client's asymetric key pair 
- [ ] Compute random key (rwd) from OPRF output
- [ ] Encrypt CLIENT private Key & SERVER public key S with rwd -> encrypted envelope
- [ ] send : encrytped envelope + unencrypted public key
- [ ] 

## Server

- [ ] receive : F(pwd,?)
- [ ] Generate a user specific OPRF key for the user
- [ ] OPRF : 2nd step : F(pwd,key)
- [ ] Generate server's asymetric key pair
- [ ] Send :  F (pwd, key) && server's public key
/-- 
- [ ] receive : encrytped envelope + unencrypted public key
- [ ] store : envelope, U public key, OPRF user specific key, indexed by username