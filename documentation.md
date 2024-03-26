# Documentaion

## API

### `/signup` Endpoint
in
- **Step 1 (POST)**
    ```json
    {
        "request_step": "1", // int
        "username": "jules", // string
        "oprf_begin": "oprfBeginData" // int
    }
    ```
out
- **Step 1 Response**
    ```json
    {
        "oprf": "oprfResult", // int
        "server_public_key": "key" // bytes
    }
    ```

in
- **Step 2 (POST)**
    ```json
    {
        "request_step": "2", // int
        "username": "jules", // string
        "encrypted_envelope": "encryptedEnvelopeData", // bytes
        "client_public_key": "userPublicKey" // bytes
    }
    ```
out
- **Step 2 Response**
    ```json
    {
        "message": "Signup successful" // string
    }
    ```

### `/login` Endpoint
in
- **POST**: For logging in, requiring username and OPRF data.
    ```json
    {
        "username": "jules", // string
        "oprf_begin": "oprfBeginData" // int
    }
    ```

out
- **POST Response**:
    ```json
    {
        "oprf": "oprfResult", // int
        "encrypted_envelope": "encryptedEnvelopeData" // bytes
    }
    ```

### `/AKE` Endpoint
in
- **POST**: For AKE, requiring username and OPRF data.
    ```json
    {
        "username": "jules", // string
        "client_public_key": "userPublicKey" // bytes
    }
    ```

out
- **POST Response**:
    ```json
    {
        "message": "AKE successful" // string
    }
    ```