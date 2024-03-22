# Documentaion

## API

### `/signup` Endpoint
in
- **Step 1 (POST)**
    ```json
    {
        "request_step": "1",
        "username": "jules",
        "oprf_begin": "oprfBeginData"
    }
    ```
out
- **Step 1 Response**
    ```json
    {
        "oprf": "oprfResult",
        "server_public_key": "key"
    }
    ```

in
- **Step 2 (POST)**
    ```json
    {
        "request_step": "2",
        "username": "jules",
        "encrypted_envelope": "encryptedEnvelopeData",
        "public_key": "userPublicKey"
    }
    ```
out
- **Step 2 Response**
    ```json
    {
        "message": "Signup successful"
    }
    ```

### `/login` Endpoint
in
- **POST**: For logging in, requiring username and OPRF data.
    ```json
    {
        "username": "exampleUsername",
        "oprf_begin": "oprfBeginData"
    }
    ```

out
- **POST Response**:
    ```json
    {
        "oprf": "oprfResult",
        "encrypted_envelope": "encryptedEnvelopeData"
    }
    ```

> **Note**: soon
> ### `/AKE` Endpoint
> in
> - **General AKE Request (assuming steps)**:
>     ```json
>     {
>         
>     }
>     ```
> out
> - **General AKE Response** (The specific output would depend on the AKE process step and implementation):
>     ```json
>     {
>         
>     }
>     ```