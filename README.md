

# 🔐 Roblox clientPublicKey and saiSignature

`Make sure to read the 'interceptedJs.js' file (all you need to see is in it (lines 3138-3189))`

This Python script generates a cryptographic signature for secure communication with Roblox’s API. It uses Elliptic Curve Cryptography (ECC) to generate keys and sign data containing the public key, a timestamp, and a server-provided nonce. The signed data can be used as a `saiSignature` for authorized API calls on Roblox.

## 📋 Requirements

Install dependencies with:
```bash
pip install pytermx tls_client cryptography
```

## 🔑 Key and Signature Generation Process

The `Roblox` class’s `gen_signature` method handles the generation of keys and signatures:

### 1️⃣ Generate an ECC Private Key
- Generates a private key using the `SECP256R1` elliptic curve.
- The private key is used for signing the data, ensuring secure API communication.

    ```python
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )
    ```

### 2️⃣ Extract and Encode the Public Key in SPKI Format
- Extracts the associated public key and encodes it in SPKI (Subject Public Key Info) format, DER-encoded and then base64-encoded for transmission.

    ```python
    public_key = private_key.public_key()
    public_key_spki = base64.b64encode(public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    ```

### 3️⃣ Prepare Data for Signing
- Constructs the data to sign, which includes:
  - The base64-encoded public key.
  - A current timestamp.
  - A `serverNonce` (unique value from Roblox).
- The data string is then UTF-8 encoded.

    ```python
    data = f"{public_key_spki}:{int(time.time())}:{serverNonce}".encode("utf-8")
    ```

### 4️⃣ Sign the Data
- Uses the private key to sign the data string with ECDSA and SHA256 for a secure signature.
- The resulting signature is base64-encoded, ready for use in secure API requests.

    ```python
    signature = base64.b64encode(private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    ))
    ```

## ⚙️ Usage

Run the script with:
```bash
python main.py
```

## 📝 Example Output

```plaintext
20:22:41 INF  Get Server Nonce. [eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6I...]
20:22:41 INF  Get Client Public Key. [MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6PdDlsxTh4jq0o...]
20:22:41 INF  Get saiSignature. [MEQCIBopQtFN/poBOK1l62ICF/DsTALVB6D7C3laED9JoN8ZAi...]
```

Each output shows the timestamp, action, and the first few characters of each key for verification.