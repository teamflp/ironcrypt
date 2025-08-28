# IronCrypt Python SDK

This Python SDK provides a simple client for interacting with the IronCrypt daemon's HTTP API.

## Installation

To install the SDK, navigate to this directory (`sdks/python`) in your terminal and run:

```bash
pip install .
```

This will install the `ironcrypt-sdk` package in your Python environment. Make sure you have the `requests` library installed, as it is a dependency.

```bash
pip install requests
```

## Usage

Here's a simple example of how to use the client to encrypt and decrypt data.

First, make sure the IronCrypt daemon is running.

```python
from ironcrypt_client import IronCryptClient

# Initialize the client
# The base URL should match where your IronCrypt daemon is running.
client = IronCryptClient(base_url="http://localhost:3000")

# --- Configuration ---
# This is the secret API key you generated with `ironcrypt generate-api-key`.
# The daemon must be configured to use the corresponding hash.
API_KEY = "your_secret_api_key_here"
KEY_VERSION = "v1" # The key version the daemon is configured to use.

# --- Data to encrypt ---
original_data = "This is a top secret message!"

try:
    # 1. Encrypt the data
    print(f"Encrypting: '{original_data}'")
    encrypted_data = client.encrypt(
        data=original_data,
        api_key=API_KEY,
        key_version=KEY_VERSION
    )
    print("Encryption successful.")
    print(f"Encrypted data (first 32 bytes): {encrypted_data[:32].hex()}...")
    print("-" * 20)

    # 2. Decrypt the data
    print("Decrypting...")
    decrypted_data = client.decrypt(
        encrypted_data=encrypted_data,
        api_key=API_KEY,
        key_version=KEY_VERSION
    )
    decrypted_string = decrypted_data.decode('utf-8')
    print("Decryption successful.")
    print(f"Decrypted string: '{decrypted_string}'")
    print("-" * 20)

    # 3. Verify correctness
    assert original_data == decrypted_string
    print("✅ Success: Decrypted data matches the original data!")

except Exception as e:
    print(f"An error occurred: {e}")

```
