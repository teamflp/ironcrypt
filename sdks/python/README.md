# IronCrypt Python SDK

Client HTTP pour `ironcryptd` (`POST /write`, `POST /read`).

## Installation

```bash
cd sdks/python
pip install .
# dépendance : requests
```

## Usage

La clé API est la valeur secrète base64 affichée par `ironcrypt generate-api-key`
(à envoyer telle quelle dans `Authorization: Bearer …`).

```python
from ironcrypt_client import IronCryptClient

client = IronCryptClient(base_url="http://127.0.0.1:3000")
API_KEY = "your_secret_api_key_base64"

original = "This is a top secret message!"
encrypted = client.encrypt(original, api_key=API_KEY)
plain = client.decrypt(encrypted, api_key=API_KEY).decode("utf-8")
assert plain == original
```
