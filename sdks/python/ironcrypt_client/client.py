import requests


class IronCryptClient:
    """
    Client for the IronCrypt HTTP daemon (`ironcryptd`).

    Endpoints: POST /write (encrypt), POST /read (decrypt).
    The API key is the secret base64 value from `ironcrypt generate-api-key`
    (send as-is in Authorization: Bearer — do not re-encode).
    """

    def __init__(self, base_url="http://127.0.0.1:3000"):
        self.base_url = base_url.rstrip("/")

    def _get_headers(self, api_key, password=None):
        if not isinstance(api_key, str) or not api_key:
            raise ValueError("API key must be a non-empty string.")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/octet-stream",
        }
        if password:
            headers["X-Password"] = password
        return headers

    def encrypt(self, data, api_key, password=None):
        """Encrypt via POST /write. Returns ciphertext bytes."""
        url = f"{self.base_url}/write"
        headers = self._get_headers(api_key, password)

        if isinstance(data, str):
            data = data.encode("utf-8")

        response = requests.post(url, headers=headers, data=data, stream=True)
        response.raise_for_status()
        return response.content

    def decrypt(self, encrypted_data, api_key, password=None):
        """Decrypt via POST /read. Returns plaintext bytes."""
        url = f"{self.base_url}/read"
        headers = self._get_headers(api_key, password)

        response = requests.post(
            url, headers=headers, data=encrypted_data, stream=True
        )
        response.raise_for_status()
        return response.content
