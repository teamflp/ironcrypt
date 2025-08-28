import requests
import base64

class IronCryptClient:
    """
    A client for interacting with the IronCrypt daemon.
    """

    def __init__(self, base_url="http://localhost:3000"):
        """
        Initializes the client with the base URL of the IronCrypt daemon.

        :param base_url: The base URL of the daemon (e.g., "http://localhost:3000").
        """
        self.base_url = base_url

    def _get_headers(self, api_key, key_version):
        """
        Constructs the necessary headers for API requests.
        """
        if not isinstance(api_key, str) or not api_key:
            raise ValueError("API key must be a non-empty string.")

        # The daemon expects the API key to be base64 encoded
        encoded_api_key = base64.b64encode(api_key.encode('utf-8')).decode('utf-8')

        headers = {
            "Authorization": f"Bearer {encoded_api_key}",
            "Content-Type": "application/octet-stream",
        }
        if key_version:
            headers["X-Key-Version"] = key_version
        return headers

    def encrypt(self, data, api_key, key_version="v1"):
        """
        Encrypts data by calling the daemon's /encrypt endpoint.

        :param data: The data to encrypt (bytes or string).
        :param api_key: The API key for authentication.
        :param key_version: The key version to use for encryption (e.g., "v1").
        :return: The encrypted data as bytes.
        :raises requests.exceptions.RequestException: For network or HTTP errors.
        """
        url = f"{self.base_url}/encrypt"
        headers = self._get_headers(api_key, key_version)

        if isinstance(data, str):
            data = data.encode('utf-8')

        response = requests.post(url, headers=headers, data=data, stream=True)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)

        return response.content

    def decrypt(self, encrypted_data, api_key, key_version="v1"):
        """
        Decrypts data by calling the daemon's /decrypt endpoint.

        :param encrypted_data: The encrypted data to decrypt (bytes).
        :param api_key: The API key for authentication.
        :param key_version: The key version used for the original encryption.
        :return: The decrypted data as bytes.
        :raises requests.exceptions.RequestException: For network or HTTP errors.
        """
        url = f"{self.base_url}/decrypt"
        headers = self._get_headers(api_key, key_version)

        response = requests.post(url, headers=headers, data=encrypted_data, stream=True)
        response.raise_for_status()

        return response.content
