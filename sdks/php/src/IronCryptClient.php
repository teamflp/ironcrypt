<?php

namespace IronCrypt\Sdk;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class IronCryptClient
{
    protected $client;
    protected $baseUrl;

    /**
     * IronCryptClient constructor.
     * @param string $baseUrl The base URL of the IronCrypt daemon.
     */
    public function __construct(string $baseUrl = 'http://localhost:3000')
    {
        $this->baseUrl = $baseUrl;
        $this->client = new Client([
            'base_uri' => $this->baseUrl,
            'timeout'  => 5.0,
        ]);
    }

    /**
     * Encrypts data by calling the daemon's /encrypt endpoint.
     *
     * @param string|resource $data The data to encrypt (string or stream resource).
     * @param string $apiKey The API key for authentication.
     * @param string $keyVersion The key version to use for encryption.
     * @return string The encrypted data as a binary string.
     * @throws RequestException if the request fails.
     */
    public function encrypt($data, string $apiKey, string $keyVersion = 'v1'): string
    {
        $headers = $this->getHeaders($apiKey, $keyVersion);

        $response = $this->client->post('/encrypt', [
            'headers' => $headers,
            'body' => $data
        ]);

        return $response->getBody()->getContents();
    }

    /**
     * Decrypts data by calling the daemon's /decrypt endpoint.
     *
     * @param string|resource $encryptedData The encrypted data to decrypt.
     * @param string $apiKey The API key for authentication.
     * @param string $keyVersion The key version used for the original encryption.
     * @return string The decrypted data as a binary string.
     * @throws RequestException if the request fails.
     */
    public function decrypt($encryptedData, string $apiKey, string $keyVersion = 'v1'): string
    {
        $headers = $this->getHeaders($apiKey, $keyVersion);

        $response = $this->client->post('/decrypt', [
            'headers' => $headers,
            'body' => $encryptedData
        ]);

        return $response->getBody()->getContents();
    }

    /**
     * Constructs the necessary headers for API requests.
     *
     * @param string $apiKey
     * @param string $keyVersion
     * @return array
     */
    private function getHeaders(string $apiKey, string $keyVersion): array
    {
        if (empty($apiKey)) {
            throw new \InvalidArgumentException("API key must be a non-empty string.");
        }

        // The daemon expects the API key to be base64 encoded
        $encodedApiKey = base64_encode($apiKey);

        return [
            'Authorization' => 'Bearer ' . $encodedApiKey,
            'Content-Type' => 'application/octet-stream',
            'X-Key-Version' => $keyVersion,
        ];
    }
}
