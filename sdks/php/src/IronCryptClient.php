<?php

namespace IronCrypt\Sdk;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

/**
 * Client for the IronCrypt HTTP daemon (`ironcryptd`).
 *
 * Endpoints: POST /write (encrypt), POST /read (decrypt).
 * Pass the secret API key from `ironcrypt generate-api-key` as-is
 * (already base64) in Authorization: Bearer — do not re-encode.
 */
class IronCryptClient
{
    protected $client;
    protected $baseUrl;

    public function __construct(string $baseUrl = 'http://127.0.0.1:3000')
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->client = new Client([
            'base_uri' => $this->baseUrl . '/',
            'timeout'  => 30.0,
        ]);
    }

    /**
     * Encrypts data via POST /write.
     *
     * @param string|resource $data
     * @param string $apiKey Secret API key (base64 from generate-api-key)
     * @param string|null $password Optional Argon2 gate (X-Password)
     * @return string Ciphertext bytes
     * @throws RequestException
     */
    public function encrypt($data, string $apiKey, ?string $password = null): string
    {
        $response = $this->client->post('write', [
            'headers' => $this->getHeaders($apiKey, $password),
            'body' => $data,
        ]);

        return $response->getBody()->getContents();
    }

    /**
     * Decrypts data via POST /read.
     *
     * @param string|resource $encryptedData
     * @param string $apiKey
     * @param string|null $password
     * @return string Plaintext bytes
     * @throws RequestException
     */
    public function decrypt($encryptedData, string $apiKey, ?string $password = null): string
    {
        $response = $this->client->post('read', [
            'headers' => $this->getHeaders($apiKey, $password),
            'body' => $encryptedData,
        ]);

        return $response->getBody()->getContents();
    }

    private function getHeaders(string $apiKey, ?string $password): array
    {
        if ($apiKey === '') {
            throw new \InvalidArgumentException('API key must be a non-empty string.');
        }

        $headers = [
            'Authorization' => 'Bearer ' . $apiKey,
            'Content-Type' => 'application/octet-stream',
        ];

        if ($password !== null && $password !== '') {
            $headers['X-Password'] = $password;
        }

        return $headers;
    }
}
