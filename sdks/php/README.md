# IronCrypt PHP SDK

This PHP SDK provides a simple client for interacting with the IronCrypt daemon's HTTP API.

## Requirements

*   PHP 7.4 or higher
*   Composer for dependency management

## Installation

1.  Make sure you have [Composer](https://getcomposer.org/) installed.
2.  Navigate to this directory (`sdks/php`) in your terminal and run the following command to install the dependencies (like Guzzle):

    ```bash
    composer install
    ```

This will download the required libraries into a `vendor` directory.

## Usage

Here's a simple example of how to use the client to encrypt and decrypt data. You must include the Composer-generated autoloader in your PHP script to use the SDK classes.

First, make sure the IronCrypt daemon is running.

```php
<?php

// Include the Composer autoloader
require_once __DIR__ . '/vendor/autoload.php';

use IronCrypt\Sdk\IronCryptClient;

// Initialize the client
// The base URL should match where your IronCrypt daemon is running.
$client = new IronCryptClient('http://localhost:3000');

// --- Configuration ---
// This is the secret API key you generated with `ironcrypt generate-api-key`.
// The daemon must be configured to use the corresponding hash.
$apiKey = 'your_secret_api_key_here';
$keyVersion = 'v1'; // The key version the daemon is configured to use.

// --- Data to encrypt ---
$originalData = "This is a top secret message from PHP!";

try {
    // 1. Encrypt the data
    echo "Encrypting: '{$originalData}'\n";
    $encryptedData = $client->encrypt($originalData, $apiKey, $keyVersion);
    echo "Encryption successful.\n";
    echo "Encrypted data (first 32 bytes): " . bin2hex(substr($encryptedData, 0, 32)) . "...\n";
    echo "--------------------\n";

    // 2. Decrypt the data
    echo "Decrypting...\n";
    $decryptedData = $client->decrypt($encryptedData, $apiKey, $keyVersion);
    echo "Decryption successful.\n";
    echo "Decrypted string: '{$decryptedData}'\n";
    echo "--------------------\n";

    // 3. Verify correctness
    assert($originalData === $decryptedData, "Decrypted data does not match original data!");
    echo "✅ Success: Decrypted data matches the original data!\n";

} catch (Exception $e) {
    echo "An error occurred: " . $e->getMessage() . "\n";
}

```
