# IronCrypt

[[[Installation Button]]](#installation)\
[[[Usage Button]]](#usage)\
[[[Contribute Button]]](#contribution)

<!-- TOC -->
* [IronCrypt](#ironcrypt)
  * [Features](#features)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
  * [Usage](#usage)
    * [Available Commands](#available-commands)
    * [Generate](#generate)
      * [Decrypt](#decrypt)
  * [Examples](#examples)
    * [Generating RSA Keys](#generating-rsa-keys)
    * [Encrypting a Password](#encrypting-a-password)
    * [Decrypting and Verifying a Password](#decrypting-and-verifying-a-password)
  * [Full Example: Password Encryption and Decryption](#full-example-password-encryption-and-decryption)
    * [Steps:](#steps)
  * [Error Handling](#error-handling)
  * [Security and Best Practices](#security-and-best-practices)
  * [Contribution](#contribution)
  * [License](#license)
<!-- TOC -->

**IronCrypt** is a Command-Line Interface (CLI) tool and Rust library dedicated to the secure encryption of passwords. By combining the **Argon2** hashing algorithm, **AES-256-GCM** encryption, and asymmetric **RSA** encryption, IronCrypt offers a robust solution for managing passwords securely within your applications.

## Features

- **Password Strength Verification**: Ensures that passwords meet stringent security criteria (length, uppercase letters, numbers, special characters, etc.).
- **Secure Password Hashing**: Utilizes **Argon2** for robust password hashing.
- **Data Encryption**: Encrypts hashed passwords using **AES-256-GCM** to ensure confidentiality and integrity.
- **Asymmetric Key Encryption**: Employs **RSA** to encrypt the symmetric key used by AES, enabling secure key management.
- **Password Decryption and Verification**: Decrypts encrypted data and verifies the authenticity of the provided password.
- **RSA Key Management**: Generates, saves, and loads RSA key pairs from PEM files.
- **Intuitive CLI Interface**: Provides user-friendly commands for managing encryption operations and key handling.

---

## Prerequisites

- **Rust** &gt;= 1.56
- **Cargo** (Rust's package manager)

Ensure your `Cargo.toml` includes the necessary dependencies:

```toml
[dependencies]
serde = { version = "1.0.210", features = ["derive"] }
argon2 = "0.5.3"
base64 = "0.22.1"
rsa = { version = "0.9.6", features = ["pem"] }
serde_json = "1.0"
sha2 = "0.10.6"
rand = "0.8.5"
rand_chacha = "0.3.1"
rand_core = "0.6.4"
clap = { version = "4.5.20", features = ["derive"] }
thiserror = "1.0.64"
indicatif = "0.17.2"
```

## Installation

Add `IronCrypt` to your project using `cargo`:

```bash
cargo add ironcrypt
```

Or, manually add the following line to your `Cargo.toml`:

```toml
[dependencies]
ironcrypt = "0.1.0"
```

## Usage

IronCrypt offers a CLI with several commands to manage RSA keys and handle password encryption. Below are the available commands:

### Available Commands

| **Command**   | **Description**                                    |
|---------------|----------------------------------------------------|
| `generate`    | Generates an RSA key pair (private and public).    |
| `encrypt`     | Hashes and encrypts a password using a public key. |
| `decrypt`     | Decrypts encrypted data and verifies a password.   |

### Generate

Generates an RSA key pair (private and public).

**Syntax:**

```bash
cargo run -- generate -v <version> -d <directory> -s <key_size>
```

| Option        | Short | Description                              | Default |
|---------------|-------|------------------------------------------|---------|
| \- -version   | \-v   | Version identifier for the key pair.     | N/A     |
| \- -directory | \-d   | Directory path where keys will be saved. | key     |
| \- -key_size  | \-s   | Size of the RSA key in bits.             | 2048    |

**Exemple :**

```bash
cargo run -- generate -v v1 -d keys -s 4096
```

This command generates a 4096-bit RSA key pair labeled with version v1 and saves them in the keys directory.

**Encryp**t\
Hashes and encrypts a password using a public key.

Syntax:

```bash
cargo run -- encrypt -w <password> -d <public_key_directory> -v <key_version>
```

| Option                   | Short | Description                                  | Default |
|--------------------------|-------|----------------------------------------------|---------|
| `--password`             | `-w`  | The password to hash and encrypt.            | N/A     |
| `--public_key_directory` | `-d`  | Directory path containing public keys.       | `keys`  |
| `--key_version`          | `-v`  | Version identifier of the public key to use. | N/A     |

**Example:**

```bash
cargo run -- encrypt -w 'YourP@ssw0rd!' -d keys -v v1
```

This command hashes and encrypts the password `YourP@ssw0rd!` using the public key of version `v1` located in the `keys`directory.

#### Decrypt

Decrypts encrypted data and verifies a password.

**Syntax:**

```bash
cargo run -- decrypt -w <password> -k <private_key_directory> [-d <data> | -f <file>]
```

**Note:** The `-d` (data) and `-f` (file) options are mutually exclusive.

| Option                    | Short | Description                               | Default |
|---------------------------|-------|-------------------------------------------|---------|
| `--password`              | `-w`  | The password to verify.                   | N/A     |
| `--private_key_directory` | `-k`  | Directory path containing private keys.   | `keys`  |
| `--data`                  | `-d`  | Encrypted data as a direct string input.  | `None`  |
| `--file`                  | `-f`  | Path to a file containing encrypted data. | `None`  |

**Example with Direct Data Input:**

```bash
cargo run -- decrypt -w 'YourP@ssw0rd!' -k keys -d '{"ciphertext":"...","encrypted_symmetric_key":"...","nonce":"..."}'
```

**Example with File:**

```bash
cargo run -- decrypt -w 'YourP@ssw0rd!' -k keys -f encrypted_data.json
```

This command decrypts the encrypted data using the private key in the `keys` directory and verifies if the provided password matches.

## Examples

### Generating RSA Keys

Generate an RSA key pair with version `v1`, saved in the `keys` directory with a key size of 4096 bits.

```bash
cargo run -- generate -v v1 -d keys -s 4096
```

**Output:**

```vbnet
⠋ Generating RSA keys...
✔ RSA key generation completed.
RSA keys have been successfully generated and saved.
Private Key: keys/private_key_v1.pem
Public Key: keys/public_key_v1.pem
```

### Encrypting a Password

Hash and encrypt the password `YourP@ssw0rd!` using the public key of version `v1`.

```bash
cargo run -- encrypt -w 'YourP@ssw0rd!' -d keys -v v1
```

**Output:**

```bash
Hashed and encrypted password: {"ciphertext":"P2A4hrhIg9E9o+sChKPK3zrwo/49Cutpb0FoxmZSfzs6YmG0wkiToEVy9vKBaxMcYzM7sAWso2977vzgrIReTZfHPMBnsi2yVR6xh7RUIeoNJvx346Ya8ws/GI+HjxTVOXZh2odHPFS7mHUpWASOb7U=","encrypted_symmetric_key":"j/MMqYqHNEh8+Go1HsjlLWfQlg9/94meH6sNpPcYQt1ZEwA5BoGVaJ1hcOt0A6Sv54dwlG4Yr8WrHUkPR04raw0jFhSNkk7iO5fZJwuA8gvYRLhnAxyW0X/vRJzwUaee4TuDt9r4Zr3DppAl12lW03SkOkuwFokrz8AGg6G1LqnUz0CwgbfmOauM2+O70VDA4cTCb6mH7LmslplS6pUuY5U3M8inWag6Z907Q6yV4HNYdHxAuYHfLK/XxOiHCsH8H8EfWbVt7BU31PC8o2L+MkfTyf6f5t4wvQtAx2BWvMt7zE9JWYVs1aTxsJC4urO4oeer/XddZLym7t6xsNTNoQ==","nonce":"W7q6TjwB4x0ysavW"}
```

### Decrypting and Verifying a Password

Decrypt the encrypted data from a file and verify the password.

```
cargo run -- decrypt -w 'YourP@ssw0rd!' -k keys -f encrypted_data.json
```

**Output if the password is correct:**

```bash
The password is correct.
```

**Output in case of an error:**

```bash
The password is incorrect or an error occurred: Detailed error message here
```

## Full Example: Password Encryption and Decryption

Before using IronCrypt for password encryption and decryption, generate an RSA key pair using:

```bash
cargo run -- generate -v v1 -d keys -s 4096
```

Then use the following code to encrypt and verify passwords:

```rust
use ironcrypt::{hash_and_encrypt_password_with_criteria, decrypt_and_verify_password, load_private_key, load_public_key, PasswordCriteria};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // ------------------------- 1. Encrypt and Store the Password -------------------------

    let password = "MySuperSecurePassword@2024";

    let key_version = "v1";
    let public_key_path = format!("keys/public_key_{}.pem", key_version);
    let public_key = load_public_key(&public_key_path)?;

    let criteria = PasswordCriteria::default();

    let encrypted_data = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria, key_version)?;

    println!("Encrypted and hashed password to store in the database:");
    println!("{}", encrypted_data);

    // --------------------- 2. Decrypt and Verify the Password ---------------------

    let user_input_password = "MySuperSecurePassword@2024";

    let private_key_path = format!("keys/private_key_{}.pem", key_version);
    let private_key = load_private_key(&private_key_path)?;

    match decrypt_and_verify_password(&encrypted_data, user_input_password, "keys") {
        Ok(_) => println!("Password is correct."),
        Err(e) => println!("The password is incorrect or an error occurred: {:?}", e),
    }

    Ok(())
}
```

### Steps:

1. **Encrypting and Storing the Password:**

   - The password is hashed using **Argon2** and encrypted with **AES-256-GCM**.
   - The symmetric key used for encryption is encrypted with an **RSA public key**.
   - The result is serialized into **JSON** and encoded in **base64**, ready to be stored in the database.

2. **Decrypting and Verifying the Password:**

   - The stored data is decrypted using the **RSA private key**, and the password is compared to the decrypted hash.

## Error Handling

IronCrypt utilizes an enumeration `IronCryptError` to consistently and informatively handle various errors that may occur. Below are some common errors and their example messages:

| Error | Example Messages |
| --- | --- |
| **Key Generation Error** | `Error generating the private key: Detailed error message` |
| **Key Loading Error** | `Error reading the public key: Detailed error message`<br>`Error loading the private key: Detailed error message` |
| **Key Saving Error** | `Error converting the private key: Detailed error message`<br>`Error writing the public key: Detailed error message` |
| **Hashing Error** | `Error hashing: Detailed error message` |
| **Encryption/Decryption Error** | `Encryption error: Detailed error message`<br>`Decryption error: Detailed error message` |
| **IO Error** | `I/O error: Detailed error message` |
| **UTF-8 Conversion Error** | `UTF-8 conversion error: Detailed error message` |
| **Invalid Password** | `Invalid password` |

**Notes:**

- **Protected RSA Private Key**: Ensure that private keys are stored securely and only accessible to authorized parties.
- **File Permissions**: Verify that the files containing RSA keys have appropriate permissions to prevent unauthorized access.

## Security and Best Practices

- **Key Storage**: Keep the private key secure and never share it publicly. The public key can be shared to encrypt data.
- **Robust Passwords**: Encourage the use of long and complex passwords to enhance security.
- **Custom Criteria**: Adapt `PasswordCriteria` according to the specific needs of your application to strengthen password requirements.
- **Error Management**: Carefully handle errors returned by functions to avoid disclosing sensitive information.
- **Secure Random Sources**: Use cryptographically secure random number sources, such as `OsRng`, for all operations requiring randomness.
- **Regular Updates**: Keep your dependencies up to date to benefit from the latest security improvements and bug fixes.

## Contribution

Contributions are welcome! To contribute to IronCrypt, follow these steps:

1. **Fork** the repository.
2. **Create a new branch** for your feature or bugfix.
3. **Commit** your changes with clear messages.
4. **Submit a Pull Request** detailing your modifications.

Ensure that your code adheres to Rust's best practices and passes all tests.

---

## License

`IronCrypt` is distributed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

**Final Notes:**

- **Unique Short Options Usage**: Each short option is unique within each command to avoid conflicts. For example, in the `decrypt` command, `-k` is used for `private_key_directory` and `-d` for `data`.
- **Mutual Exclusivity**: The `-d` (data) and `-f` (file) options in the `decrypt` command are mutually exclusive, preventing their simultaneous use.
- **Help Messages**: Use the `--help` option with each command to get detailed information about available options.

```bash
cargo run -- generate --help
cargo run -- encrypt --help
cargo run -- decrypt --help
```

This will help you better understand the various options and their usage.