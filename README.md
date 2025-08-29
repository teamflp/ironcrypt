# IronCrypt

- [IronCrypt](#ironcrypt)
  - [Features](#features)
  - [Workflows](#workflows)
    - [Password Encryption/Decryption](#password-encryptiondecryption)
    - [File Encryption/Decryption](#file-encryptiondecryption)
    - [Directory Encryption/Decryption](#directory-encryptiondecryption)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Command-Line Interface (CLI)](#command-line-interface-cli)
    - [As a Library (Crate)](#as-a-library-crate)
  - [Configuration](#configuration)
  - [Security Best Practices](#security-and-best-practices)
  - [Contribution](#contribution)
  - [License](#license)

**IronCrypt** is a Command-Line Interface (CLI) tool and Rust library dedicated to secure password and data encryption. By combining the **Argon2** hashing algorithm, **AES-256-GCM** or **XChaCha20-Poly1305** for symmetric encryption, and modern asymmetric cryptography like **RSA** or **Elliptic Curve Cryptography (ECC)**, IronCrypt provides a robust, flexible solution to ensure your application’s data confidentiality and password security.

---

## Features

- **Modern, Hybrid Encryption:** IronCrypt uses a robust hybrid encryption model. It encrypts data with a high-performance symmetric cipher (AES-256-GCM or XChaCha20-Poly1305) and protects the symmetric key using state-of-the-art asymmetric cryptography. This "envelope encryption" provides the best of both worlds: the speed of symmetric ciphers and the secure key management of public-key cryptography.
- **Flexible Asymmetric Cryptography:** Choose between **RSA** for broad compatibility or **Elliptic Curve Cryptography (ECC)** for higher performance and smaller key sizes, offering equivalent security with less overhead. Both are fully supported for encryption and digital signatures.
- **Multi-Recipient Encryption**: Natively supports encrypting a single file or directory for multiple users, even with different key types (e.g., some recipients using RSA, others ECC). Each user can decrypt the data with their own unique private key, without needing to share secrets.
- **Passphrase-Encrypted Keys**: Private keys can be optionally encrypted with a user-provided passphrase for an added layer of security, protecting them even if the key files are exposed.
- **State-of-the-Art Password Hashing:** For passwords, IronCrypt uses Argon2, currently considered one of the most secure hashing algorithms in the world. It is specifically designed to resist modern GPU-based brute-force attacks, providing much greater security than older algorithms.
- **Advanced Key Management:** The built-in key versioning system (`-v v1`, `-v v2`) and the dedicated `rotate-key` command allow you to update your encryption keys over time. This automates the process of migrating to a new key without having to manually decrypt and re-encrypt all your data. IronCrypt can load both modern PKCS#8 keys and legacy PKCS#1 keys, ensuring broad compatibility.
- **Flexible Configuration:** You can finely tune security parameters via the `ironcrypt.toml` file, environment variables, or the `IronCryptConfig` struct in code. This includes RSA key size and the computational "costs" of the Argon2 algorithm, allowing you to balance security and performance to fit your needs.
- **Streaming Encryption:** For file and directory operations, IronCrypt uses a streaming approach. This means it can encrypt and decrypt very large files without loading them entirely into memory, making it highly efficient for any file size.
- **Comprehensive Data Encryption:** IronCrypt is built to handle more than just passwords. It can encrypt any file (images, PDFs, documents), entire directories (by archiving them first), or any other data that can be represented as a stream of bytes.
- **Dual Use (CLI and Library):** IronCrypt is designed from the ground up to be dual-purpose. You can use it as a quick command-line tool for simple tasks, or integrate it as a library (crate) directly into your own Rust applications for more complex logic.

---

## Workflows

### Password Encryption/Decryption
![workflow-password.png](images/workflow-password.png)

This process ensures maximum security by combining robust hashing with **Argon2** and hybrid encryption (called "envelope encryption") with **AES** and **RSA**.

---

### **1. Encryption Process (e.g., during user registration)**

The goal here is not to encrypt the password itself, but to encrypt a **unique fingerprint** (a "hash") of that password. The plaintext password is never stored.

1.  **Password Hashing**:
    *   The password provided by the user (e.g., `"MyPassword123"`) is first passed through the **Argon2** hashing algorithm.
    *   Argon2 transforms it into a unique and non-reversible digital fingerprint (the "hash"). This algorithm is designed to be slow and memory-intensive, making it extremely resistant to modern brute-force attacks.

2.  **Creating the Encryption Envelope**:
    *   A new **AES-256** symmetric encryption key is randomly generated. This key is for one-time use and will only be used for this operation.
    *   The Argon2 hash (created in step 1) is then encrypted using this AES key.

3.  **Securing the AES Key (the "seal" of the envelope)**:
    *   To be able to verify the password later, the AES key must be saved. Storing it in plaintext would be a security flaw.
    *   Therefore, the AES key is itself encrypted, but this time with your **public RSA key**. Only the holder of the corresponding private RSA key will be able to decrypt this AES key.

4.  **Storing the Secure Data**:
    *   The final result is a structured JSON object that contains all the necessary information for future verification:
        *   The **hash encrypted** by AES.
        *   The **AES key encrypted** by RSA.
        *   The technical (public) parameters used for hashing and encryption (like the "salt" and "nonce").
        *   The version of the RSA key used for the seal.
    *   It is this JSON object that is securely stored in your database.

---

### **2. Verification Process (e.g., during user login)**

The goal here is to verify if the password provided by the user matches the stored one, **without ever having to see it in plaintext**.

1.  **Data Retrieval**:
    *   The user logs in by providing their password (e.g., `"MyPassword123"`).
    *   You retrieve the corresponding JSON object for this user from your database.

2.  **Opening the Envelope**:
    *   Using your **private RSA key**, you decrypt the AES key contained in the JSON.
    *   Once the plaintext AES key is obtained, you use it to decrypt the original Argon2 hash.

3.  **Real-time Hashing and Comparison**:
    *   The password just provided by the user for login is hashed in turn, using the exact same parameters (the "salt") as those stored in the JSON.
    *   The two hashes—the one just generated and the one decrypted from the database—are compared.

4.  **Verification Result**:
    *   **If the two hashes are identical**, it proves that the provided password is correct. Access is granted.
    *   **If they are different**, the password is incorrect. Access is denied.

This workflow ensures that even if your database were compromised, the users' passwords would remain unusable by an attacker, as the original password is never stored there.

### File Encryption/Decryption

![img.png](images/img-1.png)

This process also uses envelope encryption (AES + RSA) to ensure both performance and security.

#### **1. Encryption Process**

1.  **Opening File Streams**: IronCrypt opens the input file for reading and the output file for writing, without loading the entire content into memory.
2.  **Creating the Envelope Header**:
    *   A new one-time use **AES-256** key is randomly generated.
    *   This AES key is encrypted with one or more **public RSA keys** (one for each recipient).
    *   A JSON header is created containing a list of recipients, where each entry contains the encrypted AES key for that user and their key version.
3.  **Streaming Encryption**:
    *   The JSON header is written to the start of the output file.
    *   IronCrypt then reads the input file in small chunks, encrypts each chunk with the AES key, and immediately writes the encrypted chunk to the output file.
4.  **Finalizing**: Once the entire file has been processed, an authentication tag is appended to the end of the output file to ensure its integrity.

#### **2. Decryption Process**

1.  **Reading the Header**: IronCrypt reads the JSON header from the start of the encrypted file.
2.  **Opening the Envelope**:
    *   Your **private RSA key** is used to find your entry in the recipients list and decrypt the AES key.
3.  **Streaming Decryption**:
    *   With the AES key, IronCrypt reads the rest of the encrypted file in chunks, decrypts each chunk, and writes the plaintext data to the output file.
4.  **Verification and Saving**: After processing all chunks, it verifies the authentication tag. If valid, the original file is fully restored.

### Directory Encryption/Decryption

![img.png](images/workflow-directory.png)

Encrypting an entire directory is based on the file encryption workflow, with an additional preparation step.

#### **1. Encryption Process**

1.  **Archiving and Compression**:
    *   The target directory is first read, and all its files and subdirectories are compressed into a single `.tar.gz` archive, which is written to a temporary file on disk.
2.  **Encrypting the archive**:
    *   This temporary `.tar.gz` archive is then encrypted using the **streaming file encryption** process described above.
3.  **Storage**: The resulting JSON is saved to a single encrypted file.

#### **2. Decryption Process**

1.  **Decrypting the archive**:
    *   The **file decryption** process is used to retrieve the plaintext `.tar.gz` archive.
2.  **Decompression and Extraction**:
    *   The `.tar.gz` archive is then decompressed, and its contents are extracted to the destination directory, thus recreating the original structure and files.

---

## Installation

### Prerequisites

- **Rust** (latest stable version recommended)
- **Cargo** (Rust's package manager)

### Building and Running from Source

There are three main ways to run the `ironcrypt` command-line tool.

#### 1. Using `cargo run` (Recommended for development)
This command compiles and runs the program in one step. Use `--` to separate `cargo`'s arguments from your program's arguments.
```sh
# Clone the repository
git clone https://github.com/teamflp/ironcrypt.git
cd ironcrypt

# Run the --help command
cargo run -- --help
```

#### 2. Building and running the executable directly
You can build the executable and then run it from its path in the `target` directory.
```sh
# Build the optimized release executable
cargo build --release

# Run it from its path
./target/release/ironcrypt --help
```

#### 3. Installing the binary (Recommended for usage)
This will install the `ironcrypt` command on your system, making it available from any directory. This is the best option for regular use.
```sh
# From the root of the project directory, run:
cargo install --path .

# Now you can use the command from anywhere
ironcrypt --help
```

#### 4. Building a static Linux binary (MUSL)
Build portable static binaries (no glibc required), useful for minimal containers and Alpine.

Prerequisites (choose your OS):

- Debian/Ubuntu:
```sh
sudo apt-get update && sudo apt-get install -y musl-tools lld
rustup target add x86_64-unknown-linux-musl
```

- macOS (Homebrew):
```sh
brew install FiloSottile/musl-cross/musl-cross
rustup target add x86_64-unknown-linux-musl
```

Build the release binaries:
```sh
cargo build --locked --release --target x86_64-unknown-linux-musl
# Binaries:
#   target/x86_64-unknown-linux-musl/release/ironcrypt
#   target/x86_64-unknown-linux-musl/release/ironcryptd
```

Note: The repo’s .cargo/config.toml is already configured for MUSL (musl-gcc + lld). If you see “musl-gcc not found”, install musl-tools (Linux) or musl-cross (macOS) as above.

#### 5. Build and run with Docker
A multi-stage Dockerfile builds static binaries and ships a tiny runtime image.

Build the image:
```sh
docker build -t ironcrypt:latest .
```

Run the CLI inside the container:
```sh
docker run --rm ironcrypt:latest --help
```

Run the daemon (exposes port 3000, mounts host keys directory):
```sh
# Generate or place your keys in ./keys first
# Note: the daemon currently binds to 127.0.0.1 inside the container.
# It will be reachable from inside the container. To reach it from the host,
# bind the server to 0.0.0.0 in code or use an alternative networking setup.
docker run --rm -p 3000:3000 -v "$PWD/keys:/keys" ironcrypt:latest \
  ironcryptd -v v1 -d /keys -p 3000
```

#### 6. Using the Makefile (Docker Compose)
The project's Makefile provides shortcuts to manage Docker Compose from the terminal.

Prerequisites:
- Docker and Docker Compose v2 (`docker compose` command).

Common Commands:
```sh
# Help and list of targets
make help

# Start in development mode (uses .env by default)
make dev

# Start in production mode (uses .env.prod)
make prod

# Build images without starting
make build

# Follow logs
make logs

# Stop containers
make stop

# Clean (containers, volumes, orphans) + prune Docker [destructive]
make clean

# Run tests in the ironcrypt service
make test

# Generate coverage with tarpaulin
make coverage
```

Notes:
- You can change the environment file used by `dev` with `ENV_FILE`, e.g.:
```sh
make dev ENV_FILE=.env.local
```
- The default target is `all -> dev`, so a simple `make` is equivalent to `make dev`.

### Optimized Builds with Feature Flags

For advanced use cases, such as creating minimal binaries for embedded systems or lean Docker containers for specific cloud environments, IronCrypt supports a feature flag system. This allows you to compile only the components you need, significantly reducing binary size and dependencies.

By default, all features are enabled. To create a custom build, you must first disable the default features with `--no-default-features` and then enable the ones you need with `--features <your-features>`.

**Available Features:**

*   `cli`: Builds the `ironcrypt` command-line tool.
*   `daemon`: Builds the `ironcryptd` daemon and enables the `daemon` subcommand in the CLI.
*   `interactive`: Enables interactive elements like progress spinners in the CLI. Requires `cli`.
*   `aws`: Enables support for AWS Secrets Manager.
*   `azure`: Enables support for Azure Key Vault.
*   `gcp`: Enables support for Google Cloud Secret Manager. (Note: Currently non-functional, will result in an error at runtime).
*   `vault`: Enables support for HashiCorp Vault.
*   `cloud`: A meta-feature that enables all cloud providers (`aws`, `azure`, `gcp`, `vault`).
*   `full`: A meta-feature that enables all of the above features. This is the default.

**Local Builds with `cargo`:**

```sh
# Build a minimal CLI binary without any cloud or daemon features
cargo build --release --no-default-features --features cli

# Build the CLI with AWS support and interactive spinners
cargo build --release --no-default-features --features "cli,interactive,aws"

# Build just the daemon with all cloud providers
cargo build --release --no-default-features --features "daemon,cloud"
```

**Custom Docker Builds:**

You can pass the features to the Docker build using the `IRONCRYPT_FEATURES` build argument.

```sh
# Build a minimal Docker image with only the CLI tool
docker build --build-arg IRONCRYPT_FEATURES="cli" -t ironcrypt:cli .

# Build a Docker image with the daemon and Azure support
docker build --build-arg IRONCRYPT_FEATURES="daemon,azure" -t ironcrypt:daemon-azure .
```

---

## Usage

### Command-Line Interface (CLI)


Here is a summary table of all available commands:

| Command       | Alias                  | Description                                 | Key Options                                                                                                                                               |
| :------------ | :--------------------- | :------------------------------------------ | :-------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `generate`    |                        | Generates a new RSA key pair.               | `-v, --version <VERSION>` <br> `-d, --directory <DIR>` <br> `-s, --key-size <SIZE>` <br> `[--passphrase <PASSPHRASE>]`                                        |
| `encrypt`     |                        | Hashes and encrypts a password.             | `-w, --password <PASSWORD>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>`                                                      |
| `decrypt`     |                        | Verifies an encrypted password.             | `-w, --password <PASSWORD>` <br> `-k, --private-key-directory <DIR>` <br> `-f, --file <FILE>` <br> `[--passphrase <PASSPHRASE>]`                               |
| `encrypt-file`| `encfile`, `efile`, `ef` | Encrypts a binary file.                     | `-i, --input-file <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>...` <br> `[-w, --password <PASSWORD>]` |
| `decrypt-file`| `decfile`, `dfile`, `df` | Decrypts a binary file.                     | `-i, --input-file <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-k, --private-key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[-w, --password <PASSWORD>]` <br> `[--passphrase <PASSPHRASE>]` |
| `encrypt-dir` | `encdir`                 | Encrypts an entire directory.               | `-i, --input-dir <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>...` <br> `[-w, --password <PASSWORD>]` |
| `decrypt-dir` | `decdir`                 | Decrypts an entire directory.               | `-i, --input-file <INPUT>` <br> `-o, --output-dir <OUTPUT>` <br> `-k, --private-key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[-w, --password <PASSWORD>]` <br> `[--passphrase <PASSPHRASE>]` |
| `rotate-key`  | `rk`                     | Rotates encryption keys for encrypted data. | `--old-version <OLD_V>` <br> `--new-version <NEW_V>` <br> `-k, --key-directory <DIR>` <br> `[--file <FILE> | --directory <DIR>]` <br> `[--passphrase <PASSPHRASE>]` |

A full list of commands and their arguments can be viewed by running `ironcrypt --help`. To get help for a specific command, run `ironcrypt <command> --help`.

#### `generate`
Generates a new RSA key pair (private and public).

**Usage:**
```sh
ironcrypt generate --version <VERSION> [--directory <DIR>] [--key-size <SIZE>] [--passphrase <PASSPHRASE>]
```

**Example:**
```sh
# Generate a new v2 key with a size of 4096 bits in the "my_keys" directory
ironcrypt generate -v v2 -d my_keys -s 4096

# Generate a new v3 key protected by a passphrase
ironcrypt generate -v v3 -d my_keys --passphrase "a-very-secret-phrase"
```

#### `encrypt`
Hashes and encrypts a password.

**Usage:**
```sh
ironcrypt encrypt --password <PASSWORD> --public-key-directory <DIR> --key-version <VERSION>
```

**Example:**
```sh
# Encrypt a password using the v1 public key
ironcrypt encrypt -w "My$trongP@ssw0rd" -d keys -v v1
```

#### `decrypt`
Decrypts and verifies a password.

**Usage:**
```sh
ironcrypt decrypt --password <PASSWORD> --private-key-directory <DIR> --file <FILE> [--passphrase <PASSPHRASE>]
```

**Example:**
```sh
# Verify a password using the v1 private key and the encrypted data from a file
ironcrypt decrypt -w "My$trongP@ssw0rd" -k keys -f encrypted_data.json

# Verify using a key protected by a passphrase
ironcrypt decrypt -w "My$trongP@ssw0rd" -k my_keys -f encrypted_data_v3.json --passphrase "a-very-secret-phrase"
```

#### `encrypt-file`
Encrypts a single file.

**Usage:**
```sh
ironcrypt encrypt-file -i <INPUT> -o <OUTPUT> -d <KEY_DIR> -v <VERSION>... [-w <PASSWORD>]
```

**Example:**
```sh
# Encrypt a file for a single user (v1)
ironcrypt encrypt-file -i my_document.pdf -o my_document.enc -d keys -v v1

# Encrypt a file for multiple users (v1 and v2)
ironcrypt encrypt-file -i my_document.pdf -o my_document.multirecipient.enc -d keys -v v1 -v v2
```

#### `decrypt-file`
Decrypts a single file.

**Usage:**
```sh
ironcrypt decrypt-file -i <INPUT> -o <OUTPUT> -k <KEY_DIR> -v <VERSION> [-w <PASSWORD>] [--passphrase <PASSPHRASE>]
```

**Example:**
```sh
# Decrypt a file with the v1 private key
ironcrypt decrypt-file -i my_document.enc -o my_document.pdf -k keys -v v1

# Decrypt a file using a key protected by a passphrase
ironcrypt decrypt-file -i my_secret.enc -o my_secret.zip -k my_keys -v v3 -w "ExtraL@yerOfS3curity" --passphrase "a-very-secret-phrase"
```

#### `encrypt-dir`
Encrypts an entire directory by first archiving it into a `.tar.gz`.

**Usage:**
```sh
ironcrypt encrypt-dir -i <INPUT_DIR> -o <OUTPUT_FILE> -d <KEY_DIR> -v <VERSION>... [-w <PASSWORD>]
```

**Example:**
```sh
# Encrypt the "my_project" directory for multiple users
ironcrypt encrypt-dir -i ./my_project -o my_project.enc -d keys -v v1 -v v2
```

#### `decrypt-dir`
Decrypts and extracts a directory.

**Usage:**
```sh
ironcrypt decrypt-dir -i <INPUT_FILE> -o <OUTPUT_DIR> -k <KEY_DIR> -v <VERSION> [-w <PASSWORD>] [--passphrase <PASSPHRASE>]
```

**Example:**
```sh
# Decrypt the "my_project.enc" file into the "decrypted_project" directory
ironcrypt decrypt-dir -i my_project.enc -o ./decrypted_project -k keys -v v1
```

#### `rotate-key`
Rotates encryption keys for a file or a directory of files.

**Usage:**
```sh
ironcrypt rotate-key --old-version <OLD_V> --new-version <NEW_V> --key-directory <DIR> [--file <FILE> | --directory <DIR>] [--passphrase <PASSPHRASE>]
```

**Example:**
```sh
# Rotate keys from v1 to v2 for a single file
ironcrypt rotate-key --old-version v1 --new-version v2 -k keys --file my_document.enc
```

### As a Library (Crate)

You can also use `ironcrypt` as a library in your Rust projects. Add it to your `Cargo.toml`:
```toml
[dependencies]
ironcrypt = "0.2.0" # Replace with the desired version from crates.io
```

#### Encrypting and Verifying a Password
```rust
use ironcrypt::{IronCrypt, IronCryptConfig, DataType, config::KeyManagementConfig};
use std::collections::HashMap;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Use a temporary directory for keys to keep tests isolated.
    let temp_dir = tempfile::tempdir()?;
    let key_dir = temp_dir.path().to_str().unwrap();

    // 2. Configure IronCrypt to use the temporary directory.
    let mut config = IronCryptConfig::default();
    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config.data_type_config = Some(data_type_config);

    // 3. Initialize IronCrypt.
    let crypt = IronCrypt::new(config, DataType::Generic).await?;

    // 4. Encrypt a password.
    let password = "MySecurePassword123!";
    let encrypted_json = crypt.encrypt_password(password)?;
    println!("Encrypted password: {}", encrypted_json);

    // 5. Verify the password.
    let is_valid = crypt.verify_password(&encrypted_json, password)?;
    assert!(is_valid);
    println!("Password verification successful!");

    Ok(())
}
```

#### Encrypting and Decrypting a File (Streaming)
```rust
use ironcrypt::{encrypt_stream, decrypt_stream, generate_rsa_keys, PasswordCriteria, Argon2Config};
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate an RSA key pair (in a real application, load them from a file).
    let (private_key, public_key) = generate_rsa_keys(2048)?;

    // 2. Prepare the source and destination streams.
    let original_data = "This is a secret message that will be streamed for encryption.";
    let mut source = Cursor::new(original_data.as_bytes());
    let mut encrypted_dest = Cursor::new(Vec::new());

    // 3. Encrypt the stream for a single recipient.
    let mut password = "AnotherStrongPassword123!".to_string();
    let recipients = vec![(&public_key, "v1")];
    encrypt_stream(
        &mut source,
        &mut encrypted_dest,
        &mut password,
        recipients,
        &PasswordCriteria::default(),
        Argon2Config::default(),
        true, // Indicates that the password should be hashed
    )?;

    // 4. Go back to the beginning of the encrypted stream to read it.
    encrypted_dest.set_position(0);

    // 5. Decrypt the stream.
    let mut decrypted_dest = Cursor::new(Vec::new());
    decrypt_stream(
        &mut encrypted_dest,
        &mut decrypted_dest,
        &private_key,
        "v1", // The key version of the recipient
        "AnotherStrongPassword123!",
    )?;

    // 6. Verify that the decrypted data matches the original data.
    let decrypted_data = String::from_utf8(decrypted_dest.into_inner())?;
    assert_eq!(original_data, decrypted_data);
    println!("Stream encryption and decryption successful!");

    Ok(())
}
```

### Transparent Encryption Daemon

For seamless integration with applications written in any language, IronCrypt provides a daemon that exposes a simple, high-performance HTTP API for encryption and decryption. This allows you to run IronCrypt as a background service and have your other applications communicate with it locally, without needing to integrate the Rust library directly.

#### Daemon Configuration

The `ironcryptd` daemon is configured using a central TOML file (e.g., `ironcrypt.toml`). This approach is used to ensure that all instances in a high-availability cluster share the same settings.

**Example `ironcrypt.toml`:**
```toml
# The cryptographic standard to use.
# Options: "nist", "fips_140_2", "custom"
standard = "nist"

# The size of the buffer to use for streaming operations (in bytes).
buffer_size = 8192

# Configuration for the Argon2 password hashing algorithm.
argon2_memory_cost = 65536
argon2_time_cost = 3
argon2_parallelism = 1

# Optional: Configuration for auditing.
[audit]
# Path to the directory where audit logs will be stored.
log_path = "/var/log/ironcrypt"
# Optional: Path to a private key to sign the audit logs.
# signing_key_path = "/path/to/audit_signing_key.pem"
```

A full example configuration file can be found at `ironcrypt.toml.example`.

#### Starting the Daemon

You start the daemon by pointing it to your configuration file and providing the necessary runtime arguments.

```sh
# Start the daemon using a config file, specifying the key version and API key file
ironcryptd --config /path/to/ironcrypt.toml \
           --key-version v1 \
           --api-keys-file /path/to/keys.json \
           --port 3000
```

The daemon will run in the foreground. For production use, you should run it as a system service (e.g., using `systemd`).

#### Daemon Authentication

To secure the daemon and control access, IronCrypt uses an API key system with granular permissions. This ensures that only authorized clients can perform encryption and decryption operations.

**1. Generate an API Key**

First, generate a new secret key and its corresponding hash using the `generate-api-key` command:

```sh
ironcrypt generate-api-key
```

The output will give you two crucial pieces of information:
*   **Secret API Key:** The secret key that your client applications will use. **Treat this like a password.**
*   **API Key Hash:** A secure hash of the key that you will use to configure the daemon.

**2. Create a Key Configuration File**

Next, create a JSON file (e.g., `keys.json`) to define your keys and their permissions. The daemon will load this file at startup. Use the hash from the previous step.

*Example `keys.json`:*
```json
[
  {
    "description": "Backup service key (encrypt-only)",
    "keyHash": "hash_from_generate_api_key_command",
    "permissions": ["encrypt"]
  },
  {
    "description": "Admin key (full access)",
    "keyHash": "hash_of_another_key",
    "permissions": ["encrypt", "decrypt"]
  }
]
```
A template file named `keys.json.example` is available in the repository.

**3. Start the Daemon with Authentication**

Launch the daemon, pointing it to your key configuration file using the `--api-keys-file` argument.

```sh
ironcrypt daemon --key-version v1 --api-keys-file /path/to/your/keys.json
```

The daemon is now secured.

**4. Make an Authenticated Request**

Client applications must include the **secret API key** in the `Authorization` header as a Bearer token.

*Example with `curl`:*
```sh
# Encrypt data using a key that has the "encrypt" permission
curl --request POST \
  --header "Authorization: Bearer YOUR_SECRET_API_KEY" \
  --data "my secret data" \
  http://localhost:3000/encrypt > encrypted.bin

# Decrypt data using a key that has the "decrypt" permission
cat encrypted.bin | curl --request POST \
  --header "Authorization: Bearer YOUR_SECRET_API_KEY" \
  --data-binary @- \
  http://localhost:3000/decrypt
```

If the key is missing, invalid, or does not have the required permission, the daemon will return an appropriate HTTP error (`401 Unauthorized` or `403 Forbidden`).

#### API Endpoints

The daemon exposes two streaming endpoints:

*   `POST /encrypt`: Encrypts a stream of data.
*   `POST /decrypt`: Decrypts a stream of data.

You can optionally provide a password for Argon2id hashing in the `X-Password` HTTP header.

#### `curl` Examples

**Encrypting Data:**

Pipe any data to the `/encrypt` endpoint. The raw, encrypted data will be returned in the response body.

```sh
# Encrypt the string "my secret data"
echo "my secret data" | curl --request POST --data-binary @- http://localhost:3000/encrypt > encrypted.bin

# Encrypt a file
cat my_document.pdf | curl --request POST --data-binary @- http://localhost:3000/encrypt > my_document.enc

# Encrypt with an additional password
echo "my secret data" | curl --request POST -H "X-Password: MyStrongPassword" --data-binary @- http://localhost:3000/encrypt > encrypted_with_pass.bin
```

**Decrypting Data:**

Pipe the encrypted data to the `/decrypt` endpoint. The original plaintext data will be returned.

```sh
# Decrypt the data from the first example
cat encrypted.bin | curl --request POST --data-binary @- http://localhost:3000/decrypt

# Decrypt a file
cat my_document.enc | curl --request POST --data-binary @- http://localhost:3000/decrypt > decrypted_document.pdf

# Decrypt data that was encrypted with a password
cat encrypted_with_pass.bin | curl --request POST -H "X-Password: MyStrongPassword" --data-binary @- http://localhost:3000/decrypt
```

### High Availability

The `ironcryptd` daemon is designed to be stateless, meaning it does not store any session or request-specific data between requests. This architecture makes it horizontally scalable and highly available. You can run multiple instances of the daemon behind a load balancer to distribute traffic and ensure service continuity even if one of the instances fails.

**Key Requirements for a High-Availability Setup:**

1.  **Shared Configuration:** All `ironcryptd` instances must be started with the same configuration. This is best achieved by using a centralized `ironcrypt.toml` configuration file for all instances.
2.  **Shared Key Storage:** All instances must have access to the same set of encryption keys. This can be achieved by:
    *   Placing the key directory on a shared network file system (e.g., NFS, GlusterFS).
    *   Using a configuration management tool (e.g., Ansible, Puppet) to deploy the same key files to each node.
3.  **Centralized Logging:** To monitor and audit the cluster, the logs from all instances (both standard and audit logs) should be forwarded to a centralized logging system (e.g., ELK Stack, Splunk, Graylog).

**Example: Load Balancing with Nginx**

Here is a sample Nginx configuration that demonstrates how to load balance traffic between two `ironcryptd` instances running on `localhost` at ports 3000 and 3001.

```nginx
# /etc/nginx/nginx.conf

http {
    # Define a group of upstream servers
    upstream ironcryptd_cluster {
        # Use a load balancing algorithm, e.g., round-robin (default) or least_conn
        # least_conn;

        server 127.0.0.1:3000;
        server 127.0.0.1:3001;
    }

    server {
        listen 80;

        location / {
            # Forward requests to the upstream cluster
            proxy_pass http://ironcryptd_cluster;

            # Set headers to pass client information to the daemon
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

With this configuration, Nginx will listen on port 80 and distribute incoming requests for `/encrypt` and `/decrypt` between the two daemon instances, providing both load balancing and redundancy.

---

## Database Integration Examples

Here are some examples of how to use `ironcrypt` with popular web frameworks and a PostgreSQL database. These examples use the `sqlx` crate for database interaction.

### Actix-web Example

This example shows how to create a simple web service with `actix-web` that can register and log in users.

**Dependencies:**
```toml
[dependencies]
ironcrypt = "0.2.0"
actix-web = "4"
sqlx = { version = "0.7", features = ["runtime-async-std-native-tls", "postgres"] }
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
```

**Code:**
```rust
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use ironcrypt::{IronCrypt, IronCryptConfig, DataType};
use serde::Deserialize;

#[derive(Deserialize)]
struct User {
    username: String,
    password: String,
}

async fn register(user: web::Json<User>, pool: web::Data<PgPool>, crypt: web::Data<IronCrypt>) -> impl Responder {
    let encrypted_password = match crypt.encrypt_password(&user.password) {
        Ok(p) => p,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let result = sqlx::query("INSERT INTO users (username, password) VALUES ($1, $2)")
        .bind(&user.username)
        .bind(&encrypted_password)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("User created"),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

async fn login(user: web::Json<User>, pool: web::Data<PgPool>, crypt: web::Data<IronCrypt>) -> impl Responder {
    let result: Result<(String,), sqlx::Error> = sqlx::query_as("SELECT password FROM users WHERE username = $1")
        .bind(&user.username)
        .fetch_one(pool.get_ref())
        .await;

    let stored_password = match result {
        Ok((p,)) => p,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    match crypt.verify_password(&stored_password, &user.password) {
        Ok(true) => HttpResponse::Ok().body("Login successful"),
        Ok(false) => HttpResponse::Unauthorized().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database_url = "postgres://user:password@localhost/database";
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool.");

    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(config, DataType::Generic).await.expect("Failed to initialize IronCrypt");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )"
    )
    .execute(&pool)
    .await
    .expect("Failed to create table.");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(crypt.clone()))
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Rocket Example

This example shows how to achieve the same functionality using the `rocket` framework.

**Dependencies:**
```toml
[dependencies]
ironcrypt = "0.2.0"
rocket = { version = "0.5.0", features = ["json"] }
sqlx = { version = "0.7", features = ["runtime-tokio-native-tls", "postgres"] }
serde = { version = "1.0", features = ["derive"] }
```

**Code:**
```rust
#[macro_use] extern crate rocket;

use rocket::serde::json::Json;
use rocket::State;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use ironcrypt::{IronCrypt, IronCryptConfig, DataType};
use serde::Deserialize;

#[derive(Deserialize)]
struct User {
    username: String,
    password: String,
}

#[post("/register", data = "<user>")]
async fn register(user: Json<User>, pool: &State<PgPool>, crypt: &State<IronCrypt>) -> Result<String, rocket::response::status::Custom<String>> {
    let encrypted_password = crypt.encrypt_password(&user.password).map_err(|e| rocket::response::status::Custom(rocket::http::Status::InternalServerError, e.to_string()))?;

    sqlx::query("INSERT INTO users (username, password) VALUES ($1, $2)")
        .bind(&user.username)
        .bind(&encrypted_password)
        .execute(&**pool)
        .await
        .map_err(|e| rocket::response::status::Custom(rocket::http::Status::InternalServerError, e.to_string()))?;

    Ok("User created".to_string())
}

#[post("/login", data = "<user>")]
async fn login(user: Json<User>, pool: &State<PgPool>, crypt: &State<IronCrypt>) -> Result<String, rocket::response::status::Custom<String>> {
    let result: (String,) = sqlx::query_as("SELECT password FROM users WHERE username = $1")
        .bind(&user.username)
        .fetch_one(&**pool)
        .await
        .map_err(|_| rocket::response::status::Custom(rocket::http::Status::Unauthorized, "User not found".to_string()))?;

    let stored_password = result.0;

    if crypt.verify_password(&stored_password, &user.password).unwrap_or(false) {
        Ok("Login successful".to_string())
    } else {
        Err(rocket::response::status::Custom(rocket::http::Status::Unauthorized, "Invalid credentials".to_string()))
    }
}

#[launch]
async fn rocket() -> _ {
    let database_url = "postgres://user:password@localhost/database";
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool.");

    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(config, DataType::Generic).await.expect("Failed to initialize IronCrypt");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )"
    )
    .execute(&pool)
    .await
    .expect("Failed to create table.");

    rocket::build()
        .manage(pool)
        .manage(crypt)
        .mount("/", routes![register, login])
}
```

---

## Configuration

IronCrypt can be configured in three ways, in order of precedence:

1.  **`ironcrypt.toml` file:** Create this file in the directory where you run the command.
2.  **Environment Variables:** Set variables like `IRONCRYPT_KEY_DIRECTORY`.
3.  **Command-Line Arguments:** Flags like `--key-directory` override all other methods.

For library usage, you can construct an `IronCryptConfig` struct and pass it to `IronCrypt::new`.

### Cryptographic Algorithm Configuration

You can customize the cryptographic algorithms used by IronCrypt in your `ironcrypt.toml` file.

```toml
# Set a predefined standard for algorithms and key sizes.
# Options: "nist_p256", "nist_p384", "rsa_2048", "rsa_4096"
# If set, the specific algorithm settings below are ignored.
standard = "nist_p256"
```

Alternatively, you can specify a custom combination of algorithms:

```toml
standard = "custom"
# Symmetric algorithm for data encryption. Options: "aes_256_gcm", "chacha20_poly1305"
symmetric_algorithm = "chacha20_poly1305"
# Asymmetric algorithm for key encapsulation. Options: "rsa", "ecc"
asymmetric_algorithm = "ecc"
# RSA key size (in bits), only used if asymmetric_algorithm is "rsa".
rsa_key_size = 4096
```

Using **ECC (nist_p256)** is recommended for new applications due to its excellent performance and smaller key sizes compared to RSA.

### Secret Management Configuration

To use IronCrypt with a secret management system like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault, you need to enable the corresponding feature flag during compilation and configure it in your `ironcrypt.toml` file.

First, specify the provider you want to use:

```toml
[secrets]
provider = "vault" # or "aws", "azure"
```

Then, provide the specific configuration for your chosen provider.

#### HashiCorp Vault (`vault` feature)

```toml
[secrets.vault]
address = "http://127.0.0.1:8200" # Address of your Vault server
token = "YOUR_VAULT_TOKEN"        # Vault token with access to the secret engine
mount = "secret"                  # Mount path of the KVv2 secrets engine (optional, defaults to "secret")
```

---

## Security and Best Practices

- **Protect Your Private Keys:** Never expose your private keys. Store them in a secure, non-public location. If possible, encrypt them with a strong, unique passphrase using the `--passphrase` option during generation.
- **Use Strong Passwords:** When using the password feature for file/directory encryption, ensure the password is strong.
- **Rotate Keys Regularly:** Use the `rotate-key` command to update your encryption keys periodically.
- **Backup Your Keys:** Keep secure backups of your keys. If you lose a private key, you will not be able to decrypt your data.

---

## Contribution

Contributions are welcome! If you'd like to contribute, please follow these steps:

1.  **Fork** the repository on GitHub.
2.  **Create** a new branch for your feature or bug fix.
3.  **Commit** your changes and push them to your fork.
4.  **Submit** a pull request with a clear description of your changes.

---

## License

*IronCrypt is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.*