# IronCrypt

- [IronCrypt](#ironcrypt)
  - [Features](#features)
  - [Quick start](#quick-start)
  - [Using IronCrypt from PHP](#using-ironcrypt-from-php)
  - [Using IronCrypt via FFI (C ABI)](#using-ironcrypt-via-ffi-c-abi)
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
- **Streaming Encryption:** For **AES-256-GCM without signatures**, IronCrypt encrypts and decrypts in chunks without loading the whole file into memory. **Limits:** (1) **XChaCha20-Poly1305** is one-shot (plaintext is buffered); (2) a **signature** in the header also requires pre-buffering the content for hashing. Prefer unsigned AES for very large files.
- **Comprehensive Data Encryption:** IronCrypt is built to handle more than just passwords. It can encrypt any file (images, PDFs, documents), entire directories (by archiving them first), or any other data that can be represented as a stream of bytes.
- **Dual Use (CLI and Library):** IronCrypt is designed from the ground up to be dual-purpose. You can use it as a quick command-line tool for simple tasks, or integrate it as a library (crate) directly into your own Rust applications for more complex logic.

---

## Quick start

Copy-paste examples aligned with the current code.

### 1. Prepare a local lab

```sh
git clone https://github.com/teamflp/ironcrypt.git
cd ironcrypt

cargo build --release --features full

# Copy example fixtures (never commit real keys)
make bootstrap-lab
# → keys.json, ironcrypt.toml, keys/private_key_v1.pem, keys/public_key_v1.pem
```

### 2. CLI — keys, file, password

```sh
./target/release/ironcrypt generate -v v1 -d keys -s 2048

./target/release/ironcrypt encrypt-file \
  -i report.pdf -o report.enc -d keys -v v1

./target/release/ironcrypt decrypt-file \
  -i report.enc -o report.out.pdf -k keys -v v1

# Password (Argon2id hash sealed in JSON — never stored in cleartext)
./target/release/ironcrypt encrypt -w 'Str0ngP@ssw0rd42!' -d keys -v v1 > secret.json
./target/release/ironcrypt decrypt -w 'Str0ngP@ssw0rd42!' -k keys -f secret.json
```

### 3. HTTP daemon (`ironcryptd`)

API permissions: `read`, `write`, `delete`, `update`, `full`.  
Endpoints: **`POST /write`** (encrypt) and **`POST /read`** (decrypt).

```sh
./target/release/ironcrypt generate-api-key
# → note the secret API key (base64) and the Hash (SHA-512 hex)

# keys.json uses camelCase, e.g.:
# { "description": "lab", "keyHash": "<HASH_HEX>", "permissions": ["write", "read"] }

./target/release/ironcryptd \
  --host 127.0.0.1 --port 3000 \
  --key-directory keys --key-version v1 \
  --api-keys-file keys.json \
  --config ironcrypt.toml \
  --rate-limit-per-sec 20 --rate-limit-burst 40

export API_KEY='<SECRET_API_KEY_BASE64>'

echo 'hello ironcrypt' | curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --data-binary @- \
  http://127.0.0.1:3000/write > payload.enc

curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --data-binary @payload.enc \
  http://127.0.0.1:3000/read

# Optional Argon2 gate: -H "X-Password: Str0ngP@ssw0rd42!"
```

In-process HTTPS:

```sh
./target/release/ironcryptd \
  --host 0.0.0.0 --port 3443 \
  --tls-cert cert.pem --tls-key key.pem \
  --key-directory keys --key-version v1 \
  --api-keys-file keys.json --config ironcrypt.toml
```

### 4. Docker Compose (lab vs prod)

```sh
make bootstrap-lab
make lab    # Vault -dev + lab token (never for production)
# make prod
```

### 5. Rust library (AES streaming)

```rust
use ironcrypt::{
    algorithms::SymmetricAlgorithm,
    decrypt_stream, encrypt_stream, generate_rsa_keys,
    keys::{PrivateKey, PublicKey},
    Argon2Config, PasswordCriteria,
};
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sk, pk) = generate_rsa_keys(2048)?;
    let public_key = PublicKey::Rsa(pk);
    let private_key = PrivateKey::Rsa(sk);

    let original = b"secret streamed message";
    let mut src = Cursor::new(original.as_slice());
    let mut enc = Cursor::new(Vec::new());
    let mut password = String::new();

    encrypt_stream(
        &mut src,
        &mut enc,
        &mut password,
        [(&public_key, "v1")],
        None, // no signature → real AES streaming
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        SymmetricAlgorithm::Aes256Gcm,
    )?;

    enc.set_position(0);
    let mut out = Cursor::new(Vec::new());
    decrypt_stream(&mut enc, &mut out, &private_key, "v1", "", None)?;
    assert_eq!(out.into_inner(), original);
    Ok(())
}
```

---

## Using IronCrypt from PHP

PHP applications do **not** link the Rust crate. They talk to the **`ironcryptd` HTTP daemon** with the small client in [`sdks/php`](sdks/php/) (`IronCryptClient`).

```text
PHP app  --POST /write|/read + Bearer-->  ironcryptd  (holds PEM keys)
```

### Why this model?

- One crypto service shared by PHP, Python, curl, etc.
- API keys with fine-grained permissions (`write`, `read`, …)
- No need to ship private keys inside every PHP container

### Setup

```bash
# 1) Daemon (from repo root)
cargo build --release --features full && make bootstrap-lab
./target/release/ironcrypt generate-api-key   # secret (base64) + hash → keys.json
./target/release/ironcryptd \
  --host 127.0.0.1 --port 3000 \
  --key-directory keys --key-version v1 \
  --api-keys-file keys.json --config ironcrypt.toml

# 2) PHP SDK
cd sdks/php && composer install
```

`keys.json` must use camelCase (`keyHash`) and permissions such as `["write", "read"]`.  
Send the **secret** API key as `Authorization: Bearer …` **without** re-encoding it.

### Minimal PHP example

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';

use IronCrypt\Sdk\IronCryptClient;

$client = new IronCryptClient(getenv('IRONCRYPT_URL') ?: 'http://127.0.0.1:3000');
$apiKey = getenv('IRONCRYPT_API_KEY'); // base64 secret from generate-api-key

$ciphertext = $client->encrypt('sensitive payload', $apiKey); // POST /write
$plaintext  = $client->decrypt($ciphertext, $apiKey);        // POST /read

// Optional Argon2 gate:
// $client->encrypt($data, $apiKey, 'Str0ngP@ssw0rd42!');
```

Store ciphertext as a DB BLOB or `base64_encode($ciphertext)` for text columns.

Full walkthrough (Composer path repo, cURL without SDK, errors `401`/`403`/`429`, alternatives CLI/FFI): see **[`sdks/php/README.md`](sdks/php/README.md)**.  
Python HTTP client: [`sdks/python`](sdks/python/).

---

## Using IronCrypt via FFI (C ABI)

For **in-process** use (no HTTP daemon), link or load the dynamic library built by Cargo (`cdylib`) and call the C API declared in [`ironcrypt.h`](ironcrypt.h).

```text
Python / Java / C# / C / PHP-FFI  --native calls-->  libironcrypt (.so / .dylib / .dll)
```

### FFI vs daemon

| | **FFI (`libironcrypt`)** | **HTTP (`ironcryptd` + SDKs)** |
| --- | --- | --- |
| Process | Same process as your app | Separate service |
| Auth | You pass PEM material yourself | API key Bearer + permissions |
| Best for | Native apps, JVM/.NET, low latency | PHP/web, multi-language microservices |
| C API scope today | **Password** workflow (Argon2 + RSA envelope) | Files/streams via `/write` `/read`, secrets, … |

### Build the library

```bash
cargo build --release
# Linux:  target/release/libironcrypt.so
# macOS:  target/release/libironcrypt.dylib
# Windows: target/release/ironcrypt.dll
```

### API surface

| Function | Success | Role |
| --- | --- | --- |
| `ironcrypt_generate_rsa_keys` | `0` | Allocate PEM private/public strings |
| `ironcrypt_password_encrypt` | `0` | Password → sealed JSON |
| `ironcrypt_password_verify` | `1` / `0` / `-1` | Valid / invalid / error |
| `ironcrypt_free_string` | — | **Must** free every string Rust allocated |

### Minimal idea (Python ctypes)

```python
import ctypes
lib = ctypes.CDLL("target/release/libironcrypt.dylib")  # .so on Linux

lib.ironcrypt_generate_rsa_keys.restype = ctypes.c_int32
# … set argtypes, call encrypt/verify, then:
# lib.ironcrypt_free_string(ptr)
```

Native C sample: [`examples/c_api_usage.c`](examples/c_api_usage.c).  
Full examples (Python ctypes, Java JNA, C# P/Invoke, PHP `FFI`, build flags, troubleshooting): **[`FFI_EXAMPLES.md`](FFI_EXAMPLES.md)**.

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
        *   The **encrypted Argon2 hash** (AES ciphertext) — the hash is **never duplicated in cleartext** in the JSON.
        *   The **AES key encrypted** with RSA/ECC (envelope).
        *   Public technical parameters (nonce, key version, algorithm).
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

1.  **Opening File Streams**: IronCrypt opens the input file for reading and the output file for writing. In **AES-256-GCM without a signature**, content is processed in chunks (streaming). With **XChaCha20** or a **signature**, an in-memory buffer of the content is required (see Features).
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

- **Rust** ≥ **1.88** (MSRV for the default library build — see `rust-version` in `Cargo.toml`)
- Latest **stable** recommended for CLI / `full` / cloud features
- **Cargo** (Rust's package manager)

#### MSRV notes

| Feature set | Minimum rustc (approx.) | Notes |
|-------------|-------------------------|--------|
| default (library) | **1.88** | Guaranteed / CI-tested (`time` etc. in the lockfile) |
| `cli` / `daemon` / `full` (no AWS bump) | 1.88 | Same baseline |
| `aws` / current AWS SDK in the lockfile | **1.94.1+** | Upstream `aws-config` / Smithy crates declare this |

The CI job **MSRV 1.88** runs `cargo check/test --lib` on every push.

### Building and Running from Source

There are three main ways to run the `ironcrypt` command-line tool.

#### 1. Using `cargo run` (Recommended for development)
This command compiles and runs the program in one step. Use `--` to separate `cargo`'s arguments from your program's arguments.
```sh
# Clone the repository
git clone https://github.com/teamflp/ironcrypt.git
cd ironcrypt

# Run the --help command (CLI feature required)
cargo run --features cli -- --help
```

#### 2. Building and running the executable directly
You can build the executable and then run it from its path in the `target` directory.
```sh
# Build the optimized CLI (+ daemon) — defaults are library-only
cargo build --release --features full

# Run it from its path
./target/release/ironcrypt --help
```

#### 3. Installing the binary (Recommended for usage)
This will install the `ironcrypt` command on your system, making it available from any directory. This is the best option for regular use.
```sh
# From the root of the project directory, run:
cargo install --path . --features full
# Or from crates.io (once published):
# cargo install ironcrypt --features full

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

CI publishes images to GitHub Container Registry on every `master` push:
```sh
docker pull ghcr.io/teamflp/ironcrypt:latest
```

Build the image locally:
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
Shortcuts for lab / prod stacks.

Prerequisites: Docker and Docker Compose v2 (`docker compose`).

```sh
make help
make bootstrap-lab   # copy *.example → local files (no overwrite)
make lab             # alias: make dev — lab stack (Vault -dev)
make prod            # prod stack (no Vault root token)
make stop
make logs
make test
make coverage
```

Notes:
```sh
make lab ENV_FILE=.env.local
make prod PROD_ENV_FILE=.env.prod
```
Default target is `all -> lab`.

### Optimized Builds with Feature Flags

IronCrypt is **library-first** on crates.io: the default feature set is empty (crypto API only). Binaries and cloud backends are opt-in via features — this keeps consumer dependency trees lean.

**Available Features:**

*   *(default)*: library only — password / stream / RSA-ECC crypto API.
*   `cli`: Builds the `ironcrypt` CLI.
*   `daemon`: Builds `ironcryptd` and enables the `daemon` CLI subcommand.
*   `interactive`: Progress indicators in the CLI (requires `cli`).
*   `aws` / `azure` / `vault`: secret backends (`aws` currently needs rustc ≥ 1.94.1).
*   `gcp`: Google Secret Manager (**optional**, pulls `tonic` — outside `cloud` / `full`).
*   `hsm`: PKCS#11 backend.
*   `cloud`: `aws` + `azure` + `vault` (no `gcp`).
*   `full`: `cli` + `daemon` + `cloud` + `interactive` (batteries-included meta feature).

**As a library dependency:**

```toml
# Lean (recommended for apps)
ironcrypt = "0.1"

# With optional backends
ironcrypt = { version = "0.1", features = ["vault"] }
```

**Local Builds with `cargo`:**

```sh
# Library only (same as crates.io default)
cargo build --release

# Minimal CLI binary
cargo build --release --features cli

# CLI with AWS support and interactive spinners
cargo build --release --features "cli,interactive,aws"

# Daemon with cloud providers
cargo build --release --features "daemon,cloud"

# Everything except gcp/hsm
cargo build --release --features full
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
| `sign`        |                          | Creates a detached signature for a file.    | `-i, --input-file <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-k, --key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[--passphrase <PASSPHRASE>]` |
| `verify`      |                          | Verifies a detached signature for a file.   | `-i, --input-file <INPUT>` <br> `-s, --signature-file <SIG>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>`                  |

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

#### `sign`
Creates a detached signature for a file. This can be used to prove the file's authenticity and integrity.

**Usage:**
```sh
ironcrypt sign --input-file <INPUT> --output-file <OUTPUT> --key-directory <DIR> --key-version <VERSION> [--passphrase <PASSPHRASE>]
```

**Example:**
```sh
# Sign a document with a v1 private key
ironcrypt sign -i my_document.pdf -o my_document.sig -k keys -v v1

# Sign a file with a passphrase-protected ECC key
ironcrypt sign -i archive.zip -o archive.sig -k ecc_keys -v v1_ecc --passphrase "my-secret-phrase"
```

#### `verify`
Verifies a detached signature against a file. This confirms that the file has not been tampered with since it was signed by the holder of the corresponding private key.

**Usage:**
```sh
ironcrypt verify --input-file <INPUT> --signature-file <SIGNATURE> --public-key-directory <DIR> --key-version <VERSION>
```

**Example:**
```sh
# Verify the signature for my_document.pdf using the v1 public key
ironcrypt verify -i my_document.pdf -s my_document.sig -d keys -v v1
```

### As a Library (Crate)

You can also use `ironcrypt` as a library in your Rust projects. Add it to your `Cargo.toml`:
```toml
[dependencies]
ironcrypt = "0.1.1" # Replace with the desired version from crates.io
```

Runnable copies of the snippets below live in [`examples/`](examples/) (`cargo run --example password`, `cargo run --example stream_aes`). They are also checked by `cargo test --doc`.

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
use ironcrypt::{
    algorithms::SymmetricAlgorithm,
    decrypt_stream, encrypt_stream, generate_rsa_keys,
    keys::{PrivateKey, PublicKey},
    Argon2Config, PasswordCriteria,
};
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sk, pk) = generate_rsa_keys(2048)?;
    let public_key = PublicKey::Rsa(pk);
    let private_key = PrivateKey::Rsa(sk);

    let original_data = "This is a secret message that will be streamed for encryption.";
    let mut source = Cursor::new(original_data.as_bytes());
    let mut encrypted_dest = Cursor::new(Vec::new());
    let mut password = String::new();

    encrypt_stream(
        &mut source,
        &mut encrypted_dest,
        &mut password,
        [(&public_key, "v1")],
        None, // no signature → real AES streaming
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        SymmetricAlgorithm::Aes256Gcm,
    )?;

    encrypted_dest.set_position(0);
    let mut decrypted_dest = Cursor::new(Vec::new());
    decrypt_stream(
        &mut encrypted_dest,
        &mut decrypted_dest,
        &private_key,
        "v1",
        "",
        None,
    )?;

    assert_eq!(original_data, String::from_utf8(decrypted_dest.into_inner())?);
    Ok(())
}
```

### Transparent Encryption Daemon

For language-agnostic integration, `ironcryptd` exposes a streaming HTTP API.

#### Daemon Configuration

Config is a **flat** TOML matching `IronCryptConfig` (see `ironcrypt.toml.example`).

**Minimal `ironcrypt.toml`:**
```toml
standard = "Nist"
buffer_size = 8192
rsa_key_size = 2048
argon2_memory_cost = 65536
argon2_time_cost = 3
argon2_parallelism = 1

[password_criteria]
min_length = 12
```

#### Starting the Daemon

```sh
ironcryptd \
  --config ironcrypt.toml \
  --key-directory keys \
  --key-version v1 \
  --api-keys-file keys.json \
  --host 127.0.0.1 \
  --port 3000
```

Non-loopback HTTP requires TLS (`--tls-cert` / `--tls-key`) or `--allow-insecure-http`.

#### Daemon Authentication

**1. Generate an API key**

```sh
ironcrypt generate-api-key
```

You get:
* **Secret API key** (base64) — send as `Authorization: Bearer …`
* **Hash** (SHA-512 hex) — store in `keys.json` as `keyHash`

**2. `keys.json` (camelCase)**

```json
[
  {
    "description": "Backup service (write-only)",
    "keyHash": "HASH_HEX_FROM_GENERATE_API_KEY",
    "permissions": ["write"]
  },
  {
    "description": "Read/write service",
    "keyHash": "ANOTHER_HASH_HEX",
    "permissions": ["write", "read"]
  },
  {
    "description": "AWS secrets only",
    "keyHash": "YET_ANOTHER_HASH",
    "permissions": ["read", "write"],
    "allowedServices": ["aws"]
  }
]
```

Valid permissions: `write`, `read`, `delete`, `update`, `full`.  
Fixtures: `keys.json.example`, `private_key_v1.pem.example` / `public_key_v1.pem.example` (`make bootstrap-lab`).

**3. Authenticated requests**

```sh
export API_KEY='SECRET_API_KEY_BASE64'

echo "my secret data" | curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --data-binary @- \
  http://127.0.0.1:3000/write > encrypted.bin

curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --data-binary @encrypted.bin \
  http://127.0.0.1:3000/read

echo "secret" | curl -sS --request POST \
  --header "Authorization: Bearer ${API_KEY}" \
  --header "X-Password: Str0ngP@ssw0rd42!" \
  --data-binary @- \
  http://127.0.0.1:3000/write > encrypted_with_pass.bin
```

Typical errors: `401` (missing/invalid key), `403` (permission), `429` (rate limit), `400` (crypto / bad password).

#### API Endpoints

| Method | Path | Permission | Role |
| --- | --- | --- | --- |
| `POST` | `/write` | `write` | Encrypt request body |
| `POST` | `/read` | `read` | Decrypt request body |
| `GET` | `/service/:name/secret/:key` | `read` | Read cloud secret |
| `POST` | `/service/:name/secret/:key` | `write` | Write cloud secret |

CORS is off by default; whitelist with `--cors-origins https://app.example.com`.

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

With this configuration, Nginx will listen on port 80 and distribute incoming requests (`/write`, `/read`, …) between the two daemon instances, providing both load balancing and redundancy.

---

## Database Integration Examples

Here are some examples of how to use `ironcrypt` with popular web frameworks and a PostgreSQL database. These examples use the `sqlx` crate for database interaction.

### Actix-web Example

This example shows how to create a simple web service with `actix-web` that can register and log in users.

**Dependencies:**
```toml
[dependencies]
ironcrypt = "0.1.1"
actix-web = "4"
sqlx = { version = "0.7", features = ["runtime-async-std-native-tls", "postgres"] }
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
```

**Code:**
```rust,ignore
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
ironcrypt = "0.1.1"
rocket = { version = "0.5.0", features = ["json"] }
sqlx = { version = "0.7", features = ["runtime-tokio-native-tls", "postgres"] }
serde = { version = "1.0", features = ["derive"] }
```

**Code:**
```rust,ignore
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

1.  **`ironcrypt.toml` file:** Point the CLI (`ironcrypt`) or the daemon (`ironcryptd`) at it with `--config ironcrypt.toml`, or set `IRONCRYPT_CONFIG_FILE`. `--config` is a global flag, so it works before or after the subcommand (e.g. `ironcrypt --config ironcrypt.toml encrypt-file ...` or `ironcrypt encrypt-file --config ironcrypt.toml ...`). Without it, secure defaults are used — the file is never auto-discovered from the current directory.
2.  **Environment Variables:** Set variables like `IRONCRYPT_KEY_DIRECTORY`.
3.  **Command-Line Arguments:** Flags like `--key-directory` override all other methods.

For library usage, you can construct an `IronCryptConfig` struct and pass it to `IronCrypt::new`.

### Cryptographic Algorithm Configuration

Tune algorithms via flat `ironcrypt.toml` fields (see `ironcrypt.toml.example`).

```toml
# Standards: "Nist" | "Fips140_2" | "Anssi" | "Custom"
standard = "Nist"
rsa_key_size = 2048
buffer_size = 8192
argon2_memory_cost = 65536
argon2_time_cost = 3
argon2_parallelism = 1

[password_criteria]
min_length = 12
```

Custom mode:

```toml
standard = "Custom"
symmetric_algorithm = "ChaCha20Poly1305"  # or "Aes256Gcm"
asymmetric_algorithm = "Ecc"              # or "Rsa"
rsa_key_size = 4096                       # ignored when Ecc
```

`Anssi` forces AES-256-GCM + RSA 3072. For ECC, use `standard = "Custom"` with `asymmetric_algorithm = "Ecc"`.

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