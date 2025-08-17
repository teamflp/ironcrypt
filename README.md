
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

**IronCrypt** is a Command-Line Interface (CLI) tool and Rust library dedicated to secure password and data encryption. By combining the **Argon2** hashing algorithm, **AES-256-GCM** encryption, and **RSA** for key management, IronCrypt provides a robust solution to ensure your application’s data confidentiality and password security.

---

## Features

- **Hybrid Encryption (RSA + AES):** IronCrypt uses a smart combination of encryption methods. It encrypts your data with AES-256 (very fast and secure), and then encrypts the AES key itself with RSA. This is an industry-standard technique called "envelope encryption" that combines the best of both worlds: the speed of symmetric encryption and the secure key management of asymmetric encryption.
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
    *   This AES key is encrypted with your **public RSA key**.
    *   A JSON header is created containing the encrypted AES key and other necessary metadata (nonce, key version).
3.  **Streaming Encryption**:
    *   The JSON header is written to the start of the output file.
    *   IronCrypt then reads the input file in small chunks, encrypts each chunk with the AES key, and immediately writes the encrypted chunk to the output file.
4.  **Finalizing**: Once the entire file has been processed, an authentication tag is appended to the end of the output file to ensure its integrity.

#### **2. Decryption Process**

1.  **Reading the Header**: IronCrypt reads the JSON header from the start of the encrypted file.
2.  **Opening the Envelope**:
    *   Your **private RSA key** is used to decrypt the AES key from the header.
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

---

## Usage

### Command-Line Interface (CLI)


Here is a summary table of all available commands:

| Command       | Alias                  | Description                                 | Key Options                                                                                                                                               |
| :------------ | :--------------------- | :------------------------------------------ | :-------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `generate`    |                        | Generates a new RSA key pair.               | `-v, --version <VERSION>` <br> `-d, --directory <DIR>` <br> `-s, --key-size <SIZE>`                                                                        |
| `encrypt`     |                        | Hashes and encrypts a password.             | `-w, --password <PASSWORD>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>`                                                      |
| `decrypt`     |                        | Verifies an encrypted password.             | `-w, --password <PASSWORD>` <br> `-k, --private-key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `-f, --file <FILE>`                               |
| `encrypt-file`| `encfile`, `efile`, `ef` | Encrypts a binary file.                     | `-i, --input-file <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[-w, --password <PASSWORD>]` |
| `decrypt-file`| `decfile`, `dfile`, `df` | Decrypts a binary file.                     | `-i, --input-file <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-k, --private-key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[-w, --password <PASSWORD>]` |
| `encrypt-dir` | `encdir`                 | Encrypts an entire directory.               | `-i, --input-dir <INPUT>` <br> `-o, --output-file <OUTPUT>` <br> `-d, --public-key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[-w, --password <PASSWORD>]` |
| `decrypt-dir` | `decdir`                 | Decrypts an entire directory.               | `-i, --input-file <INPUT>` <br> `-o, --output-dir <OUTPUT>` <br> `-k, --private-key-directory <DIR>` <br> `-v, --key-version <VERSION>` <br> `[-w, --password <PASSWORD>]` |
| `rotate-key`  | `rk`                     | Rotates encryption keys for encrypted data. | `--old-version <OLD_V>` <br> `--new-version <NEW_V>` <br> `-k, --key-directory <DIR>` <br> `--file <FILE>` or `--directory <DIR>`                               |

A full list of commands and their arguments can be viewed by running `ironcrypt --help`. To get help for a specific command, run `ironcrypt <command> --help`.

#### `generate`
Generates a new RSA key pair (private and public).

**Usage:**
```sh
ironcrypt generate --version <VERSION> [--directory <DIR>] [--key-size <SIZE>]
```

**Example:**
```sh
# Generate a new v2 key with a size of 4096 bits in the "my_keys" directory
ironcrypt generate -v v2 -d my_keys -s 4096
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
ironcrypt decrypt --password <PASSWORD> --private-key-directory <DIR> --key-version <VERSION> --file <FILE>
```

**Example:**
```sh
# Verify a password using the v1 private key and the encrypted data from a file
ironcrypt decrypt -w "My$trongP@ssw0rd" -k keys -v v1 -f encrypted_data.json
```

#### `encrypt-file`
Encrypts a single file.

**Usage:**
```sh
ironcrypt encrypt-file -i <INPUT> -o <OUTPUT> -d <KEY_DIR> -v <VERSION> [-w <PASSWORD>]
```

**Example:**
```sh
# Encrypt a file with the v1 public key
ironcrypt encrypt-file -i my_document.pdf -o my_document.enc -d keys -v v1

# Encrypt a file with a password as well
ironcrypt encrypt-file -i my_secret.zip -o my_secret.enc -d keys -v v1 -w "ExtraL@yerOfS3curity"
```

#### `decrypt-file`
Decrypts a single file.

**Usage:**
```sh
ironcrypt decrypt-file -i <INPUT> -o <OUTPUT> -k <KEY_DIR> -v <VERSION> [-w <PASSWORD>]
```

**Example:**
```sh
# Decrypt a file with the v1 private key
ironcrypt decrypt-file -i my_document.enc -o my_document.pdf -k keys -v v1

# Decrypt a file that was also encrypted with a password
ironcrypt decrypt-file -i my_secret.enc -o my_secret.zip -k keys -v v1 -w "ExtraL@yerOfS3curity"
```

#### `encrypt-dir`
Encrypts an entire directory by first archiving it into a `.tar.gz`.

**Usage:**
```sh
ironcrypt encrypt-dir -i <INPUT_DIR> -o <OUTPUT_FILE> -d <KEY_DIR> -v <VERSION> [-w <PASSWORD>]
```

**Example:**
```sh
# Encrypt the "my_project" directory
ironcrypt encrypt-dir -i ./my_project -o my_project.enc -d keys -v v1
```

#### `decrypt-dir`
Decrypts and extracts a directory.

**Usage:**
```sh
ironcrypt decrypt-dir -i <INPUT_FILE> -o <OUTPUT_DIR> -k <KEY_DIR> -v <VERSION> [-w <PASSWORD>]
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
ironcrypt rotate-key --old-version <OLD_V> --new-version <NEW_V> --key-directory <DIR> [--file <FILE> | --directory <DIR>]
```

**Example:**
```sh
# Rotate keys from v1 to v2 for a single file
ironcrypt rotate-key --old-version v1 --new-version v2 -k keys --file my_document.enc

# Rotate keys from v1 to v2 for all files in the "encrypted_files" directory
ironcrypt rotate-key --old-version v1 --new-version v2 -k keys -d ./encrypted_files
```

### As a Library (Crate)

You can also use `ironcrypt` as a library in your Rust projects. Add it to your `Cargo.toml`:
```toml
[dependencies]
ironcrypt = "0.1.0" # Replace with the desired version from crates.io
```

#### Encrypting and Verifying a Password
```rust
use ironcrypt::{IronCrypt, IronCryptConfig, IronCryptError};

fn main() -> Result<(), IronCryptError> {
    // Initialize IronCrypt
    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new("keys", "v1", config)?;

    // Encrypt a password
    let password = "My$ecureP@ssw0rd!";
    let encrypted_data = crypt.encrypt_password(password)?;
    println!("Password encrypted!");

    // Verify the password
    let is_valid = crypt.verify_password(&encrypted_data, password)?;
    assert!(is_valid);
    println!("Password verification successful!");

    // Clean up keys for this example
    std::fs::remove_dir_all("keys")?;
    Ok(())
}
```

#### Encrypting and Decrypting a File (Streaming)
```rust
use ironcrypt::{encrypt_stream, decrypt_stream, load_public_key, load_private_key, PasswordCriteria, Argon2Config, IronCryptError};
use std::fs::File;
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For this example, we'll generate keys on the fly.
    // In a real application, you would load them from a secure location.
    let (private_key, public_key) = ironcrypt::generate_rsa_keys(2048)?;

    // --- Source and Destination ---
    // In a real app, these would be `File::open(...)` and `File::create(...)`.
    // Here, we use in-memory buffers for a self-contained example.
    let original_data = "This is the content of my very large secret file that should be streamed.";
    let mut source = Cursor::new(original_data);
    let mut encrypted_dest = Cursor::new(Vec::new());

    // --- Encryption ---
    let mut password = "a_very_Str0ng_P@ssw0rd!".to_string();
    encrypt_stream(
        &mut source,
        &mut encrypted_dest,
        &mut password,
        &public_key,
        &PasswordCriteria::default(),
        "v1",
        Argon2Config::default(),
        true,
    )?;
    println!("File encrypted successfully!");

    // --- Decryption ---
    let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
    let mut decrypted_dest = Cursor::new(Vec::new());

    decrypt_stream(
        &mut encrypted_source,
        &mut decrypted_dest,
        &private_key,
        "a_very_Str0ng_P@ssw0rd!",
    )?;

    // --- Verification ---
    let decrypted_data = String::from_utf8(decrypted_dest.into_inner())?;
    assert_eq!(original_data, decrypted_data);
    println!("File decrypted and verified successfully!");

    Ok(())
}
```

---

## Database Integration Examples

Here are some examples of how to use `ironcrypt` with popular web frameworks and a PostgreSQL database. These examples use the `sqlx` crate for database interaction.

### Actix-web Example

This example shows how to create a simple web service with `actix-web` that can register and log in users.

**Dependencies:**
```toml
[dependencies]
ironcrypt = "0.1.0"
actix-web = "4"
sqlx = { version = "0.7", features = ["runtime-async-std-native-tls", "postgres"] }
serde = { version = "1.0", features = ["derive"] }
```

**Code:**
```rust
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use ironcrypt::{IronCrypt, IronCryptConfig};
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
    let crypt = IronCrypt::new("keys", "v1", config).expect("Failed to initialize IronCrypt");

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
ironcrypt = "0.1.0"
rocket = { version = "0.5.0-rc.2", features = ["json"] }
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
use ironcrypt::{IronCrypt, IronCryptConfig};
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
    let crypt = IronCrypt::new("keys", "v1", config).expect("Failed to initialize IronCrypt");

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

---

## Security and Best Practices

- **Protect Your Private Keys:** Never expose your private keys. Store them in a secure, non-public location.
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