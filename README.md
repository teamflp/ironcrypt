
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
- **Comprehensive Data Encryption:** IronCrypt is built to handle more than just passwords. It can encrypt any file (images, PDFs, documents), entire directories (by archiving them first), or any other data that can be represented as a stream of bytes.
- **Dual Use (CLI and Library):** IronCrypt is designed from the ground up to be dual-purpose. You can use it as a quick command-line tool for simple tasks, or integrate it as a library (crate) directly into your own Rust applications for more complex logic.

---

## Workflows

### Password Encryption/Decryption

![Password Workflow](images/workflow-password.png)

Ce processus garantit une sécurité maximale en combinant un hachage robuste avec **Argon2** et un chiffrement hybride (appelé "chiffrement d'enveloppe") avec **AES** et **RSA**.

---

### **1. Processus de Chiffrement (par exemple, lors de l'inscription d'un utilisateur)**

L'objectif ici n'est pas de chiffrer le mot de passe lui-même, mais de chiffrer une **empreinte unique** (un "hachage") de ce mot de passe. Le mot de passe en clair n'est jamais stocké.

1.  **Hachage du mot de passe** :
    *   Le mot de passe fourni par l'utilisateur (ex: `"MonMotDePasse123"`) est d'abord passé dans l'algorithme de hachage **Argon2**.
    *   Argon2 le transforme en une empreinte digitale unique et non réversible (le "hachage"). Cet algorithme est conçu pour être lent et gourmand en mémoire, ce qui le rend extrêmement résistant aux attaques par force brute modernes.

2.  **Création de l'enveloppe de chiffrement** :
    *   Une nouvelle clé de chiffrement symétrique **AES-256** est générée de manière aléatoire. Cette clé est à usage unique et ne servira que pour cette opération.
    *   Le hachage Argon2 (créé à l'étape 1) est ensuite chiffré en utilisant cette clé AES.

3.  **Sécurisation de la clé AES (le "sceau" de l'enveloppe)** :
    *   Pour pouvoir vérifier le mot de passe plus tard, il faut conserver la clé AES. La stocker en clair serait une faille de sécurité.
    *   Par conséquent, la clé AES est elle-même chiffrée, mais cette fois avec votre **clé publique RSA**. Seul le détenteur de la clé privée RSA correspondante pourra déchiffrer cette clé AES.

4.  **Stockage des données sécurisées** :
    *   Le résultat final est un objet JSON structuré qui contient toutes les informations nécessaires pour une vérification future :
        *   Le **hachage chiffré** par AES.
        *   La **clé AES chiffrée** par RSA.
        *   Les paramètres techniques (publics) utilisés pour le hachage et le chiffrement (comme le "sel" et le "nonce").
        *   La version de la clé RSA utilisée pour le sceau.
    *   C'est cet objet JSON qui est stocké de manière sécurisée dans votre base de données.

---

### **2. Processus de Vérification (par exemple, lors de la connexion d'un utilisateur)**

Ici, l'objectif est de vérifier si le mot de passe fourni par l'utilisateur correspond à celui stocké, **sans jamais avoir à le voir en clair**.

1.  **Récupération des données** :
    *   L'utilisateur se connecte en fournissant son mot de passe (ex: `"MonMotDePasse123"`).
    *   Vous récupérez l'objet JSON correspondant à cet utilisateur dans votre base de données.

2.  **Ouverture de l'enveloppe** :
    *   À l'aide de votre **clé privée RSA**, vous déchiffrez la clé AES contenue dans le JSON.
    *   Une fois la clé AES obtenue en clair, vous l'utilisez pour déchiffrer le hachage Argon2 original.

3.  **Hachage et Comparaison en temps réel** :
    *   Le mot de passe qui vient d'être fourni par l'utilisateur pour se connecter est haché à son tour, en utilisant exactement les mêmes paramètres (le "sel") que ceux qui sont stockés dans le JSON.
    *   Les deux hachages — celui qui vient d'être généré et celui qui a été déchiffré de la base de données — sont comparés.

4.  **Résultat de la vérification** :
    *   **Si les deux hachages sont identiques**, cela prouve que le mot de passe fourni est correct. L'accès est autorisé.
    *   **S'ils sont différents**, le mot de passe est incorrect. L'accès est refusé.

Ce workflow garantit que même si votre base de données était compromise, les mots de passe des utilisateurs resteraient inutilisables par un attaquant, car le mot de passe original n'y est jamais stocké.

### File Encryption/Decryption

![File Workflow](images/workflow-file.png)

Ce processus utilise également un chiffrement d'enveloppe (AES + RSA) pour garantir à la fois la performance et la sécurité.

#### **1. Processus de Chiffrement**

1.  **Lecture du fichier** : Le contenu du fichier (par exemple, une image, un PDF) est lu en mémoire sous forme de données binaires.
2.  **Création de l'enveloppe** :
    *   Une nouvelle clé **AES-256** à usage unique est générée aléatoirement.
    *   Les données binaires du fichier sont entièrement chiffrées avec cette clé AES.
3.  **Sceau de l'enveloppe** :
    *   La clé AES est chiffrée avec votre **clé publique RSA**.
4.  **Stockage** : Un objet JSON est créé, contenant les données du fichier chiffrées, la clé AES chiffrée, et les métadonnées nécessaires. Ce JSON est ensuite sauvegardé dans un nouveau fichier (par exemple, `mon_document.enc`).

#### **2. Processus de Déchiffrement**

1.  **Lecture du fichier chiffré** : Le contenu du fichier `.enc` (le JSON) est lu.
2.  **Ouverture de l'enveloppe** :
    *   Votre **clé privée RSA** est utilisée pour déchiffrer la clé AES.
    *   La clé AES est ensuite utilisée pour déchiffrer les données binaires du fichier original.
3.  **Sauvegarde du fichier** : Les données binaires déchiffrées sont écrites dans un nouveau fichier, restaurant ainsi le fichier original.

### Directory Encryption/Decryption

![Directory Workflow](images/workflow-directory.png)

Le chiffrement d'un répertoire entier se base sur le workflow de chiffrement de fichier, avec une étape de préparation supplémentaire.

#### **1. Processus de Chiffrement**

1.  **Archivage et Compression** :
    *   Le répertoire cible est d'abord lu, et tous ses fichiers et sous-répertoires sont compressés dans une seule archive en mémoire (un fichier `.tar.gz`).
2.  **Chiffrement de l'archive** :
    *   Cette archive `.tar.gz` est ensuite traitée comme un simple fichier binaire.
    *   Le processus de **chiffrement de fichier** décrit ci-dessus est appliqué à l'archive.
3.  **Stockage** : Le JSON résultant est sauvegardé dans un unique fichier chiffré.

#### **2. Processus de Déchiffrement**

1.  **Déchiffrement de l'archive** :
    *   Le processus de **déchiffrement de fichier** est utilisé pour récupérer l'archive `.tar.gz` en clair.
2.  **Décompression et Extraction** :
    *   L'archive `.tar.gz` est ensuite décompressée, et son contenu est extrait dans le répertoire de destination, recréant ainsi la structure et les fichiers originaux.

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

#### Encrypting and Decrypting a File
```rust
use ironcrypt::{IronCrypt, IronCryptConfig, IronCryptError};
use std::fs;

fn main() -> Result<(), IronCryptError> {
    // Initialize IronCrypt
    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new("keys", "v1", config)?;

    // Encrypt a file
    let file_data = b"This is the content of my secret file.";
    let encrypted_file = crypt.encrypt_binary_data(file_data, "file_password")?;
    fs::write("secret.enc", encrypted_file).unwrap();
    println!("File encrypted!");

    // Decrypt the file
    let encrypted_content = fs::read_to_string("secret.enc").unwrap();
    let decrypted_data = crypt.decrypt_binary_data(&encrypted_content, "file_password")?;
    assert_eq!(file_data, &decrypted_data[..]);
    println!("File decrypted successfully!");

    // Clean up
    std::fs::remove_dir_all("keys")?;
    std::fs::remove_file("secret.enc")?;
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