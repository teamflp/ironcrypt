//! # IronCrypt: A Robust and Simple Cryptography Library for Rust
//!
//! IronCrypt provides a high-level API designed to simplify common cryptographic tasks,
//! with a focus on modern algorithms and secure practices. It can be used both as a
//! command-line tool and as a Rust library integrated into your applications.
//!
//! ## Core Features
//!
//! - **Streaming Encryption:** Efficiently encrypt and decrypt large files and data streams
//!   without loading them entirely into memory.
//! - **Hybrid Encryption:** Combines the speed of symmetric encryption (AES-256-GCM)
//!   for data with the security of asymmetric encryption (RSA) for key management.
//! - **State-of-the-Art Password Hashing:** Uses Argon2, a modern and resilient algorithm
//!   designed to counter GPU-based brute-force attacks.
//! - **Advanced Key Management:** Supports versioning of RSA keys and includes a rotation
//!   mechanism to update keys without having to manually re-encrypt everything.
//! - **Flexible Configuration:** Allows fine-tuning of security parameters like RSA key
//!   size, Argon2 "costs," and password strength criteria.
//!
//! ## Quick Start
//!
//! ### Example 1: Encrypting and Verifying a Password
//!
//! The example below shows how to use the `IronCrypt` struct to securely hash a password
//! and verify it later.
//!
//! ```rust
//! use ironcrypt::{IronCrypt, IronCryptConfig, DataType, config::KeyManagementConfig};
//! use std::collections::HashMap;
//! use std::error::Error;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     // 1. Use a temporary directory for keys to keep tests isolated.
//!     let temp_dir = tempfile::tempdir()?;
//!     let key_dir = temp_dir.path().to_str().unwrap();
//!
//!     // 2. Configure IronCrypt to use the temporary directory.
//!     let mut config = IronCryptConfig::default();
//!     let mut data_type_config = HashMap::new();
//!     data_type_config.insert(
//!         DataType::Generic,
//!         KeyManagementConfig {
//!             key_directory: key_dir.to_string(),
//!             key_version: "v1".to_string(),
//!         },
//!     );
//!     config.data_type_config = Some(data_type_config);
//!
//!     // 3. Initialize IronCrypt.
//!     let crypt = IronCrypt::new(config, DataType::Generic).await?;
//!
//!     // 4. Encrypt a password.
//!     let password = "MySecurePassword123!";
//!     let encrypted_json = crypt.encrypt_password(password)?;
//!     println!("Encrypted password: {}", encrypted_json);
//!
//!     // 5. Verify the password.
//!     let is_valid = crypt.verify_password(&encrypted_json, password)?;
//!     assert!(is_valid);
//!     println!("Password verification successful!");
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Example 2: Streaming File Encryption
//!
//! This example shows how to encrypt a data stream (here, an in-memory `Cursor`,
//! but it works the same way with a `File`).
//!
//! ```rust
//! use ironcrypt::{encrypt_stream, decrypt_stream, generate_rsa_keys, PasswordCriteria, Argon2Config};
//! use std::io::Cursor;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Generate an RSA key pair (in a real application, load them from a file).
//!     let (private_key, public_key) = generate_rsa_keys(2048)?;
//!
//!     // 2. Prepare the source and destination streams.
//!     let original_data = "This is a secret message that will be streamed for encryption.";
//!     let mut source = Cursor::new(original_data.as_bytes());
//!     let mut encrypted_dest = Cursor::new(Vec::new());
//!
//!     // 3. Encrypt the stream.
//!     let mut password = "AnotherStrongPassword123!".to_string();
//!     encrypt_stream(
//!         &mut source,
//!         &mut encrypted_dest,
//!         &mut password,
//!         &public_key,
//!         &PasswordCriteria::default(),
//!         "v1", // Key version
//!         Argon2Config::default(),
//!         true, // Indicates that the password should be hashed
//!     )?;
//!
//!     // 4. Go back to the beginning of the encrypted stream to read it.
//!     encrypted_dest.set_position(0);
//!
//!     // 5. Decrypt the stream.
//!     let mut decrypted_dest = Cursor::new(Vec::new());
//!     decrypt_stream(
//!         &mut encrypted_dest,
//!         &mut decrypted_dest,
//!         &private_key,
//!         "AnotherStrongPassword123!",
//!     )?;
//!
//!     // 6. Verify that the decrypted data matches the original data.
//!     let decrypted_data = String::from_utf8(decrypted_dest.into_inner())?;
//!     assert_eq!(original_data, decrypted_data);
//!     println!("Stream encryption and decryption successful!");
//!
//!     Ok(())
//! }
//! ```
//!
//! For more advanced examples, including custom configurations,
//! check out the `examples/` directory of the project.

// --- Modules ---
pub mod config;
pub mod criteria;
pub mod encrypt;
pub mod handle_error;
pub mod hashing;
pub mod ironcrypt;
pub mod metrics;
pub mod rsa_utils;
pub mod secrets;

// --- Public Re-exports ---

// Main configuration
pub use config::{DataType, IronCryptConfig};

// Password criteria
pub use criteria::PasswordCriteria;

// Streaming encryption and decryption functions
pub use encrypt::{decrypt_stream, encrypt_stream};
/// Represents the header of an encrypted data stream.
pub use encrypt::EncryptedStreamHeader;
/// Contains the parameters for the Argon2 hashing algorithm.
pub use encrypt::Argon2Config;
/// Struct containing the encrypted data and associated metadata.
pub use encrypt::EncryptedData;

// Error handling
pub use handle_error::IronCryptError;

// Password hashing function
pub use hashing::hash_password;

// Main library struct
pub use ironcrypt::IronCrypt;

// RSA key utilities
pub use rsa_utils::{generate_rsa_keys, load_private_key, load_public_key, save_keys_to_files};

// Secret management (if the feature is enabled)
pub use secrets::{aws, azure, vault, SecretStore};
