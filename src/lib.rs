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
//!             passphrase: None,
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
//! use ironcrypt::{encrypt_stream, decrypt_stream, generate_rsa_keys, PasswordCriteria, Argon2Config, PublicKey, PrivateKey, algorithms::SymmetricAlgorithm};
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
//!     let pk_enum = PublicKey::Rsa(public_key);
//!     let recipients = vec![(&pk_enum, "v1")];
//!     encrypt_stream(
//!         &mut source,
//!         &mut encrypted_dest,
//!         &mut password,
//!         recipients,
//!         None, // signing_key
//!         &PasswordCriteria::default(),
//!         Argon2Config::default(),
//!         true, // Indicates that the password should be hashed
//!         SymmetricAlgorithm::Aes256Gcm,
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
//!         &PrivateKey::Rsa(private_key),
//!         "v1",
//!         "AnotherStrongPassword123!",
//!         None // verifying_key
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
pub mod ffi;
pub mod algorithms;
pub mod audit;
pub mod config;
pub mod criteria;
pub mod ecc_utils;
pub mod encrypt;
pub mod handle_error;
pub mod hashing;
pub mod ironcrypt;
pub mod metrics;
pub mod keys;
pub mod rsa_utils;
pub mod secrets;
pub mod standards;

// --- Public Re-exports ---

// Main configuration
pub use config::{DataType, IronCryptConfig};

// Configuration types for various providers
#[cfg(feature = "gcp")]
pub use config::GoogleConfig;

// Key types
pub use keys::{PrivateKey, PublicKey};

// Password criteria
pub use criteria::PasswordCriteria;

// Cryptographic standards
pub use standards::CryptoStandard;

// Streaming encryption and decryption functions
pub use encrypt::{decrypt_stream, encrypt_stream};
pub use encrypt::{
    EncryptedStreamHeaderV1, EncryptedStreamHeaderV2, RecipientInfo, StreamHeader,
};
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

// Secret management
pub use secrets::{vault, SecretStore};
#[cfg(feature = "aws")]
pub use secrets::aws;
#[cfg(feature = "azure")]
pub use secrets::azure;
#[cfg(feature = "gcp")]
pub use secrets::google;

/// Tries to load a public key from a file, attempting to parse it as RSA and then ECC.
pub fn load_any_public_key(path: &str) -> Result<PublicKey, IronCryptError> {
    // Try loading as RSA first
    if let Ok(key) = rsa_utils::load_public_key(path) {
        return Ok(PublicKey::Rsa(key));
    }
    // If that fails, try loading as ECC
    if let Ok(key) = ecc_utils::load_public_key(path) {
        return Ok(PublicKey::Ecc(key));
    }
    Err(IronCryptError::KeyLoadingError(format!(
        "Failed to load public key from {}: unsupported format",
        path
    )))
}

/// Tries to load a private key from a file, attempting to parse it as RSA and then ECC.
pub fn load_any_private_key(
    path: &str,
    passphrase: Option<&str>,
) -> Result<PrivateKey, IronCryptError> {
    // Try loading as RSA first
    if let Ok(key) = rsa_utils::load_private_key(path, passphrase) {
        return Ok(PrivateKey::Rsa(key));
    }
    // If that fails, try loading as ECC
    if let Ok(key) = ecc_utils::load_secret_key(path, passphrase) {
        return Ok(PrivateKey::Ecc(key));
    }
    Err(IronCryptError::KeyLoadingError(format!(
        "Failed to load private key from {}: unsupported format or wrong passphrase",
        path
    )))
}
