//! # IronCrypt: A Robust Cryptography Library for Rust
//!
//! IronCrypt provides a high-level, easy-to-use API for common cryptographic tasks,
//! focusing on strong, modern algorithms and secure practices. It is designed to be used
//! both as a command-line tool and as a library integrated into Rust applications.
//!
//! ## Core Features
//!
//! - **Hybrid Encryption:** Combines the speed of AES-256-GCM for data encryption with the
//!   security of RSA for key management (envelope encryption).
//! - **State-of-the-Art Password Hashing:** Uses Argon2, a modern, memory-hard algorithm
//!   designed to resist GPU-based cracking attempts.
//! - **Comprehensive Data Handling:** Encrypts not just passwords, but also files, directories,
//!   and any arbitrary binary data.
//! - **Advanced Key Management:** Supports versioned RSA keys and provides a key rotation
//!   mechanism to update keys over time without manual re-encryption.
//! - **Flexible Configuration:** Allows fine-tuning of security parameters like RSA key size,
//!   Argon2 costs, and password strength criteria.
//!
//! ## Quick Start: Library Usage
//!
//! Here is a quick example of how to use `IronCrypt` as a library to encrypt and verify a password.
//!
//! ```rust
//! use ironcrypt::{IronCrypt, IronCryptConfig, IronCryptError};
//!
//! fn main() -> Result<(), IronCryptError> {
//!     // 1. Initialize IronCrypt with a default configuration.
//!     //    This will automatically generate a 2048-bit RSA key pair in the "keys/"
//!     //    directory if it doesn't already exist.
//!     let config = IronCryptConfig::default();
//!     let crypt = IronCrypt::new("keys", "v1", config)?;
//!
//!     // 2. Encrypt a password.
//!     let password = "My$ecureP@ssw0rd!";
//!     let encrypted_data = crypt.encrypt_password(password)?;
//!     println!("Password encrypted successfully!");
//!
//!     // 3. Verify the password.
//!     let is_valid = crypt.verify_password(&encrypted_data, password)?;
//!     assert!(is_valid);
//!     println!("Password verification successful!");
//!
//!     // 4. Clean up the generated keys for this example.
//!     //    In a real application, you would not delete your keys.
//!     std::fs::remove_dir_all("keys")?;
//!
//!     Ok(())
//! }
//! ```
//!
//! For more detailed examples, including file encryption and custom configurations,
//! please see the project's `examples/` directory.

// 1) Module declarations (files)
pub mod config;
pub mod criteria;
pub mod encrypt;
pub mod handle_error;
pub mod hashing;
pub mod ironcrypt;
pub mod rsa_utils;

// 2) Re-export the items you want to be available at the crate root.
//    This allows the binary (main.rs) and other consumers of the library
//    to do `use ironcrypt::{IronCrypt, IronCryptConfig, ...}`.
pub use config::*;
pub use criteria::*;
pub use encrypt::{Argon2Config, EncryptedData};
pub use handle_error::*;
pub use hashing::*;
pub use ironcrypt::IronCrypt;
pub use rsa_utils::*;
