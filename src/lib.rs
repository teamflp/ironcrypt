//! # IronCrypt: A Robust Cryptography Library for Rust
//!
//! IronCrypt provides a high-level, easy-to-use API for common cryptographic tasks,
//! focusing on strong, modern algorithms and secure practices. It is designed to be used
//! both as a command-line tool and as a library integrated into Rust applications.
//!
//! ## Core Features
//!
//! - **Streaming Encryption:** Efficiently encrypts and decrypts large files and data streams
//!   without loading them entirely into memory, using a chunk-based processing model.
//! - **Hybrid Encryption:** Combines the speed of AES-256-GCM for data encryption with the
//!   security of RSA for key management (envelope encryption).
//! - **State-of-the-Art Password Hashing:** Uses Argon2, a modern, memory-hard algorithm
//!   designed to resist GPU-based cracking attempts.
//! - **Advanced Key Management:** Supports versioned RSA keys and provides a key rotation
//!   mechanism to update keys over time without manual re-encryption.
//! - **Flexible Configuration:** Allows fine-tuning of security parameters like RSA key size,
//!   Argon2 costs, and password strength criteria.
//!
//! ## Quick Start: Streaming File Encryption
//!
//! Here is a quick example of how to use the streaming API to encrypt and decrypt a file.
//!
//! ```rust
//! use ironcrypt::{encrypt_stream, decrypt_stream, PasswordCriteria, Argon2Config};
//! use std::io::Cursor;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. In a real application, you would load your keys. For this example, we generate them.
//!     let (private_key, public_key) = ironcrypt::generate_rsa_keys(2048)?;
//!
//!     // 2. Prepare your data source and destination. These can be files or in-memory buffers.
//!     let original_data = "This is a secret message that will be streamed.";
//!     let mut source = Cursor::new(original_data);
//!     let mut encrypted_dest = Cursor::new(Vec::new());
//!
//!     // 3. Encrypt the stream.
//!     let mut password = "Str0ngP@ssw0rd!".to_string();
//!     encrypt_stream(
//!         &mut source,
//!         &mut encrypted_dest,
//!         &mut password,
//!         &public_key,
//!         &PasswordCriteria::default(),
//!         "v1", // The key version
//!         Argon2Config::default(),
//!         true, // Hash the password
//!     )?;
//!     println!("Stream encrypted successfully!");
//!
//!     // 4. Decrypt the stream.
//!     let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
//!     let mut decrypted_dest = Cursor::new(Vec::new());
//!     decrypt_stream(
//!         &mut encrypted_source,
//!         &mut decrypted_dest,
//!         &private_key,
//!         "Str0ngP@ssw0rd!",
//!     )?;
//!
//!     // 5. Verify the result.
//!     let decrypted_data = String::from_utf8(decrypted_dest.into_inner())?;
//!     assert_eq!(original_data, decrypted_data);
//!     println!("Stream decrypted and verified successfully!");
//!
//!     Ok(())
//! }
//! ```
//!
//! For more detailed examples, including file encryption and custom configurations,
//! please see the project's `examples/` directory.

// 1) Module declarations (the files)
pub mod config; // (maps to "config.rs")
pub mod criteria; // (maps to "criteria.rs")
pub mod encrypt; // (maps to "encrypt.rs")
pub mod handle_error; // (maps to "handle_error.rs")
pub mod hashing; // (maps to "hashing.rs")
pub mod ironcrypt; // (maps to "ironcrypt.rs")
pub mod metrics;
pub mod rsa_utils;
// (maps to "rsa_utils.rs")

// 2) Re-export items you want available at the crate root
//    The binary (main.rs) can then use `ironcrypt::{ generate_rsa_keys, ... }`
pub use config::*; // IronCryptConfig, etc.
pub use criteria::*; // PasswordCriteria
pub use encrypt::{
    encrypt_stream, decrypt_stream, EncryptedStreamHeader, Argon2Config, EncryptedData,
}; // only explicit items
pub use handle_error::*; // IronCryptError, etc.
pub use hashing::*; // hash_password (if needed)
pub use ironcrypt::IronCrypt; // struct IronCrypt
pub use rsa_utils::*; // generate_rsa_keys, load_public_key, etc.
