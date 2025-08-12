// lib.rs

// 1) Module declarations (the files)
pub mod config; // (maps to "config.rs")
pub mod criteria; // (maps to "criteria.rs")
pub mod encrypt; // (maps to "encrypt.rs")
pub mod handle_error; // (maps to "handle_error.rs")
pub mod hashing; // (maps to "hashing.rs")
pub mod ironcrypt; // (maps to "ironcrypt.rs")
pub mod rsa_utils; // (maps to "rsa_utils.rs")

// 2) Re-export items you want available at the crate root
//    The binary (main.rs) can then use `ironcrypt::{ generate_rsa_keys, ... }`
pub use config::*; // IronCryptConfig, etc.
pub use criteria::*; // PasswordCriteria
pub use encrypt::{Argon2Config, EncryptedData}; // only explicit items
pub use handle_error::*; // IronCryptError, etc.
pub use hashing::*; // hash_password (if needed)
pub use ironcrypt::IronCrypt; // struct IronCrypt
pub use rsa_utils::*; // generate_rsa_keys, load_public_key, etc.
