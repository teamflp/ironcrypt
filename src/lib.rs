// lib.rs

// 1) Déclaration des modules (les fichiers)
pub mod config;       // => "config.rs"
pub mod criteria;     // => "criteria.rs"
pub mod encrypt;      // => "encrypt.rs"
pub mod handle_error; // => "handle_error.rs"
pub mod hashing;      // => "hashing.rs"
pub mod ironcrypt;    // => "ironcrypt.rs"
pub mod rsa_utils;    // => "rsa_utils.rs"

// 2) Re-export des items que vous voulez disponibles au crate root
//    Le binaire (main.rs) pourra faire `use ironcrypt::{ generate_rsa_keys, ... }`
pub use config::*;                  // IronCryptConfig, etc.
pub use criteria::*;                // PasswordCriteria
pub use encrypt::{Argon2Config, EncryptedData}; // only items explicit
pub use handle_error::*;            // IronCryptError, etc.
pub use hashing::*;                 // hash_password (si besoin)
pub use ironcrypt::{IronCrypt};     // struct IronCrypt
pub use rsa_utils::*;               // generate_rsa_keys, load_public_key, etc.
