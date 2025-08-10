// config.rs
use crate::PasswordCriteria;
use serde::{Deserialize, Serialize};

/// Configuration for IronCrypt security, including key sizes and password strength criteria.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IronCryptConfig {
    pub rsa_key_size: u32,                   // RSA key size
    pub argon2_memory_cost: u32,             // Memory cost for Argon2
    pub argon2_time_cost: u32,               // Time cost for Argon2
    pub argon2_parallelism: u32,             // Number of threads for Argon2
    pub aes_key_size: usize,                 // AES key size (128, 192, or 256 bits)
    pub password_criteria: PasswordCriteria, // Password strength criteria
}

impl Default for IronCryptConfig {
    /// Returns a secure default configuration.
    fn default() -> Self {
        Self {
            rsa_key_size: 2048,
            argon2_memory_cost: 65536,
            argon2_time_cost: 3,
            argon2_parallelism: 1,
            aes_key_size: 256,
            password_criteria: PasswordCriteria::default(),
        }
    }
}
