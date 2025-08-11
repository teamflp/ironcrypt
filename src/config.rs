// config.rs
use crate::PasswordCriteria;
use serde::{Deserialize, Serialize};

/// Main configuration for an `IronCrypt` instance.
///
/// This struct allows for detailed customization of the security parameters used for encryption,
/// key generation, and password hashing.
///
/// # Examples
///
/// Creating a custom configuration:
/// ```
/// use ironcrypt::config::{IronCryptConfig, PasswordCriteria};
///
/// let custom_config = IronCryptConfig {
///     rsa_key_size: 4096,
///     aes_key_size: 256,
///     argon2_memory_cost: 32768, // 32MB
///     argon2_time_cost: 4,
///     argon2_parallelism: 2,
///     password_criteria: PasswordCriteria {
///         min_length: 10,
///         ..Default::default()
///     },
/// };
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IronCryptConfig {
    /// The size of the RSA key in bits.
    ///
    /// Recommended values are 2048, 3072, or 4096. Larger keys are more secure but slower.
    pub rsa_key_size: u32,
    /// The memory cost (in KiB) for the Argon2 password hashing algorithm.
    ///
    /// This parameter controls the amount of memory used by the hashing function. Higher values
    /// increase resistance to GPU-based cracking attacks.
    pub argon2_memory_cost: u32,
    /// The time cost (or number of iterations) for the Argon2 algorithm.
    ///
    /// This defines how many passes the algorithm makes over the memory. Higher values
    /// increase the computational cost for an attacker.
    pub argon2_time_cost: u32,
    /// The parallelism factor (or number of threads) for the Argon2 algorithm.
    ///
    /// This controls the number of parallel threads used during hashing.
    pub argon2_parallelism: u32,
    /// The size of the AES key in bits.
    ///
    /// IronCrypt uses AES-GCM for symmetric encryption. Supported values are 128, 192, or 256.
    /// The default and recommended value is 256.
    pub aes_key_size: usize,
    /// The criteria used to validate password strength.
    pub password_criteria: PasswordCriteria,
}

impl Default for IronCryptConfig {
    /// Creates a new `IronCryptConfig` with secure and sensible default values.
    ///
    /// - **RSA Key Size:** 2048 bits
    /// - **AES Key Size:** 256 bits
    /// - **Argon2 Memory Cost:** 65536 KiB (64 MiB)
    /// - **Argon2 Time Cost:** 3 iterations
    /// - **Argon2 Parallelism:** 1 thread
    /// - **Password Criteria:** Default `PasswordCriteria` (12 chars, requires uppercase, number, special char).
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
