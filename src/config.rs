// config.rs
use crate::algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm};
pub use crate::PasswordCriteria;
use crate::standards::CryptoStandard;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Enum for classifying data types.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum DataType {
    Generic,
    Pii,
    Biometric,
}

/// Configuration for key management for a specific data type.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyManagementConfig {
    pub key_directory: String,
    pub key_version: String,
    #[serde(default)]
    pub passphrase: Option<String>,
}

/// Type alias for a map of data types to their key management configurations.
pub type DataTypeConfig = HashMap<DataType, KeyManagementConfig>;

/// Configuration for the secret management backend.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SecretsConfig {
    /// The provider to use for secret storage.
    /// e.g., "vault"
    pub provider: String,
    /// Configuration for HashiCorp Vault.
    #[cfg(feature = "vault")]
    #[serde(default)]
    pub vault: Option<VaultConfig>,
    /// Configuration for AWS Secrets Manager.
    #[serde(default)]
    pub aws: Option<AwsConfig>,
    /// Configuration for Azure Key Vault.
    #[serde(default)]
    pub azure: Option<AzureConfig>,
    // TODO: Google provider disabled due to compilation errors.
    // /// Configuration for Google Cloud Secret Manager.
    // #[serde(default)]
    // pub google: Option<GoogleConfig>,
}

/// Configuration for auditing.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuditConfig {
    /// Path to the audit log file.
    pub log_path: String,
    /// Path to the private key used for signing the audit log.
    /// If not provided, the log will not be signed.
    #[serde(default)]
    pub signing_key_path: Option<String>,
}

// TODO: Google provider disabled due to compilation errors.
// /// Configuration for Google Cloud Secret Manager.
// #[derive(Serialize, Deserialize, Debug, Clone, Default)]
// pub struct GoogleConfig {
//     /// The Google Cloud project ID.
//     pub project_id: String,
// }

/// Configuration for Azure Key Vault.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AzureConfig {
    /// The URI of the Key Vault.
    pub vault_uri: String,
}

/// Configuration for AWS Secrets Manager.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AwsConfig {
    /// The AWS region.
    pub region: String,
}

/// Configuration for HashiCorp Vault.
#[cfg(feature = "vault")]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VaultConfig {
    /// The address of the Vault server.
    pub address: String,
    /// The token to use for authentication.
    pub token: String,
    /// The mount path of the KVv2 secrets engine.
    #[serde(default = "default_mount")]
    pub mount: String,
}

fn default_mount() -> String {
    "secret".to_string()
}

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
 /// use ironcrypt::standards::CryptoStandard;
///
/// let custom_config = IronCryptConfig {
 ///     standard: CryptoStandard::Custom,
///     symmetric_algorithm: ironcrypt::algorithms::SymmetricAlgorithm::ChaCha20Poly1305,
///     asymmetric_algorithm: ironcrypt::algorithms::AsymmetricAlgorithm::Ecc,
///     rsa_key_size: 4096,
///     buffer_size: 8192,
///     argon2_memory_cost: 32768, // 32MB
///     argon2_time_cost: 4,
///     argon2_parallelism: 2,
///     password_criteria: PasswordCriteria {
///         min_length: 10,
///         ..Default::default()
///     },
///     secrets: None,
///     data_type_config: None,
/// };
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IronCryptConfig {
    /// The cryptographic standard to use.
    ///
    /// This determines the set of algorithms and key sizes. If set to `Custom`,
    /// the `symmetric_algorithm`, `asymmetric_algorithm`, and `rsa_key_size` fields
    /// must be specified manually.
    #[serde(default)]
    pub standard: CryptoStandard,
    /// The symmetric algorithm to use for data encryption.
    ///
    /// **Note:** This is ignored if `standard` is not `Custom`.
    #[serde(default)]
    pub symmetric_algorithm: SymmetricAlgorithm,
    /// The asymmetric algorithm to use for key encapsulation.
    ///
    /// **Note:** This is ignored if `standard` is not `Custom`.
    #[serde(default)]
    pub asymmetric_algorithm: AsymmetricAlgorithm,
    /// The size of the RSA key in bits.
    ///
    /// **Note:** This is ignored if `standard` is not `Custom`.
    pub rsa_key_size: u32,
    /// The size of the buffer to use for streaming operations (in bytes).
    pub buffer_size: usize,
    /// The memory cost (in KiB) for the Argon2 password hashing algorithm.
    pub argon2_memory_cost: u32,
    /// The time cost (or number of iterations) for the Argon2 algorithm.
    pub argon2_time_cost: u32,
    /// The parallelism factor (or number of threads) for the Argon2 algorithm.
    pub argon2_parallelism: u32,
    /// The criteria used to validate password strength.
    pub password_criteria: PasswordCriteria,
    /// Configuration for the secret management backend.
    #[serde(default)]
    pub secrets: Option<SecretsConfig>,
    /// Configuration for data type specific key management.
    #[serde(default)]
    pub data_type_config: Option<DataTypeConfig>,
    /// Configuration for auditing.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

impl Default for IronCryptConfig {
    /// Creates a new `IronCryptConfig` with secure and sensible default values.
    fn default() -> Self {
        Self {
            standard: CryptoStandard::default(),
            symmetric_algorithm: SymmetricAlgorithm::default(),
            asymmetric_algorithm: AsymmetricAlgorithm::default(),
            rsa_key_size: 2048,
            buffer_size: 4096,
            argon2_memory_cost: 65536,
            argon2_time_cost: 3,
            argon2_parallelism: 1,
            password_criteria: PasswordCriteria::default(),
            secrets: None,
            data_type_config: None,
            audit: None,
        }
    }
}