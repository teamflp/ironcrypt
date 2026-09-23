// config.rs
use crate::algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm};
pub use crate::PasswordCriteria;
use crate::standards::CryptoStandard;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    Io(#[from] io::Error),
    #[error("Failed to parse TOML config: {0}")]
    Toml(#[from] toml::de::Error),
}

use std::io;

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
    /// Configuration for Google Cloud Secret Manager.
    #[cfg(feature = "gcp")]
    #[serde(default)]
    pub google: Option<GoogleConfig>,
    /// Configuration for a PKCS#11 Hardware Security Module.
    #[cfg(feature = "hsm")]
    #[serde(default)]
    pub hsm: Option<HsmConfig>,
}

/// How audit log segments are attested / signed.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AuditSigningMode {
    /// No signing.
    #[default]
    None,
    /// Local PEM private key via `signing_key_path` (lab / non-Payment only).
    Pem,
    /// HMAC-SHA256 key from environment (`signing_hmac_env`, default `IRONCRYPT_AUDIT_HMAC_KEY`).
    /// Preferred for Payment when CryptoProvider signing is not wired.
    HmacEnv,
    /// Seal the file digest with the configured [`CryptoProvider`] (`signing_key_id`).
    /// Private key material never lands on disk as PEM.
    Provider,
}

/// Configuration for auditing.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuditConfig {
    /// Directory where rolling audit log files are written by `ironcryptd`
    /// (via `tracing_appender::rolling::daily`).
    ///
    /// Prefer this field for daemon deployments. If empty, [`Self::log_path`]
    /// is treated as the directory for backward compatibility.
    #[serde(default)]
    pub audit_directory: String,
    /// Path used by library helpers such as `IronCrypt::sign_audit_log`.
    ///
    /// - When signing a single file, set this to the concrete log file path.
    /// - When only rolling logs are used, point at a consolidated export or use
    ///   [`crate::audit::sign_audit_rolling_directory`].
    #[serde(default)]
    pub log_path: String,
    /// Path to a PEM private key used when [`Self::signing_mode`] is [`AuditSigningMode::Pem`].
    ///
    /// **Payment forbids this** — use `hmac-env` or `provider` instead.
    #[serde(default)]
    pub signing_key_path: Option<String>,
    /// Attestation backend for audit segments (default: none).
    #[serde(default)]
    pub signing_mode: AuditSigningMode,
    /// Env var holding the HMAC key when `signing_mode = "hmac-env"`.
    /// Defaults to `IRONCRYPT_AUDIT_HMAC_KEY` when unset.
    #[serde(default)]
    pub signing_hmac_env: Option<String>,
    /// CryptoProvider key id when `signing_mode = "provider"`.
    #[serde(default)]
    pub signing_key_id: Option<String>,
    /// Retain rolling `audit.log*` segments for this many days (0 = no auto-purge).
    #[serde(default)]
    pub retention_days: u32,
}

impl AuditConfig {
    /// Directory used for rolling audit appenders.
    pub fn rolling_directory(&self) -> &str {
        if !self.audit_directory.is_empty() {
            &self.audit_directory
        } else {
            &self.log_path
        }
    }

    /// Env var name for the HMAC audit key.
    pub fn hmac_env_name(&self) -> &str {
        self.signing_hmac_env
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("IRONCRYPT_AUDIT_HMAC_KEY")
    }

    /// Effective signing mode (infers `pem` if only `signing_key_path` is set).
    pub fn effective_signing_mode(&self) -> AuditSigningMode {
        if self.signing_mode != AuditSigningMode::None {
            return self.signing_mode;
        }
        if self.signing_key_path.is_some() {
            AuditSigningMode::Pem
        } else {
            AuditSigningMode::None
        }
    }

    /// Reject Payment-unsafe audit signing (PEM on disk).
    pub fn ensure_payment_safe(&self) -> Result<(), crate::IronCryptError> {
        match self.effective_signing_mode() {
            AuditSigningMode::Pem => Err(crate::IronCryptError::ConfigurationError(
                "Payment profile forbids PEM audit signing keys on disk; \
                 set audit.signing_mode = \"hmac-env\" (IRONCRYPT_AUDIT_HMAC_KEY) \
                 or \"provider\" with signing_key_id (KMS/HSM CryptoProvider)"
                    .into(),
            )),
            AuditSigningMode::HmacEnv | AuditSigningMode::Provider | AuditSigningMode::None => {
                Ok(())
            }
        }
    }
}

/// Configuration for Google Cloud Secret Manager.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GoogleConfig {
    /// The Google Cloud project ID.
    pub project_id: String,
}

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

/// Configuration for AWS KMS as a [`crate::CryptoProvider`].
///
/// Credentials must come from the environment / IAM role / instance profile —
/// never embed static access keys in this TOML.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AwsKmsConfig {
    /// AWS region (e.g. `eu-west-1`).
    pub region: String,
    /// Default KMS key id or ARN used when callers pass an empty `key_id`.
    pub default_key_id: String,
}

/// Configuration for HashiCorp Vault Transit as a [`crate::CryptoProvider`].
///
/// Prefer AppRole / Kubernetes / workload identity over long-lived tokens in
/// production (see PAYMENT_SECURITY.md).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VaultTransitConfig {
    /// Vault server address (e.g. `https://vault.internal:8200`).
    pub address: String,
    /// Auth token (short-lived). Prefer env / AppRole / K8s auth over embedding here.
    #[serde(default)]
    pub token: String,
    /// Transit secrets engine mount path.
    #[serde(default = "default_transit_mount")]
    pub mount: String,
    /// AppRole auth mount (default `approle`). Used when `VAULT_ROLE_ID`+`VAULT_SECRET_ID` are set.
    #[serde(default = "default_approle_mount")]
    pub approle_mount: String,
    /// Kubernetes auth mount (default `kubernetes`). Used when `VAULT_K8S_ROLE` is set.
    #[serde(default = "default_k8s_mount")]
    pub kubernetes_mount: String,
}

fn default_transit_mount() -> String {
    "transit".to_string()
}

fn default_approle_mount() -> String {
    "approle".to_string()
}

fn default_k8s_mount() -> String {
    "kubernetes".to_string()
}

/// Configuration for Azure Key Vault Keys as a [`crate::CryptoProvider`].
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AzureKmsConfig {
    /// Vault URI (e.g. `https://myvault.vault.azure.net/`).
    pub vault_uri: String,
    /// Default key name used when callers pass an empty `key_id`.
    pub default_key_name: String,
}

/// Configuration for Google Cloud KMS as a [`crate::CryptoProvider`].
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GcpKmsConfig {
    /// Full CryptoKey resource name
    /// (`projects/.../locations/.../keyRings/.../cryptoKeys/...`).
    pub default_key_name: String,
}

/// Selects which [`crate::CryptoProvider`] backend to construct.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CryptoProviderConfig {
    /// Backend name: `aws-kms`, `azure-kms`, `gcp-kms`, `vault-transit`, `hsm`, or `local`.
    pub provider: String,
    #[serde(default)]
    pub aws_kms: Option<AwsKmsConfig>,
    #[serde(default)]
    pub azure_kms: Option<AzureKmsConfig>,
    #[serde(default)]
    pub gcp_kms: Option<GcpKmsConfig>,
    #[cfg(feature = "vault")]
    #[serde(default)]
    pub vault_transit: Option<VaultTransitConfig>,
    #[cfg(feature = "hsm")]
    #[serde(default)]
    pub hsm: Option<HsmCryptoConfig>,
    /// Ordered standby backends ([`crate::crypto_provider::HaCryptoProvider`]).
    /// Standbys must unwrap ciphertexts produced by the primary (multi-region /
    /// replicated key material). Nested `failover` lists are rejected.
    #[serde(default)]
    pub failover: Vec<CryptoProviderConfig>,
}

/// Configuration for a PKCS#11 Hardware Security Module.
///
/// Used by the legacy secrets map and by [`HsmCryptoConfig`]. Prefer configuring
/// `[crypto_provider.hsm]` for in-device wrap/unwrap.
#[cfg(feature = "hsm")]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HsmConfig {
    /// Path to the PKCS#11 module (`.so`/`.dll`) to load.
    pub module_path: String,
    /// Label of the token/slot to use.
    pub token_label: String,
    /// Optional PIN (prefer `IRONCRYPT_HSM_PIN` env in production).
    #[serde(default)]
    pub pin: Option<String>,
}

/// PKCS#11 settings for [`crate::crypto_provider::HsmProvider`].
#[cfg(feature = "hsm")]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HsmCryptoConfig {
    /// Path to the PKCS#11 module (`.so`/`.dll`) to load.
    pub module_path: String,
    /// Label of the token/slot to use.
    pub token_label: String,
    /// Default AES secret-key label used when `key_id` is empty.
    pub default_key_label: String,
    /// Optional PIN (prefer `IRONCRYPT_HSM_PIN` env — never commit production PINs).
    #[serde(default)]
    pub pin: Option<String>,
    /// Max concurrent logged-in PKCS#11 sessions (default 4, cap 32). `0` → default.
    #[serde(default)]
    pub max_sessions: u32,
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

#[cfg(feature = "vault")]
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
///     crypto_provider: None,
///     data_type_config: None,
///     audit: None,
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
    /// Configuration for the cryptographic key provider (KMS / Transit / local).
    /// Distinct from [`SecretsConfig`]: this performs crypto ops, it does not
    /// store opaque application secrets.
    #[serde(default)]
    pub crypto_provider: Option<CryptoProviderConfig>,
    /// Configuration for data type specific key management.
    #[serde(default)]
    pub data_type_config: Option<DataTypeConfig>,
    /// Configuration for auditing.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

impl IronCryptConfig {
    /// Loads configuration from a TOML file.
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }
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
            crypto_provider: None,
            data_type_config: None,
            audit: None,
        }
    }
}