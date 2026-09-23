//! Cryptographic key providers that perform operations without exporting private keys.
//!
//! This is intentionally separate from [`crate::secrets::SecretStore`], which stores
//! opaque secret *values*. A `CryptoProvider` wraps/unwraps data encryption keys
//! (and related operations) inside a local process, HSM, or cloud KMS.

use async_trait::async_trait;
use crate::config::CryptoProviderConfig;
use crate::IronCryptError;

pub mod context;
pub mod ha;
pub mod local;

#[cfg(feature = "aws-kms")]
pub mod aws_kms;
#[cfg(feature = "azure-kms")]
pub mod azure_kms;
#[cfg(feature = "gcp-kms")]
pub mod gcp_kms;
#[cfg(feature = "hsm")]
pub mod hsm;
#[cfg(feature = "vault")]
pub mod vault_transit;

pub use ha::HaCryptoProvider;
pub use local::LocalKeyProvider;

#[cfg(feature = "aws-kms")]
pub use aws_kms::AwsKmsProvider;
#[cfg(feature = "azure-kms")]
pub use azure_kms::AzureKeyVaultKeysProvider;
#[cfg(feature = "gcp-kms")]
pub use gcp_kms::GcpKmsProvider;
#[cfg(feature = "hsm")]
pub use hsm::HsmProvider;
#[cfg(feature = "vault")]
pub use vault_transit::VaultTransitProvider;

/// Result of a key-wrap operation performed by a [`CryptoProvider`].
#[derive(Debug, Clone)]
pub struct WrappedKey {
    /// Provider-specific key identifier (never a raw private key).
    pub key_id: String,
    /// Opaque ciphertext produced by the provider.
    pub ciphertext: Vec<u8>,
}

/// Backend that can perform cryptographic operations with keys that must not leave
/// the trust boundary of the provider (HSM/KMS) when remote.
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Human-readable backend name (`local`, `aws-kms`, `vault-transit`, …).
    fn name(&self) -> &'static str;

    /// `true` only for development backends that hold exportable private key material
    /// in-process. Production Payment profiles must reject exportable providers.
    fn private_material_exportable(&self) -> bool;

    /// Wrap (encrypt) a data-encryption key under `key_id`.
    async fn wrap_key(
        &self,
        key_id: &str,
        plaintext_key: &[u8],
    ) -> Result<WrappedKey, IronCryptError>;

    /// Unwrap (decrypt) a previously wrapped data-encryption key.
    ///
    /// The returned plaintext should be zeroized by the caller after use.
    async fn unwrap_key(
        &self,
        key_id: &str,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, IronCryptError>;

    /// Encrypt arbitrary bytes under `key_id`, optionally binding `aad`.
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError>;

    /// Decrypt ciphertext produced by [`CryptoProvider::encrypt`].
    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError>;
}

/// Validate provider selection before construction (Payment-safe checks).
pub fn validate_provider_config(
    config: &CryptoProviderConfig,
    payment_locked: bool,
) -> Result<(), IronCryptError> {
    validate_one_provider(&config.provider, payment_locked)?;
    for (i, fb) in config.failover.iter().enumerate() {
        if !fb.failover.is_empty() {
            return Err(IronCryptError::ConfigurationError(format!(
                "crypto_provider.failover[{i}]: nested failover is not supported"
            )));
        }
        validate_one_provider(&fb.provider, payment_locked)?;
    }
    Ok(())
}

fn validate_one_provider(provider: &str, payment_locked: bool) -> Result<(), IronCryptError> {
    let name = provider.trim().to_ascii_lowercase();
    match name.as_str() {
        "aws-kms" | "vault-transit" | "hsm" | "azure-kms" | "gcp-kms" => Ok(()),
        "local" => {
            if payment_locked {
                Err(IronCryptError::ConfigurationError(
                    "Payment profile forbids exportable `local` CryptoProvider; \
                     use aws-kms, azure-kms, gcp-kms, vault-transit, or hsm"
                        .into(),
                ))
            } else {
                Ok(())
            }
        }
        "" => Err(IronCryptError::ConfigurationError(
            "crypto_provider.provider must be set \
             (aws-kms | azure-kms | gcp-kms | vault-transit | hsm | local)"
                .into(),
        )),
        other => Err(IronCryptError::ConfigurationError(format!(
            "unknown crypto_provider.provider '{other}' \
             (expected aws-kms | azure-kms | gcp-kms | vault-transit | hsm | local)"
        ))),
    }
}

/// Construct a [`CryptoProvider`] from configuration.
///
/// When `failover` is non-empty, wraps primary + standbys in [`HaCryptoProvider`].
///
/// - `aws-kms` requires the `aws-kms` Cargo feature
/// - `vault-transit` requires the `vault` Cargo feature
/// - `local` is **not** built here (needs in-process key material); use
///   [`LocalKeyProvider::new`] explicitly in development code
pub async fn build_from_config(
    config: &CryptoProviderConfig,
) -> Result<Box<dyn CryptoProvider>, IronCryptError> {
    validate_provider_config(config, crate::payment::PaymentSecurityProfile::is_enabled())?;

    let primary = build_one(config).await?;
    if config.failover.is_empty() {
        return Ok(primary);
    }

    use std::sync::Arc;
    let mut providers: Vec<Arc<dyn CryptoProvider>> = Vec::with_capacity(1 + config.failover.len());
    providers.push(Arc::from(primary));
    for fb in &config.failover {
        providers.push(Arc::from(build_one(fb).await?));
    }
    Ok(Box::new(HaCryptoProvider::new(providers)?))
}

async fn build_one(
    config: &CryptoProviderConfig,
) -> Result<Box<dyn CryptoProvider>, IronCryptError> {
    match config.provider.trim().to_ascii_lowercase().as_str() {
        #[cfg(feature = "aws-kms")]
        "aws-kms" => {
            let kms = config.aws_kms.as_ref().ok_or_else(|| {
                IronCryptError::ConfigurationError(
                    "crypto_provider.aws_kms is required when provider = \"aws-kms\"".into(),
                )
            })?;
            let provider = AwsKmsProvider::new(kms).await?;
            Ok(Box::new(provider))
        }
        #[cfg(not(feature = "aws-kms"))]
        "aws-kms" => Err(IronCryptError::ConfigurationError(
            "aws-kms provider requested but crate built without feature `aws-kms`".into(),
        )),

        #[cfg(feature = "azure-kms")]
        "azure-kms" => {
            let az = config.azure_kms.as_ref().ok_or_else(|| {
                IronCryptError::ConfigurationError(
                    "crypto_provider.azure_kms is required when provider = \"azure-kms\"".into(),
                )
            })?;
            let provider = AzureKeyVaultKeysProvider::new(az).await?;
            Ok(Box::new(provider))
        }
        #[cfg(not(feature = "azure-kms"))]
        "azure-kms" => Err(IronCryptError::ConfigurationError(
            "azure-kms provider requested but crate built without feature `azure-kms`".into(),
        )),

        #[cfg(feature = "gcp-kms")]
        "gcp-kms" => {
            let gcp = config.gcp_kms.as_ref().ok_or_else(|| {
                IronCryptError::ConfigurationError(
                    "crypto_provider.gcp_kms is required when provider = \"gcp-kms\"".into(),
                )
            })?;
            let provider = GcpKmsProvider::new(gcp).await?;
            Ok(Box::new(provider))
        }
        #[cfg(not(feature = "gcp-kms"))]
        "gcp-kms" => Err(IronCryptError::ConfigurationError(
            "gcp-kms provider requested but crate built without feature `gcp-kms`".into(),
        )),

        #[cfg(feature = "vault")]
        "vault-transit" => {
            let vt = config.vault_transit.as_ref().ok_or_else(|| {
                IronCryptError::ConfigurationError(
                    "crypto_provider.vault_transit is required when provider = \"vault-transit\""
                        .into(),
                )
            })?;
            let provider = VaultTransitProvider::new(vt).await?;
            Ok(Box::new(provider))
        }
        #[cfg(not(feature = "vault"))]
        "vault-transit" => Err(IronCryptError::ConfigurationError(
            "vault-transit provider requested but crate built without feature `vault`".into(),
        )),

        #[cfg(feature = "hsm")]
        "hsm" => {
            let hsm = config.hsm.as_ref().ok_or_else(|| {
                IronCryptError::ConfigurationError(
                    "crypto_provider.hsm is required when provider = \"hsm\"".into(),
                )
            })?;
            let provider = HsmProvider::new(hsm)?;
            Ok(Box::new(provider))
        }
        #[cfg(not(feature = "hsm"))]
        "hsm" => Err(IronCryptError::ConfigurationError(
            "hsm provider requested but crate built without feature `hsm`".into(),
        )),

        "local" => Err(IronCryptError::ConfigurationError(
            "provider \"local\" must be constructed via LocalKeyProvider::new (not build_from_config)"
                .into(),
        )),
        other => Err(IronCryptError::ConfigurationError(format!(
            "unknown crypto provider '{other}'"
        ))),
    }
}
