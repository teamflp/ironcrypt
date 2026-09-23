//! Legacy HSM SecretStore — disabled.
//!
//! The previous PKCS#11 `0.2` backend only returned object handles as strings and
//! never performed in-HSM crypto. Use [`crate::crypto_provider::HsmProvider`]
//! (`CryptoProvider`) instead.

use crate::config::HsmConfig;
use async_trait::async_trait;
use std::error::Error;
use super::super::SecretStore;

/// Placeholder kept so existing `secrets.provider = "hsm"` configs fail loudly
/// with a migration message instead of silently locating handles.
pub struct HsmSecretStore {
    _config: HsmConfig,
}

impl HsmSecretStore {
    pub fn new(config: HsmConfig) -> Self {
        Self { _config: config }
    }
}

#[async_trait]
impl SecretStore for HsmSecretStore {
    async fn get_secret(&self, _key: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        Err("HSM SecretStore is removed: configure crypto_provider.provider = \"hsm\" \
             (HsmProvider) so wrap/unwrap/encrypt/decrypt run in-device. \
             See PAYMENT_SECURITY.md."
            .into())
    }

    async fn set_secret(&self, _key: &str, _value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        Err("HSM SecretStore is removed: provision keys on the HSM and use HsmProvider."
            .into())
    }
}
