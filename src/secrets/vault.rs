use crate::config::VaultConfig;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::error::Error;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

use super::SecretStore;

/// A simple struct to store a string value in Vault's KV store.
#[derive(Serialize, Deserialize)]
struct SecretData {
    value: String,
}

/// A secret store that uses HashiCorp Vault.
pub struct VaultStore {
    client: VaultClient,
    mount: String,
}

impl VaultStore {
    /// Creates a new `VaultStore`.
    ///
    /// # Arguments
    ///
    /// * `config` - The Vault configuration.
    pub fn new(config: &VaultConfig, mount: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let settings = VaultClientSettingsBuilder::default()
            .address(&config.address)
            .token(&config.token)
            .build()?;

        Ok(Self {
            client: VaultClient::new(settings)?,
            mount: mount.to_string(),
        })
    }
}

#[async_trait]
impl SecretStore for VaultStore {
    async fn get_secret(&self, key: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let result: SecretData =
            vaultrs::kv2::read(&self.client, &self.mount, key).await?;
        Ok(result.value)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let secret = SecretData {
            value: value.to_string(),
        };
        vaultrs::kv2::set(&self.client, &self.mount, key, &secret).await?;
        Ok(())
    }
}
