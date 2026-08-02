use crate::config::AzureConfig;
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_security_keyvault_secrets::{models::SetSecretParameters, SecretClient};
use std::error::Error;

use super::SecretStore;

/// A secret store that uses Azure Key Vault.
pub struct AzureStore {
    client: SecretClient,
}

impl AzureStore {
    /// Creates a new `AzureStore`.
    pub async fn new(config: &AzureConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let credential = DefaultAzureCredential::new()?;
        let client = SecretClient::new(&config.vault_uri, credential, None)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl SecretStore for AzureStore {
    async fn get_secret(&self, key: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let response = self.client.get_secret(key, "", None).await?;
        let secret = response.into_body().await?;
        Ok(secret.value.ok_or("Secret value is empty")?)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let params = SetSecretParameters {
            value: Some(value.to_string()),
            ..Default::default()
        };
        self.client
            .set_secret(key, params.try_into()?, None)
            .await?;
        Ok(())
    }
}
