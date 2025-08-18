use async_trait::async_trait;
use std::error::Error;

pub mod aws;
pub mod azure;
// pub mod google; // TODO: Disabled due to compilation errors after dependency update.
pub mod vault;

/// A trait for a generic secret store.
///
/// This trait defines a common interface for interacting with different secret
/// management systems, such as HashiCorp Vault, AWS Secrets Manager, etc.
#[async_trait]
pub trait SecretStore {
    /// Retrieves a secret from the store.
    ///
    /// # Arguments
    ///
    /// * `key` - The identifier for the secret to retrieve.
    async fn get_secret(&self, key: &str) -> Result<String, Box<dyn Error + Send + Sync>>;

    /// Stores a secret in the store.
    ///
    /// # Arguments
    ///
    /// * `key` - The identifier for the secret to store.
    /// * `value` - The secret value to store.
    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>>;
}
