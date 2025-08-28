use crate::config::GoogleConfig;
use async_trait::async_trait;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use google_cloud_secretmanager_v1::model::{
    Secret, SecretPayload, Replication, replication::Automatic,
};
use std::error::Error;

use super::SecretStore;

/// A secret store that uses Google Cloud Secret Manager.
/// 
/// This implementation provides secure secret storage and retrieval using Google Cloud's
/// Secret Manager service. It automatically handles secret creation with default replication
/// settings and manages secret versions.
/// 
/// # Authentication
/// 
/// This implementation uses the default Google Cloud authentication methods:
/// - Service Account keys (via GOOGLE_APPLICATION_CREDENTIALS environment variable)
/// - Application Default Credentials (ADC)
/// - Google Cloud Shell credentials
/// - gcloud user credentials
/// 
/// # Example
/// 
/// ```rust,no_run
/// use ironcrypt::secrets::google::GoogleStore;
/// use ironcrypt::config::GoogleConfig;
/// 
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = GoogleConfig {
///     project_id: "my-project-id".to_string(),
/// };
/// 
/// let store = GoogleStore::new(&config).await?;
/// store.set_secret("my-secret", "secret-value").await?;
/// let value = store.get_secret("my-secret").await?;
/// # Ok(())
/// # }
/// ```
pub struct GoogleStore {
    client: SecretManagerService,
    project_id: String,
}

impl GoogleStore {
    /// Creates a new `GoogleStore`.
    pub async fn new(config: &GoogleConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Use default credentials from the environment
        let client = SecretManagerService::builder().build().await?;
        Ok(Self {
            client,
            project_id: config.project_id.clone(),
        })
    }
}

#[async_trait]
impl SecretStore for GoogleStore {
    async fn get_secret(&self, key: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let version_name = format!(
            "projects/{}/secrets/{}/versions/latest",
            self.project_id, key
        );
        
        let response = self.client
            .access_secret_version()
            .set_name(version_name)
            .send()
            .await?;
            
        let payload = response.payload.ok_or("Secret payload is empty")?;
        let data = payload.data;
        Ok(String::from_utf8(data.to_vec())?)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let secret_name = format!("projects/{}/secrets/{}", self.project_id, key);

        // Check if the secret exists.
        let get_result = self.client
            .get_secret()
            .set_name(secret_name.clone())
            .send()
            .await;

        if get_result.is_err() {
            // Secret does not exist, create it.
            let parent = format!("projects/{}", self.project_id);
            let mut secret = Secret::default();
            // Set automatic replication for the secret
            let replication = Replication::new()
                .set_automatic(Box::new(Automatic::default()));
            secret.replication = Some(replication);
            
            self.client
                .create_secret()
                .set_parent(parent)
                .set_secret_id(key)
                .set_secret(secret)
                .send()
                .await?;
        }

        // Add a new version to the secret.
        let payload = SecretPayload::new()
            .set_data(value.as_bytes().to_vec());
        
        self.client
            .add_secret_version()
            .set_parent(secret_name)
            .set_payload(payload)
            .send()
            .await?;
        Ok(())
    }
}
