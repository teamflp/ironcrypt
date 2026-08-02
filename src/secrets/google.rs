use crate::config::GoogleConfig;
use crate::secrets::SecretStore;
use async_trait::async_trait;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use google_cloud_secretmanager_v1::model::replication::Automatic;
use google_cloud_secretmanager_v1::model::{Replication, Secret, SecretPayload};
use std::error::Error;

/// A secret store that uses Google Cloud Secret Manager.
pub struct GoogleStore {
    client: SecretManagerService,
    project_id: String,
}

impl GoogleStore {
    /// Creates a new `GoogleStore`.
    pub async fn new(config: &GoogleConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Uses Application Default Credentials by default.
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
        let name = format!(
            "projects/{}/secrets/{}/versions/latest",
            self.project_id, key
        );

        let response = self.client.access_secret_version().set_name(name).send().await?;
        let payload = response.payload.ok_or("Secret payload is empty")?;
        Ok(String::from_utf8(payload.data.to_vec())?)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let parent = format!("projects/{}", self.project_id);
        let name = format!("{}/secrets/{}", parent, key);

        // Check if the secret exists. If not, create it.
        if self.client.get_secret().set_name(name.clone()).send().await.is_err() {
            self.client
                .create_secret()
                .set_parent(parent)
                .set_secret_id(key)
                .set_secret(
                    Secret::new()
                        .set_replication(Replication::new().set_automatic(Automatic::new())),
                )
                .send()
                .await?;
        }

        self.client
            .add_secret_version()
            .set_parent(name)
            .set_payload(SecretPayload::new().set_data(value.as_bytes().to_vec()))
            .send()
            .await?;
        Ok(())
    }
}
