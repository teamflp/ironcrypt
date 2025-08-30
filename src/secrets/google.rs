use crate::config::GoogleConfig;
use crate::secrets::SecretStore;
use async_trait::async_trait;
use google_cloud_secretmanager_v1::{
    client::{Client, ClientConfig},
    model::{
        AccessSecretVersionRequest, AddSecretVersionRequest, CreateSecretRequest, Replication,
        Automatic, Secret, SecretPayload,
    },
};
use std::error::Error;

/// A secret store that uses Google Cloud Secret Manager.
pub struct GoogleStore {
    client: Client,
    project_id: String,
}

impl GoogleStore {
    /// Creates a new `GoogleStore`.
    pub async fn new(config: &GoogleConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Assume the client can be created with a default config that handles auth automatically.
        let client_config = ClientConfig::default().with_auth().await?;
        let client = Client::new(client_config);
        Ok(Self {
            client,
            project_id: config.project_id.clone(),
        })
    }
}

#[async_trait]
impl SecretStore for GoogleStore {
    async fn get_secret(&self, key: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let request = AccessSecretVersionRequest {
            name: format!(
                "projects/{}/secrets/{}/versions/latest",
                self.project_id, key
            ),
            ..Default::default()
        };

        let response = self.client.access_secret_version(request).await?;
        let payload = response.payload.ok_or("Secret payload is empty")?;
        let data = payload.data.ok_or("Secret data is empty")?;
        Ok(String::from_utf8(data)?)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let parent = format!("projects/{}", self.project_id);
        let name = format!("{}/secrets/{}", parent, key);

        // Check if the secret exists. If not, create it.
        if self.client.get_secret(&name).await.is_err() {
            let create_request = CreateSecretRequest {
                parent,
                secret_id: key.to_string(),
                secret: Secret {
                    replication: Some(Replication {
                        replication: Some(
                            google_cloud_secretmanager_v1::model::replication::Replication::Automatic(
                                Automatic::default(),
                            ),
                        ),
                    }),
                    ..Default::default()
                },
                ..Default::default()
            };
            self.client.create_secret(create_request).await?;
        }

        let add_version_request = AddSecretVersionRequest {
            parent: name,
            payload: Some(SecretPayload {
                data: Some(value.as_bytes().to_vec()),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.client.add_secret_version(add_version_request).await?;
        Ok(())
    }
}
