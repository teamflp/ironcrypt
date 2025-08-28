use crate::config::GoogleConfig;
use async_trait::async_trait;
use google_cloud_auth::project::Config;
use google_cloud_auth::token::DefaultTokenSource;
use google_cloud_secretmanager_v1::api::{
    AccessSecretVersionRequest, AddSecretVersionRequest, CreateSecretRequest, GetSecretRequest,
    Replication, Secret, SecretPayload,
};
use google_cloud_secretmanager_v1::SecretManagerClient;
use std::error::Error;
use std::sync::Arc;

use super::SecretStore;

/// A secret store that uses Google Cloud Secret Manager.
pub struct GoogleStore {
    client: SecretManagerClient,
    project_id: String,
}

impl GoogleStore {
    /// Creates a new `GoogleStore`.
    pub async fn new(config: &GoogleConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let ts = Arc::new(
            DefaultTokenSource::new(Config {
                audience: None,
                scopes: Some(&["https://www.googleapis.com/auth/cloud-platform"]),
            })
            .await?,
        );
        let client = SecretManagerClient::new(ts).await?;
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
        let request = AccessSecretVersionRequest {
            name: version_name,
            ..Default::default()
        };
        let response = self.client.access_secret_version(request).await?;
        let payload = response.payload.ok_or("Secret payload is empty")?;
        let data = payload.data.ok_or("Secret data is empty")?;
        Ok(String::from_utf8(data)?)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let secret_name = format!("projects/{}/secrets/{}", self.project_id, key);

        // Check if the secret exists.
        let get_request = GetSecretRequest {
            name: secret_name.clone(),
            ..Default::default()
        };

        if self.client.get_secret(get_request).await.is_err() {
            // Secret does not exist, create it.
            let create_request = CreateSecretRequest {
                parent: format!("projects/{}", self.project_id),
                secret_id: key.to_string(),
                secret: Some(Secret {
                    replication: Some(Replication {
                        replication: Some(
                            google_cloud_secretmanager_v1::api::replication::Replication::Automatic(
                                google_cloud_secretmanager_v1::api::Automatic::default(),
                            ),
                        ),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            self.client.create_secret(create_request).await?;
        }

        // Add a new version to the secret.
        let add_version_request = AddSecretVersionRequest {
            parent: secret_name,
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
