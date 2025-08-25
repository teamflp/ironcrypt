use crate::config::AwsConfig;
use async_trait::async_trait;
use aws_config::{meta::region::RegionProviderChain, Region};
use aws_sdk_secretsmanager::{error::SdkError, Client};
use std::error::Error;

use super::SecretStore;

/// A secret store that uses AWS Secrets Manager.
pub struct AwsStore {
    client: Client,
}

impl AwsStore {
    /// Creates a new `AwsStore`.
    pub async fn new(config: &AwsConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let region = Region::new(config.region.clone());
        let region_provider = RegionProviderChain::first_try(region).or_default_provider();
        let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;
        let client = Client::new(&shared_config);
        Ok(Self { client })
    }
}

#[async_trait]
impl SecretStore for AwsStore {
    async fn get_secret(&self, key: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let resp = self
            .client
            .get_secret_value()
            .secret_id(key)
            .send()
            .await?;
        let secret = resp.secret_string().ok_or("Secret string is empty")?;
        Ok(secret.to_string())
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        match self
            .client
            .put_secret_value()
            .secret_id(key)
            .secret_string(value)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(SdkError::ServiceError(service_err)) => {
                if service_err.err().is_resource_not_found_exception() {
                    self.client
                        .create_secret()
                        .name(key)
                        .secret_string(value)
                        .send()
                        .await?;
                    Ok(())
                } else {
                    Err(Box::from(format!("{:?}", service_err)))
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}
