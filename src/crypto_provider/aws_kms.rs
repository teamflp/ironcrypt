//! AWS KMS [`CryptoProvider`] — private keys never leave KMS.

use async_trait::async_trait;
use aws_config::{meta::region::RegionProviderChain, Region};
use aws_sdk_kms::{primitives::Blob, Client};
use std::collections::HashMap;

use crate::{
    config::AwsKmsConfig,
    crypto_provider::{context::kms_encryption_context, CryptoProvider, WrappedKey},
    IronCryptError,
};

/// AWS Key Management Service backend.
///
/// Uses IAM credentials from the default chain (env, shared config, instance
/// profile, IRSA, etc.). No static access keys belong in `AwsKmsConfig`.
pub struct AwsKmsProvider {
    client: Client,
    default_key_id: String,
}

impl AwsKmsProvider {
    /// Build a provider from configuration (loads the AWS default credential chain).
    pub async fn new(config: &AwsKmsConfig) -> Result<Self, IronCryptError> {
        if config.default_key_id.trim().is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "AwsKmsConfig.default_key_id must be set (key id or ARN)".into(),
            ));
        }
        let region = Region::new(config.region.clone());
        let region_provider = RegionProviderChain::first_try(region).or_default_provider();
        let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;
        Ok(Self {
            client: Client::new(&shared),
            default_key_id: config.default_key_id.clone(),
        })
    }

    /// Construct from an already-configured SDK client (tests / advanced wiring).
    pub fn from_client(client: Client, default_key_id: impl Into<String>) -> Self {
        Self {
            client,
            default_key_id: default_key_id.into(),
        }
    }

    fn resolve_key_id<'a>(&'a self, key_id: &'a str) -> Result<&'a str, IronCryptError> {
        let id = if key_id.is_empty() {
            self.default_key_id.as_str()
        } else {
            key_id
        };
        if id.is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "AWS KMS key_id is empty".into(),
            ));
        }
        Ok(id)
    }

    fn map_err(op: &str, err: impl std::fmt::Display) -> IronCryptError {
        IronCryptError::ProviderError(format!("aws-kms {op}: {err}"))
    }

    async fn encrypt_raw(
        &self,
        key_id: &str,
        plaintext: &[u8],
        context: HashMap<String, String>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let mut req = self
            .client
            .encrypt()
            .key_id(key_id)
            .plaintext(Blob::new(plaintext));
        for (k, v) in context {
            req = req.encryption_context(k, v);
        }
        let resp = req.send().await.map_err(|e| Self::map_err("encrypt", e))?;
        let blob = resp
            .ciphertext_blob
            .ok_or_else(|| IronCryptError::ProviderError("aws-kms encrypt: empty ciphertext".into()))?;
        Ok(blob.into_inner())
    }

    async fn decrypt_raw(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        context: HashMap<String, String>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let mut req = self
            .client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(Blob::new(ciphertext));
        for (k, v) in context {
            req = req.encryption_context(k, v);
        }
        let resp = req.send().await.map_err(|e| Self::map_err("decrypt", e))?;
        let blob = resp
            .plaintext
            .ok_or_else(|| IronCryptError::ProviderError("aws-kms decrypt: empty plaintext".into()))?;
        Ok(blob.into_inner())
    }
}

#[async_trait]
impl CryptoProvider for AwsKmsProvider {
    fn name(&self) -> &'static str {
        "aws-kms"
    }

    fn private_material_exportable(&self) -> bool {
        false
    }

    async fn wrap_key(
        &self,
        key_id: &str,
        plaintext_key: &[u8],
    ) -> Result<WrappedKey, IronCryptError> {
        let kid = self.resolve_key_id(key_id)?;
        let ciphertext = self
            .encrypt_raw(kid, plaintext_key, kms_encryption_context(None))
            .await?;
        Ok(WrappedKey {
            key_id: kid.to_string(),
            ciphertext,
        })
    }

    async fn unwrap_key(
        &self,
        key_id: &str,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        let kid = self.resolve_key_id(key_id)?;
        self.decrypt_raw(kid, wrapped, kms_encryption_context(None))
            .await
    }

    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let kid = self.resolve_key_id(key_id)?;
        self.encrypt_raw(kid, plaintext, kms_encryption_context(aad))
            .await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let kid = self.resolve_key_id(key_id)?;
        self.decrypt_raw(kid, ciphertext, kms_encryption_context(aad))
            .await
    }
}
