//! Azure Key Vault Keys [`CryptoProvider`] (wrap / unwrap via REST).
//!
//! Private key material never leaves the vault. Auth uses
//! [`azure_identity::DefaultAzureCredential`] (managed identity / Azure CLI / env).

use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_identity::DefaultAzureCredential;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    config::AzureKmsConfig,
    crypto_provider::{CryptoProvider, WrappedKey},
    IronCryptError,
};

const API_VERSION: &str = "7.4";
const WRAP_ALG: &str = "RSA-OAEP-256";

/// Azure Key Vault / Managed HSM keys backend.
pub struct AzureKeyVaultKeysProvider {
    vault_uri: String,
    default_key_name: String,
    credential: Arc<dyn TokenCredential>,
    http: reqwest::Client,
}

impl AzureKeyVaultKeysProvider {
    pub async fn new(config: &AzureKmsConfig) -> Result<Self, IronCryptError> {
        if config.vault_uri.trim().is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "AzureKmsConfig.vault_uri must be set (e.g. https://myvault.vault.azure.net/)"
                    .into(),
            ));
        }
        if config.default_key_name.trim().is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "AzureKmsConfig.default_key_name must be set".into(),
            ));
        }
        let credential: Arc<dyn TokenCredential> = DefaultAzureCredential::new().map_err(|e| {
            IronCryptError::ConfigurationError(format!("Azure credential: {e}"))
        })?;
        Ok(Self {
            vault_uri: config.vault_uri.trim_end_matches('/').to_string(),
            default_key_name: config.default_key_name.clone(),
            credential,
            http: reqwest::Client::new(),
        })
    }

    fn resolve_key<'a>(&'a self, key_id: &'a str) -> &'a str {
        if key_id.trim().is_empty() {
            self.default_key_name.as_str()
        } else {
            key_id
        }
    }

    async fn bearer(&self) -> Result<String, IronCryptError> {
        let token = self
            .credential
            .get_token(&["https://vault.azure.net/.default"], None)
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("azure-kms token: {e}")))?;
        Ok(token.token.secret().to_string())
    }

    async fn wrap_unwrap(
        &self,
        key_name: &str,
        op: &str,
        value_b64url: &str,
    ) -> Result<String, IronCryptError> {
        let url = format!(
            "{}/keys/{}/{}?api-version={}",
            self.vault_uri, key_name, op, API_VERSION
        );
        let body = WrapBody {
            alg: WRAP_ALG.to_string(),
            value: value_b64url.to_string(),
        };
        let token = self.bearer().await?;
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("azure-kms {op} http: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(IronCryptError::ProviderError(format!(
                "azure-kms {op}: HTTP {status}: {text}"
            )));
        }
        let parsed: WrapResponse = resp
            .json()
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("azure-kms {op} json: {e}")))?;
        Ok(parsed.value)
    }
}

#[derive(Serialize)]
struct WrapBody {
    alg: String,
    value: String,
}

#[derive(Deserialize)]
struct WrapResponse {
    value: String,
}

#[async_trait]
impl CryptoProvider for AzureKeyVaultKeysProvider {
    fn name(&self) -> &'static str {
        "azure-kms"
    }

    fn private_material_exportable(&self) -> bool {
        false
    }

    async fn wrap_key(
        &self,
        key_id: &str,
        plaintext_key: &[u8],
    ) -> Result<WrappedKey, IronCryptError> {
        let kid = self.resolve_key(key_id);
        let value = URL_SAFE_NO_PAD.encode(plaintext_key);
        let wrapped = self.wrap_unwrap(kid, "wrapkey", &value).await?;
        Ok(WrappedKey {
            key_id: kid.to_string(),
            ciphertext: URL_SAFE_NO_PAD
                .decode(wrapped.as_bytes())
                .or_else(|_| B64.decode(wrapped.as_bytes()))
                .map_err(|e| IronCryptError::ProviderError(format!("azure-kms wrap decode: {e}")))?,
        })
    }

    async fn unwrap_key(
        &self,
        key_id: &str,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        let kid = self.resolve_key(key_id);
        let value = URL_SAFE_NO_PAD.encode(wrapped);
        let plain_b64 = self.wrap_unwrap(kid, "unwrapkey", &value).await?;
        URL_SAFE_NO_PAD
            .decode(plain_b64.as_bytes())
            .or_else(|_| B64.decode(plain_b64.as_bytes()))
            .map_err(|e| IronCryptError::ProviderError(format!("azure-kms unwrap decode: {e}")))
    }

    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        if aad.map(|a| !a.is_empty()).unwrap_or(false) {
            return Err(IronCryptError::UnsupportedOperation(
                "azure-kms: AAD is not supported by Key Vault wrap/encrypt REST used here; \
                 omit aad or use aws-kms / vault-transit"
                    .into(),
            ));
        }
        // Key Vault encrypt uses the same wrap-style endpoint with encrypt op for RSA keys.
        let kid = self.resolve_key(key_id);
        let value = URL_SAFE_NO_PAD.encode(plaintext);
        let ct = self.wrap_unwrap(kid, "encrypt", &value).await?;
        URL_SAFE_NO_PAD
            .decode(ct.as_bytes())
            .or_else(|_| B64.decode(ct.as_bytes()))
            .map_err(|e| IronCryptError::ProviderError(format!("azure-kms encrypt decode: {e}")))
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        if aad.map(|a| !a.is_empty()).unwrap_or(false) {
            return Err(IronCryptError::UnsupportedOperation(
                "azure-kms: AAD is not supported by Key Vault wrap/encrypt REST used here"
                    .into(),
            ));
        }
        let kid = self.resolve_key(key_id);
        let value = URL_SAFE_NO_PAD.encode(ciphertext);
        let pt = self.wrap_unwrap(kid, "decrypt", &value).await?;
        URL_SAFE_NO_PAD
            .decode(pt.as_bytes())
            .or_else(|_| B64.decode(pt.as_bytes()))
            .map_err(|e| IronCryptError::ProviderError(format!("azure-kms decrypt decode: {e}")))
    }
}
