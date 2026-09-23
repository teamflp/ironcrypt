//! HashiCorp Vault Transit [`CryptoProvider`] — private keys never leave Vault.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::path::Path;
use vaultrs::api::transit::requests::{
    DecryptDataRequestBuilder, EncryptDataRequestBuilder,
};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

use crate::{
    config::VaultTransitConfig,
    crypto_provider::{context::vault_context_b64, CryptoProvider, WrappedKey},
    IronCryptError,
};

/// Vault Transit secrets-engine backend.
pub struct VaultTransitProvider {
    client: VaultClient,
    mount: String,
}

async fn resolve_vault_token_async(config: &VaultTransitConfig) -> Result<String, IronCryptError> {
    if !config.token.trim().is_empty() {
        return Ok(config.token.clone());
    }
    if let Ok(t) = std::env::var("VAULT_TOKEN") {
        if !t.trim().is_empty() {
            return Ok(t);
        }
    }

    let bootstrap = VaultClientSettingsBuilder::default()
        .address(&config.address)
        .token("")
        .build()
        .map_err(|e| IronCryptError::ConfigurationError(format!("vault settings: {e}")))?;
    let bootstrap = VaultClient::new(bootstrap)
        .map_err(|e| IronCryptError::ConfigurationError(format!("vault client: {e}")))?;

    if let (Ok(role_id), Ok(secret_id)) = (
        std::env::var("VAULT_ROLE_ID"),
        std::env::var("VAULT_SECRET_ID"),
    ) {
        if !role_id.is_empty() && !secret_id.is_empty() {
            let mount = if config.approle_mount.trim().is_empty() {
                "approle"
            } else {
                config.approle_mount.as_str()
            };
            let info = vaultrs::auth::approle::login(&bootstrap, mount, &role_id, &secret_id)
                .await
                .map_err(|e| {
                    IronCryptError::ConfigurationError(format!("Vault AppRole login failed: {e}"))
                })?;
            return Ok(info.client_token);
        }
    }

    if let Ok(role) = std::env::var("VAULT_K8S_ROLE") {
        if !role.is_empty() {
            let jwt = if let Ok(j) = std::env::var("VAULT_K8S_JWT") {
                j
            } else {
                let path = std::env::var("VAULT_K8S_JWT_PATH").unwrap_or_else(|_| {
                    "/var/run/secrets/kubernetes.io/serviceaccount/token".into()
                });
                std::fs::read_to_string(Path::new(&path)).map_err(|e| {
                    IronCryptError::ConfigurationError(format!(
                        "read K8s SA token at {path}: {e}"
                    ))
                })?
            };
            let mount = if config.kubernetes_mount.trim().is_empty() {
                "kubernetes"
            } else {
                config.kubernetes_mount.as_str()
            };
            let info = vaultrs::auth::kubernetes::login(&bootstrap, mount, &role, jwt.trim())
                .await
                .map_err(|e| {
                    IronCryptError::ConfigurationError(format!(
                        "Vault Kubernetes login failed: {e}"
                    ))
                })?;
            return Ok(info.client_token);
        }
    }

    Err(IronCryptError::ConfigurationError(
        "Vault Transit auth missing: set token / VAULT_TOKEN, or VAULT_ROLE_ID+VAULT_SECRET_ID \
         (AppRole), or VAULT_K8S_ROLE (Kubernetes auth)"
            .into(),
    ))
}

impl VaultTransitProvider {
    /// Build from config.
    ///
    /// Token resolution: config.token → `VAULT_TOKEN` → AppRole (`VAULT_ROLE_ID`+
    /// `VAULT_SECRET_ID`) → Kubernetes (`VAULT_K8S_ROLE`).
    pub async fn new(config: &VaultTransitConfig) -> Result<Self, IronCryptError> {
        if config.address.trim().is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "VaultTransitConfig.address must be set".into(),
            ));
        }

        let token = resolve_vault_token_async(config).await?;

        let settings = VaultClientSettingsBuilder::default()
            .address(&config.address)
            .token(token)
            .build()
            .map_err(|e| IronCryptError::ConfigurationError(format!("vault settings: {e}")))?;

        let client = VaultClient::new(settings)
            .map_err(|e| IronCryptError::ConfigurationError(format!("vault client: {e}")))?;

        let mount = if config.mount.trim().is_empty() {
            "transit".to_string()
        } else {
            config.mount.clone()
        };

        Ok(Self { client, mount })
    }

    fn map_err(op: &str, err: impl std::fmt::Display) -> IronCryptError {
        IronCryptError::ProviderError(format!("vault-transit {op}: {err}"))
    }

    fn require_key_id(key_id: &str) -> Result<&str, IronCryptError> {
        if key_id.trim().is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "Vault Transit key name (key_id) must not be empty".into(),
            ));
        }
        Ok(key_id)
    }

    async fn encrypt_b64(
        &self,
        key_name: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<String, IronCryptError> {
        let plaintext_b64 = B64.encode(plaintext);
        let mut opts = EncryptDataRequestBuilder::default();
        if let Some(ctx) = vault_context_b64(aad) {
            opts.context(ctx);
        }
        let resp = vaultrs::transit::data::encrypt(
            &self.client,
            &self.mount,
            key_name,
            &plaintext_b64,
            Some(&mut opts),
        )
        .await
        .map_err(|e| Self::map_err("encrypt", e))?;
        Ok(resp.ciphertext)
    }

    async fn decrypt_b64(
        &self,
        key_name: &str,
        ciphertext: &str,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let mut opts = DecryptDataRequestBuilder::default();
        if let Some(ctx) = vault_context_b64(aad) {
            opts.context(ctx);
        }
        let resp = vaultrs::transit::data::decrypt(
            &self.client,
            &self.mount,
            key_name,
            ciphertext,
            Some(&mut opts),
        )
        .await
        .map_err(|e| Self::map_err("decrypt", e))?;
        B64.decode(resp.plaintext.as_bytes())
            .map_err(|e| IronCryptError::ProviderError(format!("vault-transit plaintext b64: {e}")))
    }
}

#[async_trait]
impl CryptoProvider for VaultTransitProvider {
    fn name(&self) -> &'static str {
        "vault-transit"
    }

    fn private_material_exportable(&self) -> bool {
        false
    }

    async fn wrap_key(
        &self,
        key_id: &str,
        plaintext_key: &[u8],
    ) -> Result<WrappedKey, IronCryptError> {
        let name = Self::require_key_id(key_id)?;
        let ct = self.encrypt_b64(name, plaintext_key, None).await?;
        Ok(WrappedKey {
            key_id: name.to_string(),
            ciphertext: ct.into_bytes(),
        })
    }

    async fn unwrap_key(
        &self,
        key_id: &str,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        let name = Self::require_key_id(key_id)?;
        let ciphertext = std::str::from_utf8(wrapped).map_err(|e| {
            IronCryptError::DecryptionError(format!("vault-transit wrapped key utf8: {e}"))
        })?;
        self.decrypt_b64(name, ciphertext, None).await
    }

    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let name = Self::require_key_id(key_id)?;
        let ct = self.encrypt_b64(name, plaintext, aad).await?;
        Ok(ct.into_bytes())
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let name = Self::require_key_id(key_id)?;
        let ct = std::str::from_utf8(ciphertext).map_err(|e| {
            IronCryptError::DecryptionError(format!("vault-transit ciphertext utf8: {e}"))
        })?;
        self.decrypt_b64(name, ct, aad).await
    }
}
