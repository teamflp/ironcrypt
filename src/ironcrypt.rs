use crate::{
    algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm},
    audit::{AuditEvent, Operation, Outcome},
    config::{DataType, IronCryptConfig},
    context::EncryptionContext,
    crypto_provider::{self, CryptoProvider},
    ecc_utils,
    encrypt::{EncryptedData, RecipientInfo},
    handle_error::IronCryptError,
    keys::{PrivateKey, PublicKey},
    load_any_private_key, load_any_public_key,
    payment::PaymentSecurityProfile,
    secrets::SecretStore,
};
#[cfg(feature = "rsa-algo")]
use crate::{generate_rsa_keys, rsa_utils, save_keys_to_files};
#[cfg(feature = "vault")]
use crate::secrets::vault::VaultStore;
#[cfg(feature = "aws")]
use crate::secrets::aws::AwsStore;
#[cfg(feature = "azure")]
use crate::secrets::azure::AzureStore;
#[cfg(feature = "hsm")]
use crate::secrets::hsm::HsmSecretStore;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use p256::pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use p256::pkcs8::LineEnding;
use rand::rngs::OsRng;
use rand::RngCore;
#[cfg(feature = "rsa-algo")]
use rsa::Oaep;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroize;
use crate::memsec::{new_dek32, zeroizing_vec};

// Helper function to ensure keys exist, creating them if they don't.
fn ensure_keys_exist(
    key_directory: &str,
    key_version: &str,
    config: &IronCryptConfig,
) -> Result<(), IronCryptError> {
    let public_key_path = format!("{}/public_key_{}.pem", key_directory, key_version);
    if Path::new(&public_key_path).exists() {
        return Ok(());
    }

    if !Path::new(key_directory).exists() {
        fs::create_dir_all(key_directory)?;
    }

    let private_key_path = format!("{}/private_key_{}.pem", key_directory, key_version);
    let passphrase = config
        .data_type_config
        .as_ref()
        .and_then(|d| d.get(&DataType::Generic).and_then(|km| km.passphrase.clone()));

    let mut event = AuditEvent::new(Operation::GenerateKey);
    event.key_version = Some(key_version.to_string());

    let generation_result = match config.asymmetric_algorithm {
        #[cfg(feature = "rsa-algo")]
        AsymmetricAlgorithm::Rsa => {
            event.key_type = Some("RSA".to_string());
            event.key_size = Some(config.rsa_key_size as usize);
            let (priv_key, pub_key) = generate_rsa_keys(config.rsa_key_size)?;
            save_keys_to_files(
                &priv_key,
                &pub_key,
                &private_key_path,
                &public_key_path,
                passphrase.as_deref(),
            )
        }
        #[cfg(not(feature = "rsa-algo"))]
        AsymmetricAlgorithm::Rsa => Err(IronCryptError::ConfigurationError(
            "RSA key generation requires the rsa-algo feature".into(),
        )),
        AsymmetricAlgorithm::Ecc => {
            event.key_type = Some("ECC".to_string());
            event.key_size = Some(256); // P-256
            let (priv_key, pub_key) = ecc_utils::generate_ecc_keys()?;
            ecc_utils::save_keys_to_files(
                &priv_key,
                &pub_key,
                &private_key_path,
                &public_key_path,
                passphrase.as_deref(),
            )
        }
    };

    if let Err(e) = &generation_result {
        event.set_failure(e);
    } else {
        event.outcome = Outcome::Success;
        let alg = match config.asymmetric_algorithm {
            AsymmetricAlgorithm::Rsa => "rsa",
            AsymmetricAlgorithm::Ecc => "ecc-p256",
        };
        match crate::key_lifecycle::load_keyring(key_directory)? {
            None => {
                let key_id = format!("key-{}", uuid_like());
                let manifest =
                    crate::key_lifecycle::KeyringManifest::new(&key_id, key_version, alg);
                crate::key_lifecycle::save_keyring(key_directory, &manifest)?;
            }
            Some(mut manifest) => {
                if manifest.version(key_version).is_none() {
                    manifest.rotate_to(key_version, alg)?;
                    crate::key_lifecycle::save_keyring(key_directory, &manifest)?;
                }
            }
        }
    }
    event.log();

    generation_result
}

fn uuid_like() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// The main entry point for cryptographic operations with IronCrypt.
pub struct IronCrypt {
    pub config: IronCryptConfig,
    secret_store: Option<Box<dyn SecretStore + Send + Sync>>,
    /// Optional remote/HSM provider used to wrap DEKs (preferred when set).
    crypto_provider: Option<Arc<dyn CryptoProvider>>,
    data_type: DataType,
    key_directory: String,
    key_version: String,
    /// Local public key — `None` when operating in provider-only mode.
    public_key: Option<PublicKey>,
}

impl IronCrypt {
    pub async fn sign_audit_log(&self) -> Result<(), IronCryptError> {
        let audit_config = self.config.audit.as_ref().ok_or_else(|| {
            IronCryptError::ConfigurationError("Audit configuration is not set.".to_string())
        })?;

        match audit_config.effective_signing_mode() {
            crate::config::AuditSigningMode::None => Ok(()),
            crate::config::AuditSigningMode::Pem
            | crate::config::AuditSigningMode::HmacEnv => {
                crate::audit::sign_audit_from_config(audit_config)?;
                Ok(())
            }
            crate::config::AuditSigningMode::Provider => {
                let provider = self.crypto_provider.as_ref().ok_or_else(|| {
                    IronCryptError::ConfigurationError(
                        "audit signing_mode=provider requires a CryptoProvider".into(),
                    )
                })?;
                let key_id = audit_config.signing_key_id.as_ref().ok_or_else(|| {
                    IronCryptError::ConfigurationError(
                        "audit signing_mode=provider requires signing_key_id".into(),
                    )
                })?;
                let targets = crate::audit::audit_sign_targets(
                    &audit_config.log_path,
                    &audit_config.audit_directory,
                )?;
                for path in targets {
                    crate::audit::attest_audit_file_with_provider(&path, provider.as_ref(), key_id)
                        .await?;
                }
                Ok(())
            }
        }
    }

    /// Synchronous helper for PEM / HMAC audit signing (not `provider` mode).
    pub fn sign_audit_log_sync(&self) -> Result<(), IronCryptError> {
        let audit_config = self.config.audit.as_ref().ok_or_else(|| {
            IronCryptError::ConfigurationError("Audit configuration is not set.".to_string())
        })?;
        if matches!(
            audit_config.effective_signing_mode(),
            crate::config::AuditSigningMode::Provider
        ) {
            return Err(IronCryptError::UnsupportedOperation(
                "use async sign_audit_log() for provider attestation".into(),
            ));
        }
        crate::audit::sign_audit_from_config(audit_config)?;
        Ok(())
    }

    pub async fn new(
        mut config: IronCryptConfig,
        data_type: DataType,
    ) -> Result<Self, IronCryptError> {
        // Apply the selected standard's parameters, if not custom.
        if let Some(params) = config.standard.get_params() {
            config.symmetric_algorithm = params.symmetric_algorithm;
            config.asymmetric_algorithm = params.asymmetric_algorithm;
            config.rsa_key_size = params.rsa_key_size;
        }

        let secret_store = if let Some(secrets_config) = &config.secrets {
            match secrets_config.provider.as_str() {
                #[cfg(feature = "vault")]
                "vault" => {
                    let vault_config = secrets_config.vault.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(
                            "Vault provider selected but no vault config provided".to_string(),
                        )
                    })?;
                    let store = VaultStore::new(vault_config, &vault_config.mount)?;
                    Some(Box::new(store) as Box<dyn SecretStore + Send + Sync>)
                }
                #[cfg(feature = "aws")]
                "aws" => {
                    let aws_config = secrets_config.aws.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(
                            "AWS provider selected but no AWS config provided".to_string(),
                        )
                    })?;
                    let store = AwsStore::new(aws_config).await?;
                    Some(Box::new(store) as Box<dyn SecretStore + Send + Sync>)
                }
                #[cfg(feature = "azure")]
                "azure" => {
                    let azure_config = secrets_config.azure.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(
                            "Azure provider selected but no Azure config provided".to_string(),
                        )
                    })?;
                    let store = AzureStore::new(azure_config).await?;
                    Some(Box::new(store) as Box<dyn SecretStore + Send + Sync>)
                }
                #[cfg(feature = "gcp")]
                "google" => {
                    let google_config = secrets_config.google.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(
                            "Google provider selected but no Google config provided".to_string(),
                        )
                    })?;
                    let store = crate::secrets::google::GoogleStore::new(google_config).await?;
                    Some(Box::new(store) as Box<dyn SecretStore + Send + Sync>)
                }
                #[cfg(feature = "hsm")]
                "hsm" => {
                    let hsm_config = secrets_config.hsm.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(
                            "HSM provider selected but no HSM config provided".to_string(),
                        )
                    })?;
                    let store = HsmSecretStore::new(hsm_config.clone());
                    Some(Box::new(store) as Box<dyn SecretStore + Send + Sync>)
                }
                other => {
                    return Err(IronCryptError::ConfigurationError(format!(
                        "Unsupported secrets provider: {}",
                        other
                    )))
                }
            }
        } else {
            None
        };

        let crypto_provider = if let Some(cp_cfg) = &config.crypto_provider {
            let provider = crypto_provider::build_from_config(cp_cfg).await?;
            if provider.private_material_exportable()
                && crate::payment::PaymentSecurityProfile::is_enabled()
            {
                return Err(IronCryptError::ConfigurationError(
                    "Payment profile rejects exportable CryptoProvider".into(),
                ));
            }
            Some(Arc::from(provider))
        } else {
            None
        };

        let (key_directory, key_version) = if let Some(dt_cfg) = &config.data_type_config {
            if let Some(km) = dt_cfg.get(&data_type) {
                (km.key_directory.clone(), km.key_version.clone())
            } else {
                ("keys".to_string(), "v1".to_string())
            }
        } else {
            ("keys".to_string(), "v1".to_string())
        };

        let public_key = if crypto_provider.is_some() {
            // Provider-only: no local private key material required for DEK wrap.
            None
        } else {
            ensure_keys_exist(&key_directory, &key_version, &config)?;
            let public_key_path = format!("{}/public_key_{}.pem", key_directory, key_version);
            Some(load_any_public_key(&public_key_path)?)
        };

        Ok(Self {
            config,
            secret_store,
            crypto_provider,
            data_type,
            key_directory,
            key_version,
            public_key,
        })
    }

    #[doc(hidden)]
    pub fn with_store(
        config: IronCryptConfig,
        data_type: DataType,
        secret_store: Box<dyn SecretStore + Send + Sync>,
        key_directory: String,
        key_version: String,
    ) -> Result<Self, IronCryptError> {
        ensure_keys_exist(&key_directory, &key_version, &config)?;
        let public_key_path = format!("{}/public_key_{}.pem", key_directory, key_version);
        let public_key = load_any_public_key(&public_key_path)?;

        Ok(Self {
            config,
            secret_store: Some(secret_store),
            crypto_provider: None,
            data_type,
            key_directory,
            key_version,
            public_key: Some(public_key),
        })
    }

    /// Returns the configured [`CryptoProvider`], if any.
    pub fn crypto_provider(&self) -> Option<&Arc<dyn CryptoProvider>> {
        self.crypto_provider.as_ref()
    }

    /// Build an [`IronCrypt`] bound to an in-process / injected [`CryptoProvider`].
    ///
    /// Used for Provider-mode encryption and [`Self::rewrap_data`] without going through
    /// `build_from_config` (e.g. [`crate::LocalKeyProvider`] in tests).
    pub fn with_crypto_provider(
        config: IronCryptConfig,
        data_type: DataType,
        provider: Arc<dyn CryptoProvider>,
        key_directory: String,
        key_version: String,
    ) -> Self {
        Self {
            config,
            secret_store: None,
            crypto_provider: Some(provider),
            data_type,
            key_directory,
            key_version,
            public_key: None,
        }
    }

    pub fn encrypt_password(&self, password: &str) -> Result<String, IronCryptError> {
        if PaymentSecurityProfile::require_hash_only_login() {
            return Err(IronCryptError::UnsupportedOperation(
                "Payment profile: use hash_login_password / verify_login_password for auth; \
                 use encrypt_secret for recoverable secrets"
                    .into(),
            ));
        }
        let public_key = self.public_key.as_ref().ok_or_else(|| {
            IronCryptError::ConfigurationError(
                "encrypt_password requires local keys; provider-only mode uses hash_password \
                 for auth or encrypt_binary_data for secrets"
                    .into(),
            )
        })?;
        let argon_cfg = crate::Argon2Config {
            memory_cost: self.config.argon2_memory_cost,
            time_cost: self.config.argon2_time_cost,
            parallelism: self.config.argon2_parallelism,
        };
        crate::password::encrypt(password, public_key, &self.key_version, &argon_cfg)
    }

    /// Argon2id PHC hash for login (non-recoverable). Preferred under Payment.
    pub fn hash_login_password(&self, password: &str) -> Result<String, IronCryptError> {
        let cfg = crate::Argon2Config {
            memory_cost: self.config.argon2_memory_cost,
            time_cost: self.config.argon2_time_cost,
            parallelism: self.config.argon2_parallelism,
        };
        crate::hashing::hash_password_with_config(password, &cfg)
            .map_err(IronCryptError::HashingError)
    }

    /// Verify a login password against a stored Argon2 PHC hash.
    pub fn verify_login_password(
        &self,
        password: &str,
        phc_hash: &str,
    ) -> Result<bool, IronCryptError> {
        crate::hashing::verify_password(password, phc_hash).map_err(IronCryptError::HashingError)
    }

    /// Whether a stored login hash should be rehashed with current Argon2 costs.
    pub fn login_password_needs_rehash(&self, phc_hash: &str) -> bool {
        let cfg = crate::Argon2Config {
            memory_cost: self.config.argon2_memory_cost,
            time_cost: self.config.argon2_time_cost,
            parallelism: self.config.argon2_parallelism,
        };
        crate::hashing::password_needs_rehash(phc_hash, &cfg)
    }

    pub fn verify_password(
        &self,
        encrypted_json: &str,
        user_input_password: &str,
    ) -> Result<bool, IronCryptError> {
        let private_key_path = format!("{}/private_key_{}.pem", self.key_directory, self.key_version);
        let passphrase = self.get_passphrase()?;
        let private_key = load_any_private_key(&private_key_path, passphrase.as_deref())?;
        crate::password::verify(encrypted_json, user_input_password, &private_key)
    }

    pub async fn store_secret(&self, key: &str, value: &str) -> Result<(), IronCryptError> {
        if let Some(store) = &self.secret_store {
            store.set_secret(key, value).await.map_err(IronCryptError::from)
        } else {
            Err(IronCryptError::ConfigurationError(
                "No secret store configured".to_string(),
            ))
        }
    }

    pub async fn retrieve_secret(&self, key: &str) -> Result<String, IronCryptError> {
        if let Some(store) = &self.secret_store {
            store.get_secret(key).await.map_err(IronCryptError::from)
        } else {
            Err(IronCryptError::ConfigurationError(
                "No secret store configured".to_string(),
            ))
        }
    }

    pub async fn encrypt_binary_data(
        &self,
        data: &[u8],
        password: &str,
    ) -> Result<String, IronCryptError> {
        self.encrypt_with_context(data, password, None).await
    }

    /// Encrypt recoverable secret/data with an optional multi-tenant context (AAD).
    ///
    /// Under the Payment profile, `context` is required.
    pub async fn encrypt_with_context(
        &self,
        data: &[u8],
        password: &str,
        context: Option<&EncryptionContext>,
    ) -> Result<String, IronCryptError> {
        EncryptionContext::require_for_payment(context)?;
        if PaymentSecurityProfile::is_enabled() {
            if let Ok(s) = std::str::from_utf8(data) {
                crate::api_roles::tokenization::reject_cardholder_auth_data(s)?;
            }
        }
        self.encrypt_binary_data_inner(data, password, context).await
    }

    /// Alias for recoverable secrets (Payment naming).
    ///
    /// Under Payment, UTF-8 payloads that look like PAN/CVV are rejected
    /// ([`crate::api_roles::tokenization::reject_cardholder_auth_data`]).
    pub async fn encrypt_secret(
        &self,
        data: &[u8],
        password: &str,
        context: Option<&EncryptionContext>,
    ) -> Result<String, IronCryptError> {
        if PaymentSecurityProfile::is_enabled() {
            if let Ok(s) = std::str::from_utf8(data) {
                crate::api_roles::tokenization::reject_cardholder_auth_data(s)?;
            }
        }
        self.encrypt_with_context(data, password, context).await
    }

    /// Alias for recoverable secrets (Payment naming).
    pub async fn decrypt_secret(
        &self,
        encrypted_json: &str,
        password: &str,
        expected_context: Option<&EncryptionContext>,
    ) -> Result<Vec<u8>, IronCryptError> {
        self.decrypt_with_context(encrypted_json, password, expected_context)
            .await
    }

    pub async fn decrypt_binary_data(
        &self,
        encrypted_json: &str,
        password: &str,
    ) -> Result<Vec<u8>, IronCryptError> {
        self.decrypt_with_context(encrypted_json, password, None).await
    }

    pub async fn decrypt_with_context(
        &self,
        encrypted_json: &str,
        password: &str,
        expected_context: Option<&EncryptionContext>,
    ) -> Result<Vec<u8>, IronCryptError> {
        self.decrypt_binary_data_inner(encrypted_json, password, expected_context)
            .await
    }

    async fn encrypt_binary_data_inner(
        &self,
        data: &[u8],
        password: &str,
        context: Option<&EncryptionContext>,
    ) -> Result<String, IronCryptError> {
        let mut event = AuditEvent::new(Operation::Write);
        event.key_version = Some(self.key_version.to_string());
        event.symmetric_algorithm = Some(self.config.symmetric_algorithm.to_string());

        let result: Result<String, IronCryptError> = async {
            let mut pwd_string = password.to_string();
            self.config.password_criteria.validate(&pwd_string)?;

            let password_hash = if !password.is_empty() {
                let argon_cfg = &self.config;
                let params = Params::new(
                    argon_cfg.argon2_memory_cost,
                    argon_cfg.argon2_time_cost,
                    argon_cfg.argon2_parallelism,
                    None,
                )?;
                let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                let salt = SaltString::generate(&mut OsRng);
                let hash_str = argon2
                    .hash_password(pwd_string.as_bytes(), &salt)?
                    .to_string();
                Some(hash_str)
            } else {
                None
            };
            pwd_string.zeroize();

            let mut symmetric_key = new_dek32();

            let sym_algo = self.config.symmetric_algorithm;
            let nonce_len = match sym_algo {
                SymmetricAlgorithm::Aes256Gcm => 12,
                SymmetricAlgorithm::ChaCha20Poly1305 => 24,
            };
            let mut nonce_bytes = vec![0u8; nonce_len];
            OsRng.fill_bytes(&mut nonce_bytes);

            let sealed_password_hash = match &password_hash {
                Some(hash_str) => Some(crate::encrypt::seal_password_hash(
                    symmetric_key.as_ref(),
                    &nonce_bytes,
                    hash_str,
                )?),
                None => None,
            };

            let aad = context
                .map(|c| c.to_aad_bytes())
                .unwrap_or_default();
            let ciphertext = match sym_algo {
                SymmetricAlgorithm::Aes256Gcm => {
                    let cipher = Aes256Gcm::new_from_slice(symmetric_key.as_ref())?;
                    cipher.encrypt(
                        Nonce::from_slice(&nonce_bytes),
                        Payload {
                            msg: data,
                            aad: &aad,
                        },
                    )?
                }
                SymmetricAlgorithm::ChaCha20Poly1305 => {
                    let cipher = XChaCha20Poly1305::new_from_slice(symmetric_key.as_ref())?;
                    cipher.encrypt(
                        XNonce::from_slice(&nonce_bytes),
                        Payload {
                            msg: data,
                            aad: &aad,
                        },
                    )?
                }
            };

            let recipient_info = if let Some(provider) = &self.crypto_provider {
                let wrapped = provider
                    .wrap_key(&self.key_version, symmetric_key.as_ref())
                    .await?;
                RecipientInfo::Provider {
                    key_version: self.key_version.clone(),
                    provider: provider.name().to_string(),
                    key_id: wrapped.key_id,
                    encrypted_symmetric_key: base64_standard.encode(wrapped.ciphertext),
                }
            } else {
                match self.public_key.as_ref().ok_or_else(|| {
                    IronCryptError::ConfigurationError(
                        "No public key or CryptoProvider configured".into(),
                    )
                })? {
                    #[cfg(feature = "rsa-algo")]
                    PublicKey::Rsa(rsa_pub_key) => {
                        let padding = Oaep::new::<Sha256>();
                        let encrypted_symmetric_key =
                            rsa_pub_key.encrypt(&mut OsRng, padding, symmetric_key.as_ref())?;
                        RecipientInfo::Rsa {
                            key_version: self.key_version.clone(),
                            encrypted_symmetric_key: base64_standard
                                .encode(&encrypted_symmetric_key),
                        }
                    }
                    PublicKey::Ecc(ecc_pub_key) => {
                        let kek = ecc_utils::ecies_key_encap(ecc_pub_key, symmetric_key.as_ref())?;
                        let ephemeral_public_key_pem = kek
                            .ephemeral_pk
                            .to_public_key_pem(LineEnding::LF)
                            .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?;

                        RecipientInfo::Ecc {
                            key_version: self.key_version.clone(),
                            ephemeral_public_key: base64_standard.encode(ephemeral_public_key_pem),
                            encrypted_symmetric_key: base64_standard.encode(kek.encapsulated_key),
                        }
                    }
                }
            };

            let enc_data = EncryptedData {
                format_version: crate::envelope::CURRENT_JSON_FORMAT_VERSION,
                symmetric_algorithm: sym_algo,
                recipient_info,
                nonce: base64_standard.encode(&nonce_bytes),
                ciphertext: base64_standard.encode(&ciphertext),
                password_hash: sealed_password_hash,
                context: context.cloned(),
            };

            symmetric_key.zeroize();
            Ok(serde_json::to_string(&enc_data)?)
        }
        .await;

        if let Err(e) = &result {
            event.set_failure(e);
        } else {
            event.outcome = Outcome::Success;
        }
        event.log();

        result
    }

    async fn decrypt_binary_data_inner(
        &self,
        encrypted_json: &str,
        password: &str,
        expected_context: Option<&EncryptionContext>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let mut event = AuditEvent::new(Operation::Read);

        let result: Result<Vec<u8>, IronCryptError> = async {
            let ed: EncryptedData = serde_json::from_str(encrypted_json)?;
            crate::envelope::ensure_json_format_allowed(Some(ed.format_version))?;

            if let Some(expected) = expected_context {
                expected.validate()?;
                match &ed.context {
                    Some(got) if got == expected => {}
                    Some(_) => {
                        return Err(IronCryptError::DecryptionError(
                            "EncryptionContext mismatch (tenant/purpose/record)".into(),
                        ));
                    }
                    None => {
                        return Err(IronCryptError::DecryptionError(
                            "Ciphertext has no EncryptionContext".into(),
                        ));
                    }
                }
            } else if PaymentSecurityProfile::require_encryption_context() {
                return Err(IronCryptError::DecryptionError(
                    "Payment profile requires expected EncryptionContext on decrypt \
                     (pass tenant_id/purpose/record_id to match ciphertext binding)"
                        .into(),
                ));
            }

            let key_version = match &ed.recipient_info {
                RecipientInfo::Rsa { key_version, .. }
                | RecipientInfo::Ecc { key_version, .. }
                | RecipientInfo::Provider { key_version, .. } => key_version.clone(),
            };
            event.key_version = Some(key_version.to_string());
            event.symmetric_algorithm = Some(ed.symmetric_algorithm.to_string());

            let mut symmetric_key = match &ed.recipient_info {
                RecipientInfo::Provider {
                    provider: prov_name,
                    key_id,
                    encrypted_symmetric_key,
                    ..
                } => {
                    let provider = self.crypto_provider.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(format!(
                            "Ciphertext requires CryptoProvider '{prov_name}' but none configured"
                        ))
                    })?;
                    if provider.name() != prov_name.as_str() {
                        return Err(IronCryptError::DecryptionError(format!(
                            "Provider mismatch: ciphertext uses '{prov_name}', runtime is '{}'",
                            provider.name()
                        )));
                    }
                    let wrapped = base64_standard.decode(encrypted_symmetric_key)?;
                    zeroizing_vec(provider.unwrap_key(key_id, &wrapped).await?)
                }
                RecipientInfo::Rsa {
                    encrypted_symmetric_key: _,
                    ..
                }
                | RecipientInfo::Ecc {
                    encrypted_symmetric_key: _,
                    ..
                } => {
                    let private_key_path =
                        format!("{}/private_key_{}.pem", self.key_directory, key_version);
                    let mut passphrase = self.get_passphrase()?;
                    let private_key =
                        load_any_private_key(&private_key_path, passphrase.as_deref())?;
                    if let Some(ref mut p) = passphrase {
                        p.zeroize();
                    }

                    match (&private_key, &ed.recipient_info) {
                        #[cfg(feature = "rsa-algo")]
                        (
                            PrivateKey::Rsa(rsa_priv_key),
                            RecipientInfo::Rsa {
                                encrypted_symmetric_key,
                                ..
                            },
                        ) => {
                            let key_bytes = base64_standard.decode(encrypted_symmetric_key)?;
                            zeroizing_vec(rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?)
                        }
                        (
                            PrivateKey::Ecc(ecc_priv_key),
                            RecipientInfo::Ecc {
                                ephemeral_public_key,
                                encrypted_symmetric_key,
                                ..
                            },
                        ) => {
                            let eph_pub_key_pem = base64_standard.decode(ephemeral_public_key)?;
                            let eph_pub_key = p256::PublicKey::from_public_key_pem(
                                &String::from_utf8(eph_pub_key_pem)?,
                            )?;
                            let encapsulated_key =
                                base64_standard.decode(encrypted_symmetric_key)?;
                            ecc_utils::ecies_key_decap(
                                ecc_priv_key,
                                &eph_pub_key,
                                &encapsulated_key,
                            )?
                        }
                        _ => {
                            return Err(IronCryptError::DecryptionError(
                                "Mismatched private key and recipient info type".into(),
                            ))
                        }
                    }
                }
            };

            let ciphertext = base64_standard.decode(&ed.ciphertext)?;
            let nonce_bytes = base64_standard.decode(&ed.nonce)?;

            let password_ok = if let Some(hash_field) = ed.password_hash.as_ref() {
                crate::encrypt::verify_sealed_or_legacy_password_hash(
                    &symmetric_key,
                    &nonce_bytes,
                    hash_field,
                    password,
                )
            } else {
                true
            };

            if !password_ok {
                symmetric_key.zeroize();
                return Err(IronCryptError::DecryptionError(
                    "Invalid password or ciphertext".to_string(),
                ));
            }

            let aad = ed
                .context
                .as_ref()
                .map(|c| c.to_aad_bytes())
                .unwrap_or_default();
            let plaintext_result = match ed.symmetric_algorithm {
                SymmetricAlgorithm::Aes256Gcm => {
                    let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
                    cipher.decrypt(
                        Nonce::from_slice(&nonce_bytes),
                        Payload {
                            msg: ciphertext.as_ref(),
                            aad: &aad,
                        },
                    )
                }
                SymmetricAlgorithm::ChaCha20Poly1305 => {
                    let cipher = XChaCha20Poly1305::new_from_slice(&symmetric_key)?;
                    cipher.decrypt(
                        XNonce::from_slice(&nonce_bytes),
                        Payload {
                            msg: ciphertext.as_ref(),
                            aad: &aad,
                        },
                    )
                }
            };

            symmetric_key.zeroize();

            plaintext_result.map_err(|_| {
                IronCryptError::DecryptionError("Invalid password or ciphertext".to_string())
            })
        }
        .await;

        if let Err(e) = &result {
            event.set_failure(e);
        } else {
            event.outcome = Outcome::Success;
        }
        event.log();

        result
    }

    /// Re-wrap the DEK of an `EncryptedData` JSON envelope under a new recipient.
    ///
    /// Supports local ECC/RSA keys and [`CryptoProvider`] recipients (unwrap + wrap
    /// without re-encrypting the payload ciphertext).
    pub async fn rewrap_data(
        &self,
        encrypted_json: &str,
        new_key_version: &str,
        new_public_key: Option<&PublicKey>,
        new_provider_key_id: Option<&str>,
    ) -> Result<String, IronCryptError> {
        let mut event = AuditEvent::new(Operation::Rekey);
        event.key_version = Some(new_key_version.to_string());

        let result: Result<String, IronCryptError> = async {
            let mut ed: EncryptedData = serde_json::from_str(encrypted_json)?;

            let mut symmetric_key = match &ed.recipient_info {
                RecipientInfo::Provider {
                    provider: prov_name,
                    key_id,
                    encrypted_symmetric_key,
                    ..
                } => {
                    let provider = self.crypto_provider.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(format!(
                            "Ciphertext requires CryptoProvider '{prov_name}' but none configured"
                        ))
                    })?;
                    if provider.name() != prov_name.as_str() {
                        return Err(IronCryptError::DecryptionError(format!(
                            "Provider mismatch: ciphertext uses '{prov_name}', runtime is '{}'",
                            provider.name()
                        )));
                    }
                    let wrapped = base64_standard.decode(encrypted_symmetric_key)?;
                    zeroizing_vec(provider.unwrap_key(key_id, &wrapped).await?)
                }
                RecipientInfo::Rsa { key_version, .. }
                | RecipientInfo::Ecc { key_version, .. } => {
                    let private_key_path =
                        format!("{}/private_key_{}.pem", self.key_directory, key_version);
                    let mut passphrase = self.get_passphrase()?;
                    let old_private_key =
                        load_any_private_key(&private_key_path, passphrase.as_deref())?;
                    if let Some(ref mut p) = passphrase {
                        p.zeroize();
                    }
                    match (&old_private_key, &ed.recipient_info) {
                        #[cfg(feature = "rsa-algo")]
                        (
                            PrivateKey::Rsa(rsa_priv_key),
                            RecipientInfo::Rsa {
                                encrypted_symmetric_key,
                                ..
                            },
                        ) => {
                            let key_bytes = base64_standard.decode(encrypted_symmetric_key)?;
                            zeroizing_vec(rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?)
                        }
                        (
                            PrivateKey::Ecc(ecc_priv_key),
                            RecipientInfo::Ecc {
                                ephemeral_public_key,
                                encrypted_symmetric_key,
                                ..
                            },
                        ) => {
                            let eph_pub_key_pem = base64_standard.decode(ephemeral_public_key)?;
                            let eph_pub_key = p256::PublicKey::from_public_key_pem(
                                &String::from_utf8(eph_pub_key_pem)?,
                            )?;
                            let encapsulated_key =
                                base64_standard.decode(encrypted_symmetric_key)?;
                            ecc_utils::ecies_key_decap(
                                ecc_priv_key,
                                &eph_pub_key,
                                &encapsulated_key,
                            )?
                        }
                        _ => {
                            return Err(IronCryptError::DecryptionError(
                                "Mismatched private key and recipient info type".into(),
                            ))
                        }
                    }
                }
            };

            // Prefer local public-key rewrap when provided; otherwise CryptoProvider wrap.
            let new_recipient_info = if let Some(pk) = new_public_key {
                match pk {
                    #[cfg(feature = "rsa-algo")]
                    PublicKey::Rsa(rsa_pub_key) => {
                        let padding = Oaep::new::<Sha256>();
                        let encrypted_symmetric_key =
                            rsa_pub_key.encrypt(&mut OsRng, padding, &symmetric_key)?;
                        RecipientInfo::Rsa {
                            key_version: new_key_version.to_string(),
                            encrypted_symmetric_key: base64_standard
                                .encode(&encrypted_symmetric_key),
                        }
                    }
                    PublicKey::Ecc(ecc_pub_key) => {
                        let kek = ecc_utils::ecies_key_encap(ecc_pub_key, &symmetric_key)?;
                        let ephemeral_public_key_pem = kek
                            .ephemeral_pk
                            .to_public_key_pem(LineEnding::LF)
                            .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?;
                        RecipientInfo::Ecc {
                            key_version: new_key_version.to_string(),
                            ephemeral_public_key: base64_standard.encode(ephemeral_public_key_pem),
                            encrypted_symmetric_key: base64_standard.encode(kek.encapsulated_key),
                        }
                    }
                }
            } else if let Some(provider) = &self.crypto_provider {
                let wrap_id = new_provider_key_id.unwrap_or(new_key_version);
                let wrapped = provider.wrap_key(wrap_id, &symmetric_key).await?;
                RecipientInfo::Provider {
                    key_version: new_key_version.to_string(),
                    provider: provider.name().to_string(),
                    key_id: wrapped.key_id,
                    encrypted_symmetric_key: base64_standard.encode(wrapped.ciphertext),
                }
            } else {
                return Err(IronCryptError::ConfigurationError(
                    "rewrap_data requires new_public_key or a configured CryptoProvider".into(),
                ));
            };

            symmetric_key.zeroize();
            ed.recipient_info = new_recipient_info;
            Ok(serde_json::to_string(&ed)?)
        }
        .await;

        if let Err(e) = &result {
            event.set_failure(e);
        } else {
            event.outcome = Outcome::Success;
        }
        event.log();
        result
    }

    pub fn re_encrypt_data(
        &self,
        encrypted_json: &str,
        new_public_key: &PublicKey,
        new_key_version: &str,
    ) -> Result<String, IronCryptError> {
        // Sync wrapper for local-key rewrap (legacy CLI). Provider envelopes need
        // [`Self::rewrap_data`].
        let mut event = AuditEvent::new(Operation::Rekey);
        event.key_version = Some(new_key_version.to_string());

        let result: Result<String, IronCryptError> = (|| {
            let mut ed: EncryptedData = serde_json::from_str(encrypted_json)?;

            let old_key_version = match &ed.recipient_info {
                RecipientInfo::Rsa { key_version, .. }
                | RecipientInfo::Ecc { key_version, .. } => key_version.clone(),
                RecipientInfo::Provider { .. } => {
                    return Err(IronCryptError::UnsupportedOperation(
                        "Provider-wrapped DEKs require async IronCrypt::rewrap_data".into(),
                    ));
                }
            };

            let private_key_path =
                format!("{}/private_key_{}.pem", self.key_directory, old_key_version);
            let mut passphrase = self.get_passphrase()?;
            let old_private_key = load_any_private_key(&private_key_path, passphrase.as_deref())?;
            if let Some(ref mut p) = passphrase {
                p.zeroize();
            }

            let mut symmetric_key = match (&old_private_key, &ed.recipient_info) {
                #[cfg(feature = "rsa-algo")]
                (
                    PrivateKey::Rsa(rsa_priv_key),
                    RecipientInfo::Rsa {
                        encrypted_symmetric_key,
                        ..
                    },
                ) => {
                    let key_bytes = base64_standard.decode(encrypted_symmetric_key)?;
                    zeroizing_vec(rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?)
                }
                (
                    PrivateKey::Ecc(ecc_priv_key),
                    RecipientInfo::Ecc {
                        ephemeral_public_key,
                        encrypted_symmetric_key,
                        ..
                    },
                ) => {
                    let eph_pub_key_pem = base64_standard.decode(ephemeral_public_key)?;
                    let eph_pub_key = p256::PublicKey::from_public_key_pem(
                        &String::from_utf8(eph_pub_key_pem)?,
                    )?;
                    let encapsulated_key = base64_standard.decode(encrypted_symmetric_key)?;
                    ecc_utils::ecies_key_decap(ecc_priv_key, &eph_pub_key, &encapsulated_key)?
                }
                _ => {
                    return Err(IronCryptError::DecryptionError(
                        "Mismatched private key and recipient info type".into(),
                    ))
                }
            };

            let new_recipient_info = match new_public_key {
                #[cfg(feature = "rsa-algo")]
                PublicKey::Rsa(rsa_pub_key) => {
                    let padding = Oaep::new::<Sha256>();
                    let encrypted_symmetric_key =
                        rsa_pub_key.encrypt(&mut OsRng, padding, &symmetric_key)?;
                    RecipientInfo::Rsa {
                        key_version: new_key_version.to_string(),
                        encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
                    }
                }
                PublicKey::Ecc(ecc_pub_key) => {
                    let kek = ecc_utils::ecies_key_encap(ecc_pub_key, &symmetric_key)?;
                    let ephemeral_public_key_pem = kek
                        .ephemeral_pk
                        .to_public_key_pem(LineEnding::LF)
                        .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?;

                    RecipientInfo::Ecc {
                        key_version: new_key_version.to_string(),
                        ephemeral_public_key: base64_standard.encode(ephemeral_public_key_pem),
                        encrypted_symmetric_key: base64_standard.encode(kek.encapsulated_key),
                    }
                }
            };

            symmetric_key.zeroize();

            ed.recipient_info = new_recipient_info;

            Ok(serde_json::to_string(&ed)?)
        })();

        if let Err(e) = &result {
            event.set_failure(e);
        } else {
            event.outcome = Outcome::Success;
        }
        event.log();

        result
    }

    pub fn public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    pub fn key_version(&self) -> &str {
        &self.key_version
    }

    fn get_passphrase(&self) -> Result<Option<String>, IronCryptError> {
        if let Some(dt_cfg) = &self.config.data_type_config {
            if let Some(km) = dt_cfg.get(&self.data_type) {
                return Ok(km.passphrase.clone());
            }
        }
        Ok(None)
    }

    pub fn sign(&self, data_to_sign: &[u8]) -> Result<String, IronCryptError> {
        let mut event = AuditEvent::new(Operation::Sign);
        event.key_version = Some(self.key_version.to_string());

        let result: Result<String, IronCryptError> = (|| {
            let private_key_path =
                format!("{}/private_key_{}.pem", self.key_directory, self.key_version);
            let passphrase = self.get_passphrase()?;
            let private_key = load_any_private_key(&private_key_path, passphrase.as_deref())?;

            let mut hasher = Sha256::new();
            hasher.update(data_to_sign);
            let hash = hasher.finalize();

            let (signature, algo) = match private_key {
                #[cfg(feature = "rsa-algo")]
                PrivateKey::Rsa(key) => (
                    rsa_utils::sign_hash_pss(&key, &hash)?,
                    "rsa-pss-sha256",
                ),
                PrivateKey::Ecc(key) => (
                    ecc_utils::sign_hash_ecc(&key, &hash)?,
                    "ecdsa-p256-sha256",
                ),
            };
            event.signature_algorithm = Some(algo.to_string());

            Ok(base64_standard.encode(signature))
        })();

        if let Err(e) = &result {
            event.set_failure(e);
        } else {
            event.outcome = Outcome::Success;
        }
        event.log();

        result
    }

    pub fn verify(
        &self,
        data_to_verify: &[u8],
        signature: &str,
    ) -> Result<bool, IronCryptError> {
        let public_key = self.public_key.as_ref().ok_or_else(|| {
            IronCryptError::ConfigurationError(
                "verify requires a local public key (not available in provider-only mode)".into(),
            )
        })?;
        let mut event = AuditEvent::new(Operation::Verify);
        event.key_version = Some(self.key_version.to_string());
        event.signature_algorithm = Some(match public_key {
            #[cfg(feature = "rsa-algo")]
            PublicKey::Rsa(_) => "rsa-pss-sha256".to_string(),
            PublicKey::Ecc(_) => "ecdsa-p256-sha256".to_string(),
        });

        let verification_result = (|| {
            let signature_bytes = base64_standard.decode(signature)?;

            let mut hasher = Sha256::new();
            hasher.update(data_to_verify);
            let hash = hasher.finalize();

            match public_key {
                #[cfg(feature = "rsa-algo")]
                PublicKey::Rsa(key) => {
                    rsa_utils::verify_signature(key, &hash, &signature_bytes)
                }
                PublicKey::Ecc(key) => {
                    ecc_utils::verify_signature_ecc(key, &hash, &signature_bytes)
                }
            }
        })();

        match verification_result {
            Ok(_) => {
                event.outcome = Outcome::Success;
                event.log();
                Ok(true)
            }
            Err(IronCryptError::SignatureError(_))
            | Err(IronCryptError::SignatureVerificationFailed(_)) => {
                event.outcome = Outcome::Failure;
                event.log();
                Ok(false)
            }
            Err(e) => {
                event.set_failure(&e);
                event.log();
                Err(e)
            }
        }
    }
}
