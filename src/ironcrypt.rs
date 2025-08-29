use crate::{
    algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm},
    audit::{AuditEvent, Operation, Outcome},
    config::{DataType, IronCryptConfig},
    ecc_utils,
    encrypt::{EncryptedData, RecipientInfo},
    generate_rsa_keys,
    handle_error::IronCryptError,
    keys::{PrivateKey, PublicKey},
    load_any_private_key, load_any_public_key, save_keys_to_files,
    secrets::SecretStore,
};
#[cfg(feature = "vault")]
use crate::secrets::vault::VaultStore;
#[cfg(feature = "aws")]
use crate::secrets::aws::AwsStore;
#[cfg(feature = "azure")]
use crate::secrets::azure::AzureStore;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use chacha20poly1305::XChaCha20Poly1305;
use p256::pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use p256::pkcs8::LineEnding;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::Oaep;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;
use crate::rsa_utils;

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
        event.outcome = Outcome::Failure;
        event.error_message = Some(e.to_string());
    } else {
        event.outcome = Outcome::Success;
    }
    event.log();

    generation_result
}

/// Represents the configuration for the Argon2 hashing algorithm.
#[derive(Clone, Debug, Copy)]
pub struct Argon2Config {
    /// Memory cost (in KiB). Recommended: 65536 (64 MB).
    pub memory_cost: u32,
    /// Time cost (number of iterations). Recommended: 3.
    pub time_cost: u32,
    /// Degree of parallelism. Recommended: 1.
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_cost: 65536,
            time_cost: 3,
            parallelism: 1,
        }
    }
}

/// The main entry point for cryptographic operations with IronCrypt.
pub struct IronCrypt {
    pub config: IronCryptConfig,
    secret_store: Option<Box<dyn SecretStore + Send + Sync>>,
    data_type: DataType,
    key_directory: String,
    key_version: String,
    public_key: PublicKey,
}

impl IronCrypt {
    pub fn sign_audit_log(&self) -> Result<(), IronCryptError> {
        let audit_config = self.config.audit.as_ref().ok_or_else(|| {
            IronCryptError::ConfigurationError("Audit configuration is not set.".to_string())
        })?;

        let signing_key_path = audit_config.signing_key_path.as_ref().ok_or_else(|| {
            IronCryptError::ConfigurationError(
                "Audit log signing key path is not configured.".to_string(),
            )
        })?;

        let log_content = fs::read_to_string(&audit_config.log_path)?;

        // For signing the audit log, we don't assume a standard passphrase.
        // The key should ideally be protected by other means (e.g., file permissions).
        let private_key = load_any_private_key(signing_key_path, None)?;

        let rsa_private_key = match private_key {
            PrivateKey::Rsa(key) => key,
            PrivateKey::Ecc(_) => {
                return Err(IronCryptError::UnsupportedOperation(
                    "Log signing is only supported with RSA keys.".to_string(),
                ))
            }
        };

        let mut hasher = Sha256::new();
        hasher.update(log_content.as_bytes());
        let hash = hasher.finalize();

        let signature = rsa_utils::sign_hash(&rsa_private_key, &hash)?;

        let signature_path = format!("{}.sig", audit_config.log_path);
        fs::write(signature_path, base64_standard.encode(signature))?;

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
                    return Err(IronCryptError::ConfigurationError(
                        "Google Cloud provider is not yet supported".to_string(),
                    ))
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

        let (key_directory, key_version) = if let Some(dt_cfg) = &config.data_type_config {
            if let Some(km) = dt_cfg.get(&data_type) {
                (km.key_directory.clone(), km.key_version.clone())
            } else {
                ("keys".to_string(), "v1".to_string())
            }
        } else {
            ("keys".to_string(), "v1".to_string())
        };

        ensure_keys_exist(&key_directory, &key_version, &config)?;
        let public_key_path = format!("{}/public_key_{}.pem", key_directory, key_version);
        let public_key = load_any_public_key(&public_key_path)?;

        Ok(Self {
            config,
            secret_store,
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
            data_type,
            key_directory,
            key_version,
            public_key,
        })
    }

    pub fn encrypt_password(&self, password: &str) -> Result<String, IronCryptError> {
        self.encrypt_binary_data(b"", password)
    }

    pub fn verify_password(
        &self,
        encrypted_json: &str,
        user_input_password: &str,
    ) -> Result<bool, IronCryptError> {
        match self.decrypt_binary_data(encrypted_json, user_input_password) {
            Ok(_) => Ok(true),
            Err(IronCryptError::DecryptionError(_)) => Ok(false),
            Err(e) => Err(e),
        }
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

    pub fn encrypt_binary_data(
        &self,
        data: &[u8],
        password: &str,
    ) -> Result<String, IronCryptError> {
        let mut event = AuditEvent::new(Operation::Encrypt);
        event.key_version = Some(self.key_version.to_string());
        event.symmetric_algorithm = Some(self.config.symmetric_algorithm.to_string());

        let result: Result<String, IronCryptError> = (|| {
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
                Some(base64_standard.encode(hash_str))
            } else {
                None
            };
            pwd_string.zeroize();

            let mut symmetric_key = [0u8; 32];
            OsRng.fill_bytes(&mut symmetric_key);

            let sym_algo = self.config.symmetric_algorithm;
            let nonce_len = match sym_algo {
                SymmetricAlgorithm::Aes256Gcm => 12,
                SymmetricAlgorithm::ChaCha20Poly1305 => 24,
            };
            let mut nonce_bytes = vec![0u8; nonce_len];
            OsRng.fill_bytes(&mut nonce_bytes);

            let ciphertext = match sym_algo {
                SymmetricAlgorithm::Aes256Gcm => {
                    let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
                    cipher.encrypt(Nonce::from_slice(&nonce_bytes), data)?
                }
                SymmetricAlgorithm::ChaCha20Poly1305 => {
                    let cipher = XChaCha20Poly1305::new_from_slice(&symmetric_key)?;
                    cipher.encrypt(Nonce::from_slice(&nonce_bytes), data)?
                }
            };

            let recipient_info = match &self.public_key {
                PublicKey::Rsa(rsa_pub_key) => {
                    let padding = Oaep::new::<Sha256>();
                    let encrypted_symmetric_key =
                        rsa_pub_key.encrypt(&mut OsRng, padding, &symmetric_key)?;
                    RecipientInfo::Rsa {
                        key_version: self.key_version.clone(),
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
                        key_version: self.key_version.clone(),
                        ephemeral_public_key: base64_standard.encode(ephemeral_public_key_pem),
                        encrypted_symmetric_key: base64_standard.encode(kek.encapsulated_key),
                    }
                }
            };

            let enc_data = EncryptedData {
                symmetric_algorithm: sym_algo,
                recipient_info,
                nonce: base64_standard.encode(&nonce_bytes),
                ciphertext: base64_standard.encode(&ciphertext),
                password_hash,
            };

            symmetric_key.zeroize();
            Ok(serde_json::to_string(&enc_data)?)
        })();

        if let Err(e) = &result {
            event.outcome = Outcome::Failure;
            event.error_message = Some(e.to_string());
        } else {
            event.outcome = Outcome::Success;
        }
        event.log();

        result
    }

    pub fn decrypt_binary_data(
        &self,
        encrypted_json: &str,
        password: &str,
    ) -> Result<Vec<u8>, IronCryptError> {
        let mut event = AuditEvent::new(Operation::Decrypt);

        let result: Result<Vec<u8>, IronCryptError> = (|| {
            let ed: EncryptedData = serde_json::from_str(encrypted_json)?;

            let key_version = match &ed.recipient_info {
                RecipientInfo::Rsa { key_version, .. } => key_version.clone(),
                RecipientInfo::Ecc { key_version, .. } => key_version.clone(),
            };
            event.key_version = Some(key_version.to_string());
            event.symmetric_algorithm = Some(ed.symmetric_algorithm.to_string());

            let private_key_path = format!("{}/private_key_{}.pem", self.key_directory, key_version);
            let passphrase = self.get_passphrase()?;
            let private_key = load_any_private_key(&private_key_path, passphrase.as_deref())?;

            let mut symmetric_key = match (&private_key, &ed.recipient_info) {
                (
                    PrivateKey::Rsa(rsa_priv_key),
                    RecipientInfo::Rsa {
                        encrypted_symmetric_key,
                        ..
                    },
                ) => {
                    let key_bytes = base64_standard.decode(encrypted_symmetric_key)?;
                    rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?
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

            let ciphertext = base64_standard.decode(&ed.ciphertext)?;
            let nonce_bytes = base64_standard.decode(&ed.nonce)?;

            let plaintext_result = match ed.symmetric_algorithm {
                SymmetricAlgorithm::Aes256Gcm => {
                    let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
                    cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
                }
                SymmetricAlgorithm::ChaCha20Poly1305 => {
                    let cipher = XChaCha20Poly1305::new_from_slice(&symmetric_key)?;
                    cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
                }
            };

            symmetric_key.zeroize();

            let password_ok = if let Some(hash_b64) = ed.password_hash.as_ref() {
                crate::encrypt::check_password_hash(hash_b64, password)
            } else {
                true
            };

            if plaintext_result.is_err() || !password_ok {
                return Err(IronCryptError::DecryptionError(
                    "Invalid password or ciphertext".to_string(),
                ));
            }

            Ok(plaintext_result.unwrap())
        })();

        if let Err(e) = &result {
            event.outcome = Outcome::Failure;
            event.error_message = Some(e.to_string());
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
        let mut event = AuditEvent::new(Operation::Rekey);
        event.key_version = Some(new_key_version.to_string());

        let result: Result<String, IronCryptError> = (|| {
            let mut ed: EncryptedData = serde_json::from_str(encrypted_json)?;

            let old_key_version = match &ed.recipient_info {
                RecipientInfo::Rsa { key_version, .. } => key_version.clone(),
                RecipientInfo::Ecc { key_version, .. } => key_version.clone(),
            };

            let private_key_path =
                format!("{}/private_key_{}.pem", self.key_directory, old_key_version);
            let passphrase = self.get_passphrase()?;
            let old_private_key = load_any_private_key(&private_key_path, passphrase.as_deref())?;

            let mut symmetric_key = match (&old_private_key, &ed.recipient_info) {
                (
                    PrivateKey::Rsa(rsa_priv_key),
                    RecipientInfo::Rsa {
                        encrypted_symmetric_key,
                        ..
                    },
                ) => {
                    let key_bytes = base64_standard.decode(encrypted_symmetric_key)?;
                    rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?
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
            event.outcome = Outcome::Failure;
            event.error_message = Some(e.to_string());
        } else {
            event.outcome = Outcome::Success;
        }
        event.log();

        result
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
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
        event.signature_algorithm = Some("rsa-pkcs1v15-sha256".to_string());

        let result: Result<String, IronCryptError> = (|| {
            let private_key_path =
                format!("{}/private_key_{}.pem", self.key_directory, self.key_version);
            let passphrase = self.get_passphrase()?;
            let private_key = load_any_private_key(&private_key_path, passphrase.as_deref())?;

            let mut hasher = Sha256::new();
            hasher.update(data_to_sign);
            let hash = hasher.finalize();

            let signature = match private_key {
                PrivateKey::Rsa(key) => rsa_utils::sign_hash(&key, &hash)?,
                PrivateKey::Ecc(key) => ecc_utils::sign_hash_ecc(&key, &hash)?,
            };

            Ok(base64_standard.encode(signature))
        })();

        if let Err(e) = &result {
            event.outcome = Outcome::Failure;
            event.error_message = Some(e.to_string());
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
        let mut event = AuditEvent::new(Operation::Verify);
        event.key_version = Some(self.key_version.to_string());
        event.signature_algorithm = Some("rsa-pkcs1v15-sha256".to_string());

        let verification_result = (|| {
            let signature_bytes = base64_standard.decode(signature)?;

            let mut hasher = Sha256::new();
            hasher.update(data_to_verify);
            let hash = hasher.finalize();

            match &self.public_key {
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
            Err(IronCryptError::SignatureError(_)) => {
                event.outcome = Outcome::Failure;
                // Don't log the full signature error message, as it can be verbose
                // and is expected in a verification failure scenario.
                event.error_message = Some("Signature verification failed.".to_string());
                event.log();
                Ok(false)
            }
            Err(e) => {
                event.outcome = Outcome::Failure;
                event.error_message = Some(e.to_string());
                event.log();
                Err(e)
            }
        }
    }
}
