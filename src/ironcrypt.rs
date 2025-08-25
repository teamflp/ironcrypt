use crate::{
    config::{DataType, IronCryptConfig},
    criteria::PasswordCriteria,
    generate_rsa_keys,
    handle_error::IronCryptError,
    load_private_key, load_public_key, save_keys_to_files,
    secrets::{aws::AwsStore, azure::AzureStore, vault::VaultStore, SecretStore},
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordVerifier, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use rsa::{Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

// Helper function to ensure keys exist and load the public key
fn ensure_and_load_public_key_from_paths(
    key_directory: &str,
    key_version: &str,
    rsa_key_size: u32,
) -> Result<RsaPublicKey, IronCryptError> {
    let private_key_path = format!("{}/private_key_{}.pem", key_directory, key_version);
    let public_key_path = format!("{}/public_key_{}.pem", key_directory, key_version);

    if !Path::new(key_directory).exists() {
        fs::create_dir_all(key_directory)?;
    }
    if !Path::new(&private_key_path).exists() || !Path::new(&public_key_path).exists() {
        let (priv_key, pub_key) = generate_rsa_keys(rsa_key_size)?;
        save_keys_to_files(
            &priv_key,
            &pub_key,
            &private_key_path,
            &public_key_path,
            None,
        )?;
    }
    load_public_key(&public_key_path)
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

/// Contains the encrypted data along with the metadata needed for decryption.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    /// The version of the RSA key used for encryption.
    pub key_version: String,
    /// The symmetric (AES) key encrypted with the RSA public key.
    pub encrypted_symmetric_key: String,
    /// The nonce (unique number) used for AES-GCM encryption.
    pub nonce: String,
    /// The encrypted data (ciphertext).
    pub ciphertext: String,
    /// The hash of the password (if a password was used).
    pub password_hash: Option<String>,
    /// The data type, for managing specific configurations.
    pub data_type: Option<String>,
}

/// Internal context used for encryption.
struct EncryptionContext<'a> {
    public_key: &'a RsaPublicKey,
    criteria: &'a PasswordCriteria,
    key_version: &'a str,
    argon_cfg: Argon2Config,
    hash_password: bool,
}

/// The main entry point for cryptographic operations with IronCrypt.
///
/// This struct provides a high-level interface for encrypting and verifying
/// passwords, as well as encrypting and decrypting binary data.
/// It automatically handles the generation and loading of RSA keys.
pub struct IronCrypt {
    /// The configuration used by the `IronCrypt` instance.
    pub config: IronCryptConfig,
    /// The secret store (e.g., Vault, AWS Secrets Manager).
    secret_store: Option<Box<dyn SecretStore + Send + Sync>>,
    /// The data type, to apply the corresponding key configuration.
    data_type: DataType,
    /// The directory where the keys are stored.
    key_directory: String,
    /// The version of the key to use.
    key_version: String,
    /// The loaded RSA public key.
    public_key: RsaPublicKey,
}

impl IronCrypt {
    /// Creates a new instance of `IronCrypt`.
    ///
    /// This function initializes the configuration, loads or generates the necessary RSA keys,
    /// and sets up a secret store if specified in the configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - An `IronCryptConfig` instance that defines the security parameters.
    /// * `data_type` - A `DataType` that specifies which key set to use.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `IronCrypt` instance or an `IronCryptError` on failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ironcrypt::{IronCrypt, IronCryptConfig, DataType};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let config = IronCryptConfig::default();
    ///     let crypt = IronCrypt::new(config, DataType::Generic).await.unwrap();
    ///     println!("IronCrypt initialized with key version: {}", crypt.key_version());
    ///     // Cleanup
    ///     std::fs::remove_dir_all("keys").unwrap();
    /// }
    /// ```
    pub async fn new(
        config: IronCryptConfig,
        data_type: DataType,
    ) -> Result<Self, IronCryptError> {
        let secret_store = if let Some(secrets_config) = &config.secrets {
            match secrets_config.provider.as_str() {
                "vault" => {
                    let vault_config = secrets_config.vault.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(
                            "Vault provider selected but no vault config provided".to_string(),
                        )
                    })?;
                    let store = VaultStore::new(vault_config, &vault_config.mount)?;
                    Some(Box::new(store) as Box<dyn SecretStore + Send + Sync>)
                }
                "aws" => {
                    let aws_config = secrets_config.aws.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(
                            "AWS provider selected but no AWS config provided".to_string(),
                        )
                    })?;
                    let store = AwsStore::new(aws_config).await?;
                    Some(Box::new(store) as Box<dyn SecretStore + Send + Sync>)
                }
                "azure" => {
                    let azure_config = secrets_config.azure.as_ref().ok_or_else(|| {
                        IronCryptError::ConfigurationError(
                            "Azure provider selected but no Azure config provided".to_string(),
                        )
                    })?;
                    let store = AzureStore::new(azure_config).await?;
                    Some(Box::new(store) as Box<dyn SecretStore + Send + Sync>)
                }
                "google" => {
                    return Err(IronCryptError::ConfigurationError(
                        "Google provider is temporarily disabled.".to_string(),
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

        let public_key = ensure_and_load_public_key_from_paths(
            &key_directory,
            &key_version,
            config.rsa_key_size,
        )?;

        Ok(Self {
            config,
            secret_store,
            data_type,
            key_directory,
            key_version,
            public_key,
        })
    }

    /// Creates an `IronCrypt` instance with a custom secret store.
    /// (Mainly used for testing).
    #[doc(hidden)]
    pub fn with_store(
        config: IronCryptConfig,
        data_type: DataType,
        secret_store: Box<dyn SecretStore + Send + Sync>,
        key_directory: String,
        key_version: String,
    ) -> Result<Self, IronCryptError> {
        let public_key = ensure_and_load_public_key_from_paths(
            &key_directory,
            &key_version,
            config.rsa_key_size,
        )?;

        Ok(Self {
            config,
            secret_store: Some(secret_store),
            data_type,
            key_directory,
            key_version,
            public_key,
        })
    }

    /// Encrypts a password.
    ///
    /// This method hashes the password with Argon2 and then encrypts the hash
    /// using a hybrid encryption scheme (AES + RSA).
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to encrypt.
    ///
    /// # Returns
    ///
    /// A JSON string containing the encrypted data, or an `IronCryptError`.
    pub fn encrypt_password(&self, password: &str) -> Result<String, IronCryptError> {
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);
        let public_key = load_public_key(&public_key_path)?;
        let mut pwd_string = password.to_string();
        let criteria = &self.config.password_criteria;
        let argon_cfg = Argon2Config {
            memory_cost: self.config.argon2_memory_cost,
            time_cost: self.config.argon2_time_cost,
            parallelism: self.config.argon2_parallelism,
        };
        let context = EncryptionContext {
            public_key: &public_key,
            criteria,
            key_version: &self.key_version,
            argon_cfg,
            hash_password: true,
        };
        let enc_data = self.encrypt_data_with_context(b"", &mut pwd_string, &context)?;
        Ok(serde_json::to_string(&enc_data)?)
    }

    /// Verifies a password against its encrypted version.
    ///
    /// # Arguments
    ///
    /// * `encrypted_json` - The JSON string produced by `encrypt_password`.
    /// * `user_input_password` - The plaintext password provided by the user.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the password is correct, `Err(IronCryptError::InvalidPassword)`
    /// if it is incorrect, or another error on failure.
    pub fn verify_password(
        &self,
        encrypted_json: &str,
        user_input_password: &str,
    ) -> Result<bool, IronCryptError> {
        let ed: EncryptedData = serde_json::from_str(encrypted_json)?;
        let private_key_path =
            format!("{}/private_key_{}.pem", self.key_directory, ed.key_version);
        let passphrase = self.get_passphrase()?;
        self.decrypt_data_and_verify_password(
            encrypted_json,
            user_input_password,
            &private_key_path,
            passphrase.as_deref(),
        )
    }

    /// Stores a secret in the configured secret store.
    pub async fn store_secret(&self, key: &str, value: &str) -> Result<(), IronCryptError> {
        if let Some(store) = &self.secret_store {
            store.set_secret(key, value).await.map_err(IronCryptError::from)
        } else {
            Err(IronCryptError::ConfigurationError(
                "No secret store configured".to_string(),
            ))
        }
    }

    /// Retrieves a secret from the secret store.
    pub async fn retrieve_secret(&self, key: &str) -> Result<String, IronCryptError> {
        if let Some(store) = &self.secret_store {
            store.get_secret(key).await.map_err(IronCryptError::from)
        } else {
            Err(IronCryptError::ConfigurationError(
                "No secret store configured".to_string(),
            ))
        }
    }

    /// Encrypts a block of binary data.
    ///
    /// # Arguments
    ///
    /// * `data` - The binary data to encrypt.
    /// * `password` - An optional password to strengthen security.
    ///
    /// # Returns
    ///
    /// A JSON string containing the encrypted data.
    pub fn encrypt_binary_data(
        &self,
        data: &[u8],
        password: &str,
    ) -> Result<String, IronCryptError> {
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);
        let public_key = load_public_key(&public_key_path)?;
        let mut pwd_string = password.to_string();
        let context = EncryptionContext {
            public_key: &public_key,
            criteria: &self.config.password_criteria,
            key_version: &self.key_version,
            argon_cfg: Argon2Config::default(),
            hash_password: !password.is_empty(),
        };
        let enc_data = self.encrypt_data_with_context(data, &mut pwd_string, &context)?;
        Ok(serde_json::to_string(&enc_data)?)
    }

    /// Decrypts a block of binary data.
    ///
    /// # Arguments
    ///
    /// * `encrypted_json` - The JSON string produced by `encrypt_binary_data`.
    /// * `password` - The password used during encryption.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the decrypted data.
    pub fn decrypt_binary_data(
        &self,
        encrypted_json: &str,
        password: &str,
    ) -> Result<Vec<u8>, IronCryptError> {
        let ed: EncryptedData = serde_json::from_str(encrypted_json)?;

        let private_key_path =
            format!("{}/private_key_{}.pem", self.key_directory, self.key_version);
        let passphrase = self.get_passphrase()?;
        let private_key = load_private_key(&private_key_path, passphrase.as_deref())?;

        let encrypted_key_bytes = base64_standard.decode(&ed.encrypted_symmetric_key)?;
        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key.decrypt(padding, &encrypted_key_bytes)?;

        let ciphertext = base64_standard.decode(&ed.ciphertext)?;
        let nonce_bytes = base64_standard.decode(&ed.nonce)?;

        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;

        if let Some(hash_b64) = ed.password_hash.as_ref() {
            let decoded_hash = base64_standard.decode(hash_b64)?;
            let hash_str = String::from_utf8(decoded_hash)?;
            let parsed_hash = PasswordHash::new(&hash_str)?;
            if Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_err()
            {
                return Err(IronCryptError::InvalidPassword);
            }
        }

        Ok(plaintext)
    }

    /// Re-encrypts data with a new public key (key rotation).
    ///
    /// # Arguments
    ///
    /// * `encrypted_json` - The currently encrypted data.
    /// * `new_public_key` - The new RSA public key to use.
    /// * `new_key_version` - The version name of the new key.
    ///
    /// # Returns
    ///
    /// A new JSON string containing the re-encrypted data.
    pub fn re_encrypt_data(
        &self,
        encrypted_json: &str,
        new_public_key: &RsaPublicKey,
        new_key_version: &str,
    ) -> Result<String, IronCryptError> {
        let mut ed: EncryptedData = serde_json::from_str(encrypted_json)?;

        let private_key_path =
            format!("{}/private_key_{}.pem", self.key_directory, self.key_version);
        let passphrase = self.get_passphrase()?;
        let private_key = load_private_key(&private_key_path, passphrase.as_deref())?;

        let encrypted_key_bytes = base64_standard.decode(&ed.encrypted_symmetric_key)?;
        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key.decrypt(padding, &encrypted_key_bytes)?;

        let new_padding = Oaep::new::<Sha256>();
        let new_encrypted_symmetric_key =
            new_public_key.encrypt(&mut OsRng, new_padding, &symmetric_key)?;

        ed.key_version = new_key_version.to_string();
        ed.encrypted_symmetric_key = base64_standard.encode(new_encrypted_symmetric_key);

        Ok(serde_json::to_string(&ed)?)
    }

    /// Internal function for encryption.
    fn encrypt_data_with_context(
        &self,
        data: &[u8],
        password: &mut String,
        context: &EncryptionContext,
    ) -> Result<EncryptedData, IronCryptError> {
        if context.hash_password {
            context.criteria.validate(password)?;
        }

        let password_hash = if context.hash_password {
            let params = Params::new(
                context.argon_cfg.memory_cost,
                context.argon_cfg.time_cost,
                context.argon_cfg.parallelism,
                None,
            )?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let salt = SaltString::generate(&mut OsRng);
            let hash_str = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
            Some(base64_standard.encode(hash_str))
        } else {
            None
        };

        let mut symmetric_key = [0u8; 32];
        OsRng.fill_bytes(&mut symmetric_key);

        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data)?;

        let padding = Oaep::new::<Sha256>();
        let encrypted_symmetric_key =
            context.public_key.encrypt(&mut OsRng, padding, &symmetric_key)?;

        let result = EncryptedData {
            key_version: context.key_version.to_string(),
            encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
            nonce: base64_standard.encode(nonce_bytes),
            ciphertext: base64_standard.encode(&ciphertext),
            password_hash,
            data_type: Some(format!("{:?}", self.data_type)),
        };

        symmetric_key.zeroize();
        password.zeroize();

        Ok(result)
    }

    /// Internal function for decryption and verification.
    fn decrypt_data_and_verify_password(
        &self,
        encrypted_data_json: &str,
        input_password: &str,
        private_key_pem_path: &str,
        passphrase: Option<&str>,
    ) -> Result<bool, IronCryptError> {
        let ed: EncryptedData = serde_json::from_str(encrypted_data_json)?;

        let private_key = load_private_key(private_key_pem_path, passphrase)?;
        let encrypted_key_bytes = base64_standard.decode(ed.encrypted_symmetric_key)?;
        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key.decrypt(padding, &encrypted_key_bytes)?;

        let ciphertext = base64_standard.decode(ed.ciphertext)?;
        let nonce_bytes = base64_standard.decode(ed.nonce)?;
        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let _ = cipher.decrypt(nonce, ciphertext.as_ref())?;

        if let Some(hash_b64) = ed.password_hash {
            let decoded_hash = base64_standard.decode(hash_b64)?;
            let hash_str = String::from_utf8(decoded_hash)?;
            let parsed_hash = PasswordHash::new(&hash_str)?;
            if Argon2::default()
                .verify_password(input_password.as_bytes(), &parsed_hash)
                .is_err()
            {
                return Err(IronCryptError::InvalidPassword);
            }
        }
        Ok(true)
    }

    /// Returns a reference to the RSA public key in use.
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// Returns the version of the key currently in use.
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
}
