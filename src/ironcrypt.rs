use crate::{
    generate_rsa_keys, load_private_key, load_public_key, save_keys_to_files, IronCryptError,
};
use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use argon2::PasswordVerifier;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
// use rand::RngCore as MyRngCore;
use rsa::{Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::config::IronCryptConfig;
use crate::criteria::PasswordCriteria;

#[derive(Clone, Debug)]
pub struct Argon2Config {
    pub memory_cost: u32,
    pub time_cost: u32,
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

/// Structure returned after encryption (JSON + base64 data).
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
    pub nonce: String,
    pub ciphertext: String,
    /// Optional, if `hash_password` is `true`.
    pub password_hash: Option<String>,
}

/// The `IronCrypt` struct manages key generation/loading
/// and exposes methods for encrypting/decrypting a password or binary data.
pub struct IronCrypt {
    key_directory: String,
    key_version: String,
    pub config: IronCryptConfig,
}

impl IronCrypt {
    /// Creates a new IronCrypt instance (generates RSA keys if needed).
    pub fn new(
        directory: &str,
        version: &str,
        config: IronCryptConfig,
    ) -> Result<Self, IronCryptError> {
        let instance = Self {
            key_directory: directory.to_string(),
            key_version: version.to_string(),
            config,
        };
        instance.ensure_keys_exist()?;
        Ok(instance)
    }

    fn ensure_keys_exist(&self) -> Result<(), IronCryptError> {
        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);

        if !Path::new(&self.key_directory).exists() {
            fs::create_dir_all(&self.key_directory)?;
        }

        if !Path::new(&private_key_path).exists() {
            let (priv_key, pub_key) = generate_rsa_keys(self.config.rsa_key_size)?;
            save_keys_to_files(&priv_key, &pub_key, &private_key_path, &public_key_path)?;
        }
        Ok(())
    }

    /// Encrypts a password (existing logic).
    /// Returns a JSON string (base64) ready to be stored in "encrypted_data.json".
    pub fn encrypt_password(&self, password: &str) -> Result<String, IronCryptError> {
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);
        let public_key = load_public_key(&public_key_path)?;

        let mut pwd_string = password.to_string();
        let criteria: &PasswordCriteria = &self.config.password_criteria;

        let argon_cfg = Argon2Config {
            memory_cost: self.config.argon2_memory_cost,
            time_cost: self.config.argon2_time_cost,
            parallelism: self.config.argon2_parallelism,
        };

        // We encrypt empty data (b""), hashing the password (hash_password = true).
        let enc_data = self.encrypt_data_with_criteria(
            b"",
            &mut pwd_string,
            &public_key,
            criteria,
            &self.key_version,
            argon_cfg,
            true,
        )?;

        let json_str = serde_json::to_string(&enc_data)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
        Ok(json_str)
    }

    /// Verifies a password by decrypting the JSON string (existing logic).
    pub fn verify_password(
        &self,
        encrypted_json: &str,
        user_input_password: &str,
    ) -> Result<bool, IronCryptError> {
        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        self.decrypt_data_and_verify_password(
            encrypted_json,
            user_input_password,
            &private_key_path,
        )
    }

    // --------------------------------------------------------------------
    //                          NEW METHODS
    // --------------------------------------------------------------------

    /// Encrypts any binary data into JSON (base64).
    /// The `password` can be used (or not) to enforce Argon2; if `hash_password=false`, the hash is ignored.
    pub fn encrypt_binary_data(
        &self,
        data: &[u8],
        password: &str,
    ) -> Result<String, IronCryptError> {
        // 1) Load the public key
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);
        let public_key = load_public_key(&public_key_path)?;

        // 2) Convert to mutable (necessary if we hash the password)
        let mut pwd_string = password.to_string();

        // 3) We can decide here not to hash the password. For the example, "false".
        //    If you want Argon2, set to "true" and adapt "criteria" etc.
        let hash_it = !password.is_empty();

        let enc_data = self.encrypt_data_with_criteria(
            data,
            &mut pwd_string,
            &public_key,
            &self.config.password_criteria,
            &self.key_version,
            Argon2Config::default(),
            hash_it,
        )?;

        // 4) Serialize to JSON
        let json_str = serde_json::to_string(&enc_data)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
        Ok(json_str)
    }

    /// Decrypts a JSON (base64) representing binary data
    /// and returns a `Vec<u8>` (the original binary).
    pub fn decrypt_binary_data(
        &self,
        encrypted_json: &str,
        password: &str,
    ) -> Result<Vec<u8>, IronCryptError> {
        // 1) Deserialize JSON -> EncryptedData
        let ed: EncryptedData = serde_json::from_str(encrypted_json)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        // 2) Load the private key
        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        let private_key = load_private_key(&private_key_path)?;

        // 3) Decrypt the symmetric key
        let encrypted_key_bytes = base64_standard
            .decode(&ed.encrypted_symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(format!("Symkey decode error: {e}")))?;

        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key
            .decrypt(padding, &encrypted_key_bytes)
            .map_err(|e| IronCryptError::DecryptionError(format!("RSA decrypt error: {e}")))?;

        // 4) Decrypt the data (ciphertext)
        let ciphertext = base64_standard.decode(&ed.ciphertext).map_err(|e| {
            IronCryptError::DecryptionError(format!("Ciphertext decode error: {e}"))
        })?;

        let nonce_bytes = base64_standard
            .decode(&ed.nonce)
            .map_err(|e| IronCryptError::DecryptionError(format!("Nonce decode error: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(format!("AES init error: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| IronCryptError::DecryptionError(format!("AES decrypt error: {e}")))?;

        // 5) If "ed.password_hash" exists => compare Argon2 + `password`
        if let Some(hash_b64) = ed.password_hash.as_ref() {
            let decoded_hash = base64_standard.decode(hash_b64).map_err(|e| {
                IronCryptError::DecryptionError(format!("password_hash decode error: {e}"))
            })?;
            let hash_str = String::from_utf8(decoded_hash)
                .map_err(|e| IronCryptError::DecryptionError(format!("UTF8 decode error: {e}")))?;

            // Verify
            let parsed_hash = PasswordHash::new(&hash_str)
                .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
            let argon2 = Argon2::default();
            if argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_err()
            {
                return Err(IronCryptError::InvalidPassword);
            }
        }

        // Return the decrypted binary
        Ok(plaintext)
    }

    /// Re-encrypts existing data with a new public key.
    pub fn re_encrypt_data(
        &self,
        encrypted_json: &str,
        new_public_key: &RsaPublicKey,
        new_key_version: &str,
    ) -> Result<String, IronCryptError> {
        // 1. Deserialize the existing encrypted data
        let mut ed: EncryptedData = serde_json::from_str(encrypted_json)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        // 2. Load the current private key to decrypt the symmetric key
        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        let private_key = load_private_key(&private_key_path)?;

        // 3. Decrypt the symmetric key
        let encrypted_key_bytes = base64_standard
            .decode(&ed.encrypted_symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key
            .decrypt(padding, &encrypted_key_bytes)
            .map_err(|e| IronCryptError::DecryptionError(format!("RSA decryption error: {}", e)))?;

        // 4. Re-encrypt the symmetric key with the new public key
        let new_padding = Oaep::new::<Sha256>();
        let new_encrypted_symmetric_key = new_public_key
            .encrypt(&mut OsRng, new_padding, &symmetric_key)
            .map_err(|e| IronCryptError::EncryptionError(format!("RSA encryption error: {}", e)))?;

        // 5. Update the data structure with the new key and version
        ed.key_version = new_key_version.to_string();
        ed.encrypted_symmetric_key = base64_standard.encode(new_encrypted_symmetric_key);

        // 6. Serialize the new data to JSON
        serde_json::to_string(&ed)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))
    }

    // --------------------------------------------------------------------
    //                          Existing internal methods
    // --------------------------------------------------------------------

    fn encrypt_data_with_criteria(
        &self,
        data: &[u8],
        password: &mut String,
        public_key: &RsaPublicKey,
        criteria: &PasswordCriteria,
        key_version: &str,
        argon_cfg: Argon2Config,
        hash_password: bool,
    ) -> Result<EncryptedData, IronCryptError> {
        // 1) Check strength if needed
        if hash_password {
            criteria.validate(password)?;
        }

        // 2) Optional hashing
        let password_hash = if hash_password {
            let params = Params::new(
                argon_cfg.memory_cost,
                argon_cfg.time_cost,
                argon_cfg.parallelism,
                None,
            )?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let salt = SaltString::generate(&mut OsRng);

            let hash_str = argon2
                .hash_password(password.as_bytes(), &salt)?
                .to_string();
            Some(base64_standard.encode(hash_str))
        } else {
            None
        };

        // 3) Symmetric key
        let mut symmetric_key = [0u8; 32];
        OsRng.fill_bytes(&mut symmetric_key);

        // 4) AES-GCM
        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| IronCryptError::EncryptionError(format!("AES encryption: {e}")))?;

        // 5) RSA encryption of the symmetric key
        let padding = Oaep::new::<Sha256>();
        let encrypted_symmetric_key = public_key
            .encrypt(&mut OsRng, padding, &symmetric_key)
            .map_err(|e| IronCryptError::EncryptionError(format!("RSA encryption: {e}")))?;

        let result = EncryptedData {
            key_version: key_version.to_string(),
            encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
            nonce: base64_standard.encode(&nonce_bytes),
            ciphertext: base64_standard.encode(&ciphertext),
            password_hash,
        };

        symmetric_key.zeroize();
        password.zeroize();

        Ok(result)
    }

    fn decrypt_data_and_verify_password(
        &self,
        encrypted_data_json: &str,
        input_password: &str,
        private_key_pem_path: &str,
    ) -> Result<bool, IronCryptError> {
        let ed: EncryptedData = serde_json::from_str(encrypted_data_json)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        // 1) Load the private key
        let private_key = load_private_key(private_key_pem_path)?;

        // 2) Decrypt the symmetric key
        let encrypted_key_bytes = base64_standard
            .decode(ed.encrypted_symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key
            .decrypt(padding, &encrypted_key_bytes)
            .map_err(|e| IronCryptError::DecryptionError(format!("RSA decrypt error: {e}")))?;

        // 3) AES decrypt
        let ciphertext = base64_standard
            .decode(ed.ciphertext)
            .map_err(|e| IronCryptError::DecryptionError(format!("Decode ciphertext: {e}")))?;
        let nonce_bytes = base64_standard
            .decode(ed.nonce)
            .map_err(|e| IronCryptError::DecryptionError(format!("Decode nonce: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let _plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| IronCryptError::DecryptionError(format!("AES decrypt error: {e}")))?;

        // 4) Compare Argon2 hash if password_hash exists
        if let Some(hash_b64) = ed.password_hash {
            let decoded_hash = base64_standard
                .decode(hash_b64)
                .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
            let hash_str = String::from_utf8(decoded_hash)
                .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
            let parsed_hash = PasswordHash::new(&hash_str)
                .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
            let argon2 = Argon2::default();
            if argon2
                .verify_password(input_password.as_bytes(), &parsed_hash)
                .is_err()
            {
                return Err(IronCryptError::InvalidPassword);
            }
        }

        Ok(true)
    }
}