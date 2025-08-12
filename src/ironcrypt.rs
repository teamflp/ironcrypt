use crate::{
    config::IronCryptConfig, criteria::PasswordCriteria, generate_rsa_keys, load_private_key,
    load_public_key, save_keys_to_files, IronCryptError,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version, PasswordVerifier};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use rsa::{Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

/// Holds the result of an encryption operation.
///
/// This struct contains all the necessary components, serialized as base64-encoded strings,
/// to decrypt the original data. It is typically serialized to a JSON string for storage.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    /// The version of the RSA key pair used for this encryption.
    pub key_version: String,
    /// The AES symmetric key, encrypted with the RSA public key.
    pub encrypted_symmetric_key: String,
    /// A unique nonce used for the AES-GCM encryption.
    pub nonce: String,
    /// The actual data, encrypted with AES-GCM.
    pub ciphertext: String,
    /// An optional Argon2 password hash. This is present when encrypting
    /// a password, allowing for verification without decrypting any data.
    pub password_hash: Option<String>,
}

/// The main struct for handling cryptographic operations in IronCrypt.
///
/// `IronCrypt` provides a high-level API for encrypting and decrypting passwords and binary data
/// using a combination of RSA, AES, and Argon2. An `IronCrypt` instance is tied to a specific
/// key version and configuration.
pub struct IronCrypt {
    key_directory: String,
    key_version: String,
    /// The configuration used by this `IronCrypt` instance.
    pub config: IronCryptConfig,
}

impl IronCrypt {
    /// Creates a new `IronCrypt` instance.
    ///
    /// This function initializes the cryptosystem for a specific key version. If the RSA key pair
    /// for the given version does not exist in the specified directory, it will be generated automatically.
    ///
    /// # Arguments
    ///
    /// * `directory`: The path to the directory where RSA keys are stored.
    /// * `version`: The version identifier for the keys (e.g., "v1").
    /// * `config`: The `IronCryptConfig` specifying the security parameters to use.
    ///
    /// # Errors
    ///
    /// Returns an error if the key directory cannot be created or if key generation fails.
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

    /// Ensures that the RSA key pair for the instance's version exists, generating it if not.
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

    /// Hashes and encrypts a password.
    ///
    /// This method is specifically for handling passwords. It first validates the password against
    /// the configured criteria, then hashes it with Argon2. The resulting hash is then encrypted.
    /// The primary use case is storing user passwords securely.
    ///
    /// # Arguments
    ///
    /// * `password`: The password to hash and encrypt.
    ///
    /// # Returns
    ///
    /// A JSON string containing the `EncryptedData`, ready for storage.
    pub fn encrypt_password(&self, password: &str) -> Result<String, IronCryptError> {
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);
        let public_key = load_public_key(&public_key_path)?;

        let mut pwd_string = password.to_string();
        let criteria: &PasswordCriteria = &self.config.password_criteria;

        // Encrypt empty data, as the password itself is stored in the hash.
        let enc_data = self.encrypt_data_with_criteria(
            b"",
            &mut pwd_string,
            &public_key,
            criteria,
            &self.key_version,
            true,
        )?;

        let json_str = serde_json::to_string(&enc_data)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
        Ok(json_str)
    }

    /// Verifies a password against previously encrypted data.
    ///
    /// This method takes an encrypted JSON string (as produced by `encrypt_password`) and a
    /// plaintext password attempt. It decrypts the necessary data and uses Argon2 to securely
    /// compare the provided password against the stored hash.
    ///
    /// # Arguments
    ///
    /// * `encrypted_json`: The JSON string produced by `encrypt_password`.
    /// * `user_input_password`: The plaintext password to verify.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the password is correct. Returns `Err(IronCryptError::InvalidPassword)`
    /// if it is incorrect.
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

    /// Encrypts arbitrary binary data.
    ///
    /// This method can be used to encrypt any data (e.g., file contents).
    /// An optional password can be provided to also derive and store a verifiable Argon2 hash,
    /// though this is less common for non-password data.
    ///
    /// # Arguments
    ///
    /// * `data`: A slice of bytes representing the data to encrypt.
    /// * `password`: An optional password. If not empty, it will be hashed and included in the
    ///   encrypted payload for later verification.
    ///
    /// # Returns
    ///
    /// A JSON string containing the `EncryptedData`, ready for storage.
    pub fn encrypt_binary_data(
        &self,
        data: &[u8],
        password: &str,
    ) -> Result<String, IronCryptError> {
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);
        let public_key = load_public_key(&public_key_path)?;

        let mut pwd_string = password.to_string();
        let hash_it = !password.is_empty();

        let enc_data = self.encrypt_data_with_criteria(
            data,
            &mut pwd_string,
            &public_key,
            &self.config.password_criteria,
            &self.key_version,
            hash_it,
        )?;

        let json_str = serde_json::to_string(&enc_data)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
        Ok(json_str)
    }

    /// Decrypts a JSON string to retrieve the original binary data.
    ///
    /// If the data was encrypted with a password, the same password must be provided here
    /// to successfully verify the hash before decryption.
    ///
    /// # Arguments
    ///
    /// * `encrypted_json`: The JSON string produced by `encrypt_binary_data` or `encrypt_password`.
    /// * `password`: The password to use for verification, if one was used during encryption.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the original plaintext data.
    pub fn decrypt_binary_data(
        &self,
        encrypted_json: &str,
        password: &str,
    ) -> Result<Vec<u8>, IronCryptError> {
        let ed: EncryptedData = serde_json::from_str(encrypted_json)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        let private_key = load_private_key(&private_key_path)?;

        let encrypted_key_bytes = base64_standard
            .decode(&ed.encrypted_symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(format!("Failed to decode symmetric key: {e}")))?;

        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key
            .decrypt(padding, &encrypted_key_bytes)
            .map_err(|e| IronCryptError::DecryptionError(format!("RSA decrypt error: {e}")))?;

        let ciphertext = base64_standard.decode(&ed.ciphertext).map_err(|e| {
            IronCryptError::DecryptionError(format!("Failed to decode ciphertext: {e}"))
        })?;

        let nonce_bytes = base64_standard
            .decode(&ed.nonce)
            .map_err(|e| IronCryptError::DecryptionError(format!("Failed to decode nonce: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(format!("Failed to initialize AES: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| IronCryptError::DecryptionError(format!("AES decrypt error: {e}")))?;

        if let Some(hash_b64) = ed.password_hash.as_ref() {
            let decoded_hash = base64_standard.decode(hash_b64).map_err(|e| {
                IronCryptError::DecryptionError(format!("Failed to decode password_hash: {e}"))
            })?;
            let hash_str = String::from_utf8(decoded_hash)
                .map_err(|e| IronCryptError::DecryptionError(format!("UTF8 decode error: {e}")))?;

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

        Ok(plaintext)
    }

    /// Re-encrypts existing data with a new public key.
    ///
    /// This function is the core of the key rotation feature. It decrypts the symmetric key
    /// using the old private key and then re-encrypts it with the new public key, updating
    /// the key version in the process. The actual encrypted data is not touched.
    ///
    /// # Arguments
    ///
    /// * `encrypted_json`: The JSON string of the data to re-encrypt.
    /// * `new_public_key`: The new `RsaPublicKey` to use for re-encryption.
    /// * `new_key_version`: The version string for the new key.
    ///
    /// # Returns
    ///
    /// A new JSON string with the data re-encrypted under the new key.
    pub fn re_encrypt_data(
        &self,
        encrypted_json: &str,
        new_public_key: &RsaPublicKey,
        new_key_version: &str,
    ) -> Result<String, IronCryptError> {
        let mut ed: EncryptedData = serde_json::from_str(encrypted_json)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        let private_key = load_private_key(&private_key_path)?;

        let encrypted_key_bytes = base64_standard
            .decode(&ed.encrypted_symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key
            .decrypt(padding, &encrypted_key_bytes)
            .map_err(|e| IronCryptError::DecryptionError(format!("RSA decryption error: {}", e)))?;

        let new_padding = Oaep::new::<Sha256>();
        let new_encrypted_symmetric_key = new_public_key
            .encrypt(&mut OsRng, new_padding, &symmetric_key)
            .map_err(|e| IronCryptError::EncryptionError(format!("RSA encryption error: {}", e)))?;

        ed.key_version = new_key_version.to_string();
        ed.encrypted_symmetric_key = base64_standard.encode(new_encrypted_symmetric_key);

        serde_json::to_string(&ed)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))
    }

    /// Internal function to handle the core encryption logic.
    fn encrypt_data_with_criteria(
        &self,
        data: &[u8],
        password: &mut String,
        public_key: &RsaPublicKey,
        criteria: &PasswordCriteria,
        key_version: &str,
        hash_password: bool,
    ) -> Result<EncryptedData, IronCryptError> {
        if hash_password {
            criteria.validate(password)?;
        }

        let password_hash = if hash_password {
            let params = Params::new(
                self.config.argon2_memory_cost,
                self.config.argon2_time_cost,
                self.config.argon2_parallelism,
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

        let mut symmetric_key = vec![0u8; self.config.aes_key_size / 8];
        OsRng.fill_bytes(&mut symmetric_key);

        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12]; // AES-GCM standard nonce size
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| IronCryptError::EncryptionError(format!("AES encryption error: {e}")))?;

        let padding = Oaep::new::<Sha256>();
        let encrypted_symmetric_key = public_key
            .encrypt(&mut OsRng, padding, &symmetric_key)
            .map_err(|e| IronCryptError::EncryptionError(format!("RSA encryption error: {e}")))?;

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

    /// Internal function to handle decryption and password verification.
    fn decrypt_data_and_verify_password(
        &self,
        encrypted_data_json: &str,
        input_password: &str,
        private_key_pem_path: &str,
    ) -> Result<bool, IronCryptError> {
        let ed: EncryptedData = serde_json::from_str(encrypted_data_json)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        let private_key = load_private_key(private_key_pem_path)?;

        let encrypted_key_bytes = base64_standard
            .decode(ed.encrypted_symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key
            .decrypt(padding, &encrypted_key_bytes)
            .map_err(|e| IronCryptError::DecryptionError(format!("RSA decrypt error: {e}")))?;

        let ciphertext = base64_standard
            .decode(ed.ciphertext)
            .map_err(|e| IronCryptError::DecryptionError(format!("Decode ciphertext error: {e}")))?;
        let nonce_bytes = base64_standard
            .decode(ed.nonce)
            .map_err(|e| IronCryptError::DecryptionError(format!("Decode nonce error: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let _plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| IronCryptError::DecryptionError(format!("AES decrypt error: {e}")))?;

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
