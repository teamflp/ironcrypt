use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use rsa::{Oaep, RsaPublicKey};
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{IronCryptError, PasswordCriteria};

/// Configuration of Argon2 parameters for hashing.
#[derive(Clone, Debug)]
pub struct Argon2Config {
    pub memory_cost: u32, // per ex. 65536 (64 Mo)
    pub time_cost: u32,   // per ex. 3
    pub parallelism: u32, // per ex. 1
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

/// Serializable return structure containing encryption information.
#[derive(Serialize, Debug)]
pub struct EncryptedData {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
    pub nonce: String,
    pub ciphertext: String,
    /// Optional, if `hash_password` is `true` and we want to return the hash.
    pub password_hash: Option<String>,
}

/// Encrypts binary data using AES-256-GCM + RSA,
/// and optionally hashes the password with Argon2id.
///
/// # Steps
/// 1) Checks password strength (`criteria.validate`).
/// 2) (Optional) Hashes the password using Argon2.
/// 3) Generates a random AES-256 symmetric key.
/// 4) Encrypts `data` using AES-256-GCM.
/// 5) Encrypts the symmetric key using RSA (OAEP/SHA-256).
/// 6) Returns a serializable `EncryptedData` structure.
///
/// # Parameters
/// - `data`: The binary data to encrypt.
/// - `password`: The password to validate and optionally hash.
/// - `public_key`: RSA public key (for encrypting the AES key).
/// - `criteria`: Password strength criteria.
/// - `key_version`: Key version identifier (e.g., "v1"), useful for rotation.
/// - `argon_cfg`: Argon2 configuration (memory, time cost, etc.).
/// - `hash_password`: If `true`, the password is hashed and included in `EncryptedData`.
///
/// # Returns
/// - `Ok(EncryptedData)` on success.
/// - `Err(IronCryptError)` if an error occurs (weak password, encryption failure, etc.).
pub fn encrypt_data_with_criteria(
    data: &[u8],
    password: &mut String, // mut to allow zeroizing it later
    public_key: &RsaPublicKey,
    criteria: &PasswordCriteria,
    key_version: &str,
    argon_cfg: Argon2Config,
    hash_password: bool,
) -> Result<EncryptedData, IronCryptError> {
    // 1) Check password strength
    criteria.validate(password)?;

    // Argon2 hashing (if hash_password == true)
    let password_hash = if hash_password {
        let params = Params::new(
            argon_cfg.memory_cost,
            argon_cfg.time_cost,
            argon_cfg.parallelism,
            None,
        )?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Use the same OsRng from argon2::password_hash::rand_core
        let salt = SaltString::generate(&mut OsRng);

        let hash_str = argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string();
        Some(base64_standard.encode(hash_str))
    } else {
        None
    };

    // Generate AES key
    let mut symmetric_key = [0u8; 32];
    // still safe, because we re-imported RngCore from argon2's rand_core
    OsRng.fill_bytes(&mut symmetric_key);

    // 4) Encrypt data with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96 bits = 12 bytes
    let ciphertext = cipher.encrypt(&nonce, data)
        .map_err(|e| IronCryptError::EncryptionError(format!("AES encryption error: {e}")))?;

    // 5) Encrypt the symmetric key with RSA (OAEP/SHA-256)
    let padding = Oaep::new::<Sha256>();
    let encrypted_symmetric_key = public_key
        .encrypt(&mut OsRng, padding, &symmetric_key)
        .map_err(|e| {
            IronCryptError::EncryptionError(format!("RSA symmetric key encryption error: {e}"))
        })?;

    // 6) Build the return structure
    let result = EncryptedData {
        key_version: key_version.to_string(),
        encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
        nonce: base64_standard.encode(nonce),
        ciphertext: base64_standard.encode(&ciphertext),
        password_hash,
    };

    // Clear the symmetric key from memory (good practice)
    symmetric_key.zeroize();

    // Clear the plaintext password to avoid keeping it in memory longer than necessary
    password.zeroize();

    Ok(result)
}
