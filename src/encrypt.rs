use crate::{IronCryptError, PasswordCriteria};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm};
use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{Read, Write};
use zeroize::Zeroize;

/// Represents the configuration for the Argon2 hashing algorithm.
#[derive(Clone, Debug)]
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

/// Serializable struct containing encryption information.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
    pub nonce: String,
    pub ciphertext: String,
    /// Optional, if `hash_password` is `true`.
    pub password_hash: Option<String>,
}

/// Encrypts binary data using AES-256-GCM + RSA.
///
/// **Warning:** This function is deprecated and loads the entire data into memory.
/// For encrypting large files or streams, prefer `encrypt_stream`.
#[deprecated(
    since = "0.2.0",
    note = "Use `encrypt_stream` for better memory management."
)]
pub fn encrypt_data_with_criteria(
    data: &[u8],
    password: &mut String,
    public_key: &RsaPublicKey,
    criteria: &PasswordCriteria,
    key_version: &str,
    argon_cfg: Argon2Config,
    hash_password: bool,
) -> Result<EncryptedData, IronCryptError> {
    criteria.validate(password)?;

    let password_hash = if hash_password {
        let params = Params::new(
            argon_cfg.memory_cost,
            argon_cfg.time_cost,
            argon_cfg.parallelism,
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
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data)?;

    let padding = Oaep::new::<Sha256>();
    let encrypted_symmetric_key = public_key.encrypt(&mut OsRng, padding, &symmetric_key)?;

    let result = EncryptedData {
        key_version: key_version.to_string(),
        encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
        nonce: base64_standard.encode(nonce),
        ciphertext: base64_standard.encode(&ciphertext),
        password_hash,
    };

    symmetric_key.zeroize();
    password.zeroize();

    Ok(result)
}

// --- Streaming API ---

const BUFFER_SIZE: usize = 8192; // 8 KB buffer

/// Serializable header for encrypted streams (V1, single-recipient).
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedStreamHeaderV1 {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
    pub nonce: String,
    pub password_hash: Option<String>,
}

/// Holds the encrypted symmetric key for a single recipient.
#[derive(Serialize, Deserialize, Debug)]
pub struct RecipientInfo {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
}

/// Serializable header for encrypted streams (V2, multi-recipient).
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedStreamHeaderV2 {
    pub recipients: Vec<RecipientInfo>,
    pub nonce: String,
    pub password_hash: Option<String>,
}

/// An enum to handle different versions of the stream header for backward compatibility.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)] // Allows deserializing into the first matching variant
pub enum StreamHeader {
    V2(EncryptedStreamHeaderV2),
    V1(EncryptedStreamHeaderV1),
}

/// Encrypts a data stream using AES-256-GCM and RSA for multiple recipients.
pub fn encrypt_stream<'a, R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    password: &mut String,
    recipients: impl IntoIterator<Item = (&'a RsaPublicKey, &'a str)>,
    criteria: &PasswordCriteria,
    argon_cfg: Argon2Config,
    hash_password: bool,
) -> Result<(), IronCryptError> {
    criteria.validate(password)?;
    let password_hash = if hash_password {
        let params = Params::new(
            argon_cfg.memory_cost,
            argon_cfg.time_cost,
            argon_cfg.parallelism,
            None,
        )?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let hash_str = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
        Some(base64_standard.encode(hash_str))
    } else {
        None
    };
    password.zeroize();

    let mut symmetric_key = [0u8; 32];
    OsRng.fill_bytes(&mut symmetric_key);
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);

    let mut recipient_infos = Vec::new();

    for (public_key, key_version) in recipients {
        let padding = Oaep::new::<Sha256>();
        let encrypted_symmetric_key =
            public_key.encrypt(&mut OsRng, padding, &symmetric_key)?;
        recipient_infos.push(RecipientInfo {
            key_version: key_version.to_string(),
            encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
        });
    }

    if recipient_infos.is_empty() {
        return Err(IronCryptError::EncryptionError(
            "No recipients provided for encryption.".to_string(),
        ));
    }

    let header = StreamHeader::V2(EncryptedStreamHeaderV2 {
        recipients: recipient_infos,
        nonce: base64_standard.encode(&nonce_bytes),
        password_hash,
    });

    let header_json = serde_json::to_string(&header)?;
    let header_len = header_json.len() as u64;

    destination.write_u64::<BigEndian>(header_len)?;
    destination.write_all(header_json.as_bytes())?;

    let mut encryptor = Aes256GcmStreamEncryptor::new(symmetric_key, &nonce_bytes);
    symmetric_key.zeroize();

    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let bytes_read = source.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let ciphertext_chunk = encryptor.update(&buffer[..bytes_read]);
        destination.write_all(&ciphertext_chunk)?;
    }

    let (final_chunk, tag) = encryptor.finalize();
    destination.write_all(&final_chunk)?;
    destination.write_all(&tag)?;

    Ok(())
}

/// Decrypts a data stream encrypted with `encrypt_stream`.
pub fn decrypt_stream<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    private_key: &RsaPrivateKey,
    key_version: &str,
    password: &str,
) -> Result<(), IronCryptError> {
    let header_len = source.read_u64::<BigEndian>()?;
    let mut header_bytes = vec![0; header_len as usize];
    source.read_exact(&mut header_bytes)?;
    let header: StreamHeader = serde_json::from_slice(&header_bytes)?;

    let (encrypted_symmetric_key_b64, nonce_b64, password_hash) = match header {
        StreamHeader::V2(h) => {
            let recipient_info = h
                .recipients
                .iter()
                .find(|r| r.key_version == key_version)
                .ok_or(IronCryptError::DecryptionError(format!(
                    "No key found for recipient version '{}'",
                    key_version
                )))?;
            (
                recipient_info.encrypted_symmetric_key.clone(),
                h.nonce,
                h.password_hash,
            )
        }
        StreamHeader::V1(h) => {
            if h.key_version != key_version {
                return Err(IronCryptError::DecryptionError(format!(
                    "Key version mismatch: expected '{}', found '{}'",
                    key_version, h.key_version
                )));
            }
            (h.encrypted_symmetric_key, h.nonce, h.password_hash)
        }
    };

    if let Some(expected_hash_b64) = &password_hash {
        let expected_hash_str = String::from_utf8(base64_standard.decode(expected_hash_b64)?)?;
        let parsed_hash = PasswordHash::new(&expected_hash_str)?;

        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(IronCryptError::PasswordVerificationError);
        }
    }

    let encrypted_symmetric_key = base64_standard.decode(&encrypted_symmetric_key_b64)?;
    let padding = Oaep::new::<Sha256>();
    let mut symmetric_key = private_key.decrypt(padding, &encrypted_symmetric_key)?;

    let nonce_bytes = base64_standard.decode(&nonce_b64)?;
    let key_array: [u8; 32] = symmetric_key
        .clone()
        .try_into()
        .map_err(|_| {
            IronCryptError::DecryptionError("Decrypted key has incorrect size.".to_string())
        })?;

    let mut decryptor = Aes256GcmStreamDecryptor::new(key_array, &nonce_bytes);
    symmetric_key.zeroize();

    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let bytes_read = source.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let plaintext_chunk = decryptor.update(&buffer[..bytes_read]);
        destination.write_all(&plaintext_chunk)?;
    }

    let final_chunk = decryptor.finalize()?;
    destination.write_all(&final_chunk)?;

    Ok(())
}
