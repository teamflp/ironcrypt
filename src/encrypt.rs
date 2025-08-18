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
#[derive(Serialize, Debug)]
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

/// Serializable header for encrypted streams.
/// Contains the metadata needed for decryption.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedStreamHeader {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
    pub nonce: String,
    pub password_hash: Option<String>,
}

/// Encrypts a data stream using AES-256-GCM and RSA.
///
/// This function reads from a `Read` source, encrypts the data in chunks,
/// and writes the result to a `Write` destination. Ideal for large files.
///
/// # Encrypted Stream Format
/// 1. `header_length` (u64, Big Endian): The size of the JSON header.
/// 2. `header` (JSON): The serialized `EncryptedStreamHeader` struct.
/// 3. `encrypted_data` (binary): The AES-GCM encrypted stream.
///
/// # Arguments
/// * `source` - The source of the plaintext data.
/// * `destination` - The destination for the encrypted data.
/// * `password` - The password for hashing (will be cleared from memory).
/// * `public_key` - The RSA public key to encrypt the session key.
/// * `key_version` - The version of the key being used.
///
/// # Example
///
/// ```rust
/// use ironcrypt::{encrypt_stream, decrypt_stream, generate_rsa_keys, PasswordCriteria, Argon2Config};
/// use std::io::Cursor;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let (private_key, public_key) = generate_rsa_keys(2048)?;
/// let mut source = Cursor::new(b"my secret data");
/// let mut dest = Cursor::new(Vec::new());
/// let mut password = "a_very_Str0ng_P@ssw0rd!".to_string();
///
/// encrypt_stream(&mut source, &mut dest, &mut password, &public_key, &PasswordCriteria::default(), "v1", Argon2Config::default(), true)?;
///
/// dest.set_position(0);
///
/// let mut decrypted_dest = Cursor::new(Vec::new());
/// decrypt_stream(&mut dest, &mut decrypted_dest, &private_key, "a_very_Str0ng_P@ssw0rd!")?;
///
/// assert_eq!(decrypted_dest.into_inner(), b"my secret data");
/// # Ok(())
/// # }
/// ```
pub fn encrypt_stream<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    password: &mut String,
    public_key: &RsaPublicKey,
    criteria: &PasswordCriteria,
    key_version: &str,
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
    password.zeroize(); // Early password zeroization

    let mut symmetric_key = [0u8; 32];
    OsRng.fill_bytes(&mut symmetric_key);
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);

    let padding = Oaep::new::<Sha256>();
    let encrypted_symmetric_key = public_key.encrypt(&mut OsRng, padding, &symmetric_key)?;

    let header = EncryptedStreamHeader {
        key_version: key_version.to_string(),
        encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
        nonce: base64_standard.encode(&nonce_bytes),
        password_hash,
    };
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
///
/// # Arguments
/// * `source` - The source of the encrypted data.
/// * `destination` - The destination for the plaintext data.
/// * `private_key` - The RSA private key to decrypt the session key.
/// * `password` - The password for verification (if used during encryption).
///
/// # Returns
/// `Ok(())` on success. An `IronCryptError` if authentication fails
/// or if the password is incorrect.
pub fn decrypt_stream<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    private_key: &RsaPrivateKey,
    password: &str,
) -> Result<(), IronCryptError> {
    let header_len = source.read_u64::<BigEndian>()?;
    let mut header_bytes = vec![0; header_len as usize];
    source.read_exact(&mut header_bytes)?;
    let header: EncryptedStreamHeader = serde_json::from_slice(&header_bytes)?;

    if let Some(expected_hash_b64) = &header.password_hash {
        let expected_hash_str = String::from_utf8(base64_standard.decode(expected_hash_b64)?)?;
        let parsed_hash = PasswordHash::new(&expected_hash_str)?;

        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(IronCryptError::PasswordVerificationError);
        }
    }

    let encrypted_symmetric_key = base64_standard.decode(&header.encrypted_symmetric_key)?;
    let padding = Oaep::new::<Sha256>();
    let mut symmetric_key = private_key.decrypt(padding, &encrypted_symmetric_key)?;

    let nonce_bytes = base64_standard.decode(&header.nonce)?;
    let key_array: [u8; 32] = symmetric_key
        .clone()
        .try_into()
        .map_err(|_| IronCryptError::DecryptionError("Decrypted key has incorrect size.".to_string()))?;

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
