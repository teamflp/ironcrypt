use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm};
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

use crate::{IronCryptError, PasswordCriteria};
use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};

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
#[deprecated(
    since = "0.2.0",
    note = "use `encrypt_stream` instead for better memory management"
)]
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
    let ciphertext = cipher
        .encrypt(&nonce, data)
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

// ---------------------------------------------------------------------------------
// Streaming API
// ---------------------------------------------------------------------------------

const BUFFER_SIZE: usize = 8192; // 8 KB buffer

/// Serializable structure for stream headers.
/// Same as EncryptedData, but without the ciphertext.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedStreamHeader {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
    pub nonce: String,
    pub password_hash: Option<String>,
}

/// Encrypts a stream of data using AES-256-GCM + RSA.
///
/// This function reads from a `Read` source, encrypts the data in chunks, and
/// writes the encrypted data to a `Write` destination. It's designed for large files
/// to avoid loading the entire content into memory.
///
/// # File Format
/// 1. `header_len` (u64, Big Endian): 8-byte integer specifying the length of the JSON header.
/// 2. `header` (JSON string): The `EncryptedStreamHeader` serialized to JSON.
/// 3. `encrypted_data` (stream): The raw AES-GCM encrypted stream.
///
/// # Parameters
/// - `source`: The `Read` trait object to read plaintext data from.
/// - `destination`: The `Write` trait object to write ciphertext to.
/// - `password`, `public_key`, etc.: Same as `encrypt_data_with_criteria`.
///
/// # Returns
/// - `Ok(())` on success.
/// - `Err(IronCryptError)` on failure.
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
    // 1. Password validation and hashing (same as before)
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
        let hash_str = argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string();
        Some(base64_standard.encode(hash_str))
    } else {
        None
    };
    password.zeroize(); // Zeroize password early

    // 2. Generate AES key and nonce
    let mut symmetric_key = [0u8; 32];
    OsRng.fill_bytes(&mut symmetric_key);
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng); // 12-byte nonce

    // 3. Encrypt symmetric key with RSA
    let padding = Oaep::new::<Sha256>();
    let encrypted_symmetric_key = public_key.encrypt(&mut OsRng, padding, &symmetric_key)?;

    // 4. Create and write the header
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

    // 5. Encrypt the stream
    let mut encryptor = Aes256GcmStreamEncryptor::new(symmetric_key, &nonce_bytes);
    symmetric_key.zeroize(); // Zeroize key after use

    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let bytes_read = source.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // End of stream
        }
        let ciphertext_chunk = encryptor.update(&buffer[..bytes_read]);
        destination.write_all(&ciphertext_chunk)?;
    }

    // 6. Finalize encryption and write the tag
    let (final_chunk, tag) = encryptor.finalize();
    destination.write_all(&final_chunk)?;
    destination.write_all(&tag)?;

    Ok(())
}

/// Decrypts a stream of data that was encrypted with `encrypt_stream`.
///
/// This function reads from a `Read` source, decrypts the data in chunks, and
/// writes the plaintext data to a `Write` destination. It's designed for large files
/// to avoid loading the entire content into memory.
///
/// # Parameters
/// - `source`: The `Read` trait object to read ciphertext from.
/// - `destination`: The `Write` trait object to write plaintext to.
/// - `private_key`: The RSA private key for decrypting the AES key.
/// - `password`: The password to verify against the stored hash.
///
/// # Returns
/// - `Ok(())` on success.
/// - `Err(IronCryptError)` on failure (e.g., authentication error, password mismatch).
pub fn decrypt_stream<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    private_key: &RsaPrivateKey,
    password: &str,
) -> Result<(), IronCryptError> {
    // 1. Read header
    let header_len = source.read_u64::<BigEndian>()?;
    let mut header_bytes = vec![0; header_len as usize];
    source.read_exact(&mut header_bytes)?;
    let header: EncryptedStreamHeader = serde_json::from_slice(&header_bytes)?;

    // 2. Verify password if hash is present
    if let Some(expected_hash_b64) = &header.password_hash {
        let expected_hash_str = String::from_utf8(base64_standard.decode(expected_hash_b64)?)?;
        let parsed_hash = PasswordHash::new(&expected_hash_str)?;

        // Use the default Argon2 instance for verification.
        // The parameters are encoded in the hash string itself.
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(IronCryptError::PasswordVerificationError);
        }
    }

    // 3. Decrypt symmetric key
    let encrypted_symmetric_key = base64_standard.decode(&header.encrypted_symmetric_key)?;
    let padding = Oaep::new::<Sha256>();
    let mut symmetric_key = private_key.decrypt(padding, &encrypted_symmetric_key)?;

    // 4. Decrypt stream
    let nonce_bytes = base64_standard.decode(&header.nonce)?;
    let key_array: [u8; 32] = symmetric_key.clone()
        .try_into()
        .map_err(|_| IronCryptError::DecryptionError("Decrypted key has incorrect size".to_string()))?;

    let mut decryptor =
        Aes256GcmStreamDecryptor::new(key_array, &nonce_bytes);
    symmetric_key.zeroize();

    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let bytes_read = source.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // End of stream
        }
        let plaintext_chunk = decryptor.update(&buffer[..bytes_read]);
        destination.write_all(&plaintext_chunk)?;
    }

    // 5. Finalize decryption (this performs the authentication tag check)
    let final_chunk = decryptor
        .finalize()
        .map_err(|e| IronCryptError::DecryptionError(e))?;
    destination.write_all(&final_chunk)?;

    Ok(())
}
