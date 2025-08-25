use crate::{
    algorithms::SymmetricAlgorithm,
    hashing,
    keys::{PrivateKey, PublicKey},
    rsa_utils, IronCryptError, PasswordCriteria,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chacha20poly1305::XChaCha20Poly1305;
use hex;
use hkdf::Hkdf;
use p256::ecdh::{self, EphemeralSecret};
use p256::pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use p256::pkcs8::LineEnding;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::Oaep;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{Cursor, Read, Write};
use zeroize::Zeroize;

/// Represents the configuration for the Argon2 hashing algorithm.
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

/// Serializable struct containing encryption information for non-streaming data.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    /// The symmetric algorithm used for data encryption.
    pub symmetric_algorithm: SymmetricAlgorithm,
    /// Information about the recipient, including the encrypted symmetric key.
    pub recipient_info: RecipientInfo,
    /// The nonce used for symmetric encryption.
    pub nonce: String,
    /// The encrypted data.
    pub ciphertext: String,
    /// The hash of the password, if one was used.
    pub password_hash: Option<String>,
}

// --- Streaming API ---

const BUFFER_SIZE: usize = 8192;

/// Serializable header for encrypted streams (V1, single-recipient).
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedStreamHeaderV1 {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
    pub nonce: String,
    pub password_hash: Option<String>,
}

/// Holds the encrypted symmetric key for a single recipient (legacy V2).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecipientInfoV2 {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
}

/// Serializable header for encrypted streams (V2, multi-recipient).
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedStreamHeaderV2 {
    pub recipients: Vec<RecipientInfoV2>,
    pub nonce: String,
    pub password_hash: Option<String>,
}

/// Holds information for a single recipient, supporting different asymmetric algorithms.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum RecipientInfo {
    Rsa {
        key_version: String,
        encrypted_symmetric_key: String,
    },
    Ecc {
        key_version: String,
        ephemeral_public_key: String,
        encrypted_symmetric_key: String,
    },
}

/// Serializable header for encrypted streams (V3, multi-algorithm).
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedStreamHeaderV3 {
    pub symmetric_algorithm: SymmetricAlgorithm,
    pub recipients: Vec<RecipientInfo>,
    pub nonce: String,
    pub password_hash: Option<String>,
}

/// Sensitive metadata that gets encrypted within the V4 header.
#[derive(Serialize, Deserialize, Debug)]
pub struct SensitiveHeaderData {
    pub nonce: String,
    pub password_hash: Option<String>,
    pub signature: Option<String>,
    pub signature_algorithm: Option<String>,
    pub signer_key_version: Option<String>,
}

/// Serializable header for encrypted streams (V4, with encrypted metadata).
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedStreamHeaderV4 {
    pub symmetric_algorithm: SymmetricAlgorithm,
    pub recipients: Vec<RecipientInfo>,
    pub encrypted_metadata: String,
    pub metadata_nonce: String,
}

/// An enum to handle different versions of the stream header for backward compatibility.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum StreamHeader {
    V4(EncryptedStreamHeaderV4),
    V3(EncryptedStreamHeaderV3),
    V2(EncryptedStreamHeaderV2),
    V1(EncryptedStreamHeaderV1),
}

/// Encrypts a data stream using a configurable combination of algorithms.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream<'a, R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    password: &mut String,
    recipients: impl IntoIterator<Item = (&'a PublicKey, &'a str)>,
    signing_key: Option<(&'a PrivateKey, &'a str)>,
    criteria: &PasswordCriteria,
    argon_cfg: Argon2Config,
    hash_password: bool,
    sym_algo: SymmetricAlgorithm,
) -> Result<(), IronCryptError> {
    // This is the new V4 implementation
    // Buffer the source data to allow for both hashing (for signature) and encryption.
    let mut source_data = Vec::new();
    source.read_to_end(&mut source_data)?;
    let mut source_cursor = Cursor::new(&source_data);

    let (signature, signature_algorithm, signer_key_version) =
        if let Some((key, version)) = signing_key {
            let hash = hashing::hash_bytes(&source_data)?;
            let rsa_private_key = match key {
                PrivateKey::Rsa(k) => k,
                _ => {
                    return Err(IronCryptError::SignatureError(
                        "Only RSA keys are supported for signing.".to_string(),
                    ))
                }
            };
            let sig = rsa_utils::sign_hash(rsa_private_key, &hash)?;
            (
                Some(hex::encode(sig)),
                Some("rsa-pkcs1v15-sha256".to_string()),
                Some(version.to_string()),
            )
        } else {
            (None, None, None)
        };

    let password_hash = if hash_password {
        criteria.validate(password)?;
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

    let file_content_nonce_len = match sym_algo {
        SymmetricAlgorithm::Aes256Gcm => 12,
        SymmetricAlgorithm::ChaCha20Poly1305 => 24,
    };
    let mut file_content_nonce_bytes = vec![0u8; file_content_nonce_len];
    OsRng.fill_bytes(&mut file_content_nonce_bytes);

    let mut recipient_infos = Vec::new();

    for (public_key, key_version) in recipients {
        let recipient_info = match public_key {
            PublicKey::Rsa(rsa_pub_key) => {
                let padding = Oaep::new::<Sha256>();
                let encrypted_symmetric_key =
                    rsa_pub_key.encrypt(&mut OsRng, padding, &symmetric_key)?;
                RecipientInfo::Rsa {
                    key_version: key_version.to_string(),
                    encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
                }
            }
            PublicKey::Ecc(ecc_pub_key) => {
                let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
                let shared_secret = ephemeral_secret.diffie_hellman(ecc_pub_key);
                let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
                let mut okm = [0u8; 32];
                hkdf.expand(b"ironcrypt-ecies", &mut okm)
                    .map_err(|_| IronCryptError::KeyGenerationError("HKDF expansion failed".into()))?;
                let key_cipher = Aes256Gcm::new_from_slice(&okm)?;
                let key_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let encrypted_symmetric_key = key_cipher.encrypt(&key_nonce, &symmetric_key[..])?;
                let mut final_payload = key_nonce.to_vec();
                final_payload.extend_from_slice(&encrypted_symmetric_key);
                let ephemeral_pub_key_pem = ephemeral_secret
                    .public_key()
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(|_| {
                        IronCryptError::KeySavingError(
                            "Failed to encode ephemeral public key".into(),
                        )
                    })?;
                RecipientInfo::Ecc {
                    key_version: key_version.to_string(),
                    ephemeral_public_key: base64_standard.encode(ephemeral_pub_key_pem),
                    encrypted_symmetric_key: base64_standard.encode(&final_payload),
                }
            }
        };
        recipient_infos.push(recipient_info);
    }

    if recipient_infos.is_empty() {
        return Err(IronCryptError::EncryptionError(
            "No recipients provided for encryption.".to_string(),
        ));
    }

    let sensitive_metadata = SensitiveHeaderData {
        nonce: base64_standard.encode(&file_content_nonce_bytes),
        password_hash,
        signature,
        signature_algorithm,
        signer_key_version,
    };
    let sensitive_metadata_json = serde_json::to_string(&sensitive_metadata)?;
    let mut metadata_nonce_bytes = vec![0u8; 12]; // AES-GCM nonce size
    OsRng.fill_bytes(&mut metadata_nonce_bytes);
    let cipher = Aes256Gcm::new(&symmetric_key.into());
    let encrypted_metadata = cipher
        .encrypt(Nonce::from_slice(&metadata_nonce_bytes), sensitive_metadata_json.as_bytes())
        .map_err(|e| IronCryptError::EncryptionError(format!("Metadata encryption failed: {}", e)))?;

    let header = StreamHeader::V4(EncryptedStreamHeaderV4 {
        symmetric_algorithm: sym_algo,
        recipients: recipient_infos,
        encrypted_metadata: base64_standard.encode(&encrypted_metadata),
        metadata_nonce: base64_standard.encode(&metadata_nonce_bytes),
    });

    let header_json = serde_json::to_string(&header)?;
    destination.write_u64::<BigEndian>(header_json.len() as u64)?;
    destination.write_all(header_json.as_bytes())?;

    match sym_algo {
        SymmetricAlgorithm::Aes256Gcm => {
            let mut encryptor =
                Aes256GcmStreamEncryptor::new(symmetric_key, &file_content_nonce_bytes);
            symmetric_key.zeroize();
            let mut buffer = [0u8; BUFFER_SIZE];
            loop {
                let bytes_read = source_cursor.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                let ciphertext_chunk = encryptor.update(&buffer[..bytes_read]);
                destination.write_all(&ciphertext_chunk)?;
            }
            let (final_chunk, tag) = encryptor.finalize();
            destination.write_all(&final_chunk)?;
            destination.write_all(&tag)?;
        }
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            let mut source_data_inner = Vec::new();
            source_cursor.read_to_end(&mut source_data_inner)?;
            let cipher = XChaCha20Poly1305::new_from_slice(&symmetric_key)?;
            let nonce = Nonce::from_slice(&file_content_nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, source_data_inner.as_ref())?;
            destination.write_all(&ciphertext)?;
        }
    }

    symmetric_key.zeroize();
    Ok(())
}

/// Decrypts a data stream.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_stream<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    private_key: &PrivateKey,
    key_version: &str,
    password: &str,
    verifying_key: Option<&PublicKey>,
) -> Result<(), IronCryptError> {
    let header_len = source.read_u64::<BigEndian>()?;
    let mut header_bytes = vec![0; header_len as usize];
    source.read_exact(&mut header_bytes)?;
    let header: StreamHeader = serde_json::from_slice(&header_bytes)?;

    let (symmetric_key, nonce_bytes, sym_algo, signature_info) = match header {
        StreamHeader::V4(h) => {
            let recipient_info = h
                .recipients
                .iter()
                .find(|r| match r {
                    RecipientInfo::Rsa { key_version: v, .. } => v == key_version,
                    RecipientInfo::Ecc { key_version: v, .. } => v == key_version,
                })
                .ok_or_else(|| {
                    IronCryptError::DecryptionError(format!(
                        "No key found for recipient version '{}'",
                        key_version
                    ))
                })?;

            let sk = match (private_key, recipient_info) {
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

                    let shared_secret = ecdh::diffie_hellman(
                        ecc_priv_key.to_nonzero_scalar(),
                        eph_pub_key.as_affine(),
                    );

                    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
                    let mut okm = [0u8; 32];
                    hkdf.expand(b"ironcrypt-ecies", &mut okm)
                        .map_err(|_| {
                            IronCryptError::DecryptionError("HKDF expansion failed".into())
                        })?;

                    let payload = base64_standard.decode(encrypted_symmetric_key)?;
                    let (nonce, ciphertext) = payload.split_at(12);

                    let key_cipher = Aes256Gcm::new_from_slice(&okm)?;
                    key_cipher.decrypt(nonce.into(), ciphertext)?
                }
                _ => {
                    return Err(IronCryptError::DecryptionError(
                        "Mismatched private key and recipient info type".into(),
                    ))
                }
            };

            let metadata_nonce = base64_standard.decode(h.metadata_nonce)?;
            let encrypted_metadata = base64_standard.decode(h.encrypted_metadata)?;
            let cipher = Aes256Gcm::new_from_slice(&sk)?;
            let sensitive_metadata_json = cipher.decrypt(Nonce::from_slice(&metadata_nonce), encrypted_metadata.as_ref())
                .map_err(|e| IronCryptError::DecryptionError(format!("Failed to decrypt metadata: {}", e)))?;
            let sensitive_metadata: SensitiveHeaderData = serde_json::from_slice(&sensitive_metadata_json)?;

            if let Some(expected_hash_b64) = sensitive_metadata.password_hash {
                verify_password_hash(&expected_hash_b64, password)?;
            }

            let sig_info = if let (Some(sig), Some(algo), Some(version)) =
                (sensitive_metadata.signature, sensitive_metadata.signature_algorithm, sensitive_metadata.signer_key_version)
            {
                Some((sig, algo, version))
            } else {
                None
            };

            (
                sk,
                base64_standard.decode(sensitive_metadata.nonce)?,
                h.symmetric_algorithm,
                sig_info,
            )
        }
        StreamHeader::V3(h) => {
            let recipient_info = h
                .recipients
                .iter()
                .find(|r| match r {
                    RecipientInfo::Rsa { key_version: v, .. } => v == key_version,
                    RecipientInfo::Ecc { key_version: v, .. } => v == key_version,
                })
                .ok_or_else(|| {
                    IronCryptError::DecryptionError(format!(
                        "No key found for recipient version '{}'",
                        key_version
                    ))
                })?;

            let sk = match (private_key, recipient_info) {
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

                    let shared_secret = ecdh::diffie_hellman(
                        ecc_priv_key.to_nonzero_scalar(),
                        eph_pub_key.as_affine(),
                    );

                    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
                    let mut okm = [0u8; 32];
                    hkdf.expand(b"ironcrypt-ecies", &mut okm)
                        .map_err(|_| {
                            IronCryptError::DecryptionError("HKDF expansion failed".into())
                        })?;

                    let payload = base64_standard.decode(encrypted_symmetric_key)?;
                    let (nonce, ciphertext) = payload.split_at(12);

                    let key_cipher = Aes256Gcm::new_from_slice(&okm)?;
                    key_cipher.decrypt(nonce.into(), ciphertext)?
                }
                _ => {
                    return Err(IronCryptError::DecryptionError(
                        "Mismatched private key and recipient info type".into(),
                    ))
                }
            };

            if let Some(expected_hash_b64) = h.password_hash {
                verify_password_hash(&expected_hash_b64, password)?;
            }

            let sig_info = None; // V3 has no signature info

            (
                sk,
                base64_standard.decode(h.nonce)?,
                h.symmetric_algorithm,
                sig_info,
            )
        }
        // Backward compatibility for V1 and V2
        StreamHeader::V1(h) => (
            {
                if let Some(hash) = &h.password_hash {
                    verify_password_hash(hash, password)?;
                }
                let key_bytes = base64_standard.decode(h.encrypted_symmetric_key)?;
                if let PrivateKey::Rsa(rsa_priv_key) = private_key {
                    rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?
                } else {
                    return Err(IronCryptError::DecryptionError(
                        "V1 headers only support RSA keys".into(),
                    ));
                }
            },
            base64_standard.decode(h.nonce)?,
            SymmetricAlgorithm::Aes256Gcm,
            None,
        ),
        StreamHeader::V2(h) => (
            {
                if let Some(hash) = &h.password_hash {
                    verify_password_hash(hash, password)?;
                }
                let recipient_info = h
                    .recipients
                    .iter()
                    .find(|r| r.key_version == key_version)
                    .ok_or_else(|| {
                        IronCryptError::DecryptionError(format!(
                            "No key found for recipient version '{}'",
                            key_version
                        ))
                    })?;
                let key_bytes = base64_standard.decode(&recipient_info.encrypted_symmetric_key)?;
                if let PrivateKey::Rsa(rsa_priv_key) = private_key {
                    rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?
                } else {
                    return Err(IronCryptError::DecryptionError(
                        "V2 headers only support RSA keys".into(),
                    ));
                }
            },
            base64_standard.decode(h.nonce)?,
            SymmetricAlgorithm::Aes256Gcm,
            None,
        ),
    };

    // Decrypt into a temporary buffer first for potential signature verification
    let mut plaintext_buffer = Vec::new();
    match sym_algo {
        SymmetricAlgorithm::Aes256Gcm => {
            let key_array: [u8; 32] = symmetric_key.as_slice().try_into().map_err(|_| {
                IronCryptError::DecryptionError("Decrypted key has incorrect size.".to_string())
            })?;
            let mut decryptor = Aes256GcmStreamDecryptor::new(key_array, &nonce_bytes);

            let mut buffer = [0u8; BUFFER_SIZE];
            loop {
                let bytes_read = source.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                let plaintext_chunk = decryptor.update(&buffer[..bytes_read]);
                plaintext_buffer.extend_from_slice(&plaintext_chunk);
            }
            let final_chunk = decryptor.finalize()?;
            plaintext_buffer.extend_from_slice(&final_chunk);
        }
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            let mut source_data = Vec::new();
            source.read_to_end(&mut source_data)?;
            let cipher = XChaCha20Poly1305::new_from_slice(&symmetric_key)?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            plaintext_buffer = cipher.decrypt(nonce, source_data.as_ref())?;
        }
    }

    // --- Signature Verification ---
    if let Some((signature_hex, algo, _signer_version)) = signature_info {
        let key_for_verification = verifying_key.ok_or_else(|| {
            IronCryptError::SignatureVerificationFailed(
                "Signature found in file but no verification key was provided.".to_string(),
            )
        })?;

        if algo != "rsa-pkcs1v15-sha256" {
            return Err(IronCryptError::SignatureVerificationFailed(format!(
                "Unsupported signature algorithm: {}",
                algo
            )));
        }

        let rsa_public_key = match key_for_verification {
            PublicKey::Rsa(k) => k,
            _ => return Err(IronCryptError::SignatureVerificationFailed(
                "Only RSA keys are supported for verification.".to_string(),
            )),
        };

        let hash = hashing::hash_bytes(&plaintext_buffer)?;
        let signature = hex::decode(signature_hex)
            .map_err(|e| IronCryptError::SignatureError(format!("Failed to decode signature: {}", e)))?;

        rsa_utils::verify_signature(rsa_public_key, &hash, &signature)?;
    }

    // If verification passes (or was not required), write the plaintext to the destination
    destination.write_all(&plaintext_buffer)?;

    Ok(())
}

fn verify_password_hash(hash_b64: &str, password: &str) -> Result<(), IronCryptError> {
    let expected_hash_str = String::from_utf8(base64_standard.decode(hash_b64)?)?;
    let parsed_hash = PasswordHash::new(&expected_hash_str)?;
    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(IronCryptError::PasswordVerificationError);
    }
    Ok(())
}
