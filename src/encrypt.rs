#[cfg(feature = "rsa-algo")]
use crate::rsa_utils;
use crate::{
    algorithms::SymmetricAlgorithm,
    audit::{AuditEvent, Operation, Outcome},
    context::EncryptionContext,
    hashing,
    keys::{PrivateKey, PublicKey},
    limits::{
        MAX_ENCAPSULATED_KEY_B64_LEN, MAX_ENCRYPTED_METADATA_B64_LEN, MAX_KEY_VERSION_LEN,
        MAX_RECIPIENTS, MAX_STREAM_HEADER_SIZE,
    },
    payment::PaymentSecurityProfile,
    memsec::new_dek32,
    IronCryptError, PasswordCriteria, ecc_utils,
};
#[cfg(feature = "rsa-algo")]
use crate::memsec::zeroizing_vec;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hex;
use p256::pkcs8::spki::{DecodePublicKey};
use p256::pkcs8::{EncodePublicKey, LineEnding};
use rand::rngs::OsRng;
use rand::RngCore;
#[cfg(feature = "rsa-algo")]
use rsa::Oaep;
use serde::{Deserialize, Serialize};
#[cfg(feature = "rsa-algo")]
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
    /// Envelope format version (see [`crate::envelope`]). Defaults to 1 when absent.
    #[serde(default = "default_json_format_version")]
    pub format_version: u32,
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
    /// Application context bound as AEAD AAD (multi-tenant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<EncryptionContext>,
}

fn default_json_format_version() -> u32 {
    crate::envelope::CURRENT_JSON_FORMAT_VERSION
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

/// Holds information for a single recipient, supporting different asymmetric algorithms
/// and remote [`crate::CryptoProvider`] backends (KMS / Transit / HSM).
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
    /// DEK wrapped by a [`crate::CryptoProvider`] (private key never leaves the provider).
    Provider {
        /// Logical version / envelope id (often same as `key_id`).
        key_version: String,
        /// Backend name: `aws-kms`, `vault-transit`, `hsm`, …
        provider: String,
        /// Provider key id / label / ARN.
        key_id: String,
        /// Base64-encoded wrapped DEK ciphertext from the provider.
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
    /// Cleartext application context (also bound as AAD on encrypted_metadata).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<EncryptionContext>,
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

fn aead_payload<'a>(msg: &'a [u8], aad: &'a [u8]) -> Payload<'a, 'a> {
    Payload { msg, aad }
}

fn context_aad(ctx: Option<&EncryptionContext>) -> Vec<u8> {
    ctx.map(|c| c.to_aad_bytes()).unwrap_or_default()
}

fn validate_key_version(v: &str) -> Result<(), IronCryptError> {
    if v.is_empty() || v.len() > MAX_KEY_VERSION_LEN {
        return Err(IronCryptError::DecryptionError(format!(
            "key_version length {} exceeds MAX_KEY_VERSION_LEN ({MAX_KEY_VERSION_LEN})",
            v.len()
        )));
    }
    Ok(())
}

fn validate_b64_field(name: &str, value: &str, max: usize) -> Result<(), IronCryptError> {
    if value.len() > max {
        return Err(IronCryptError::DecryptionError(format!(
            "{name} length {} exceeds limit ({max})",
            value.len()
        )));
    }
    Ok(())
}

fn validate_recipient_info(r: &RecipientInfo) -> Result<(), IronCryptError> {
    match r {
        RecipientInfo::Rsa {
            key_version,
            encrypted_symmetric_key,
        } => {
            validate_key_version(key_version)?;
            validate_b64_field(
                "encrypted_symmetric_key",
                encrypted_symmetric_key,
                MAX_ENCAPSULATED_KEY_B64_LEN,
            )?;
        }
        RecipientInfo::Ecc {
            key_version,
            ephemeral_public_key,
            encrypted_symmetric_key,
        } => {
            validate_key_version(key_version)?;
            validate_b64_field(
                "ephemeral_public_key",
                ephemeral_public_key,
                MAX_ENCAPSULATED_KEY_B64_LEN,
            )?;
            validate_b64_field(
                "encrypted_symmetric_key",
                encrypted_symmetric_key,
                MAX_ENCAPSULATED_KEY_B64_LEN,
            )?;
        }
        RecipientInfo::Provider {
            key_version,
            provider,
            key_id,
            encrypted_symmetric_key,
        } => {
            validate_key_version(key_version)?;
            if provider.is_empty() || provider.len() > MAX_KEY_VERSION_LEN {
                return Err(IronCryptError::DecryptionError(
                    "invalid provider name in recipient".into(),
                ));
            }
            if key_id.is_empty() || key_id.len() > MAX_ENCAPSULATED_KEY_B64_LEN {
                return Err(IronCryptError::DecryptionError(
                    "invalid provider key_id in recipient".into(),
                ));
            }
            validate_b64_field(
                "encrypted_symmetric_key",
                encrypted_symmetric_key,
                MAX_ENCAPSULATED_KEY_B64_LEN,
            )?;
        }
    }
    Ok(())
}

fn validate_stream_header_bounds(header: &StreamHeader) -> Result<(), IronCryptError> {
    crate::envelope::ensure_stream_header_allowed(header)?;
    match header {
        StreamHeader::V4(h) => {
            if h.recipients.is_empty() || h.recipients.len() > MAX_RECIPIENTS {
                return Err(IronCryptError::DecryptionError(format!(
                    "recipient count {} outside 1..={MAX_RECIPIENTS}",
                    h.recipients.len()
                )));
            }
            for r in &h.recipients {
                validate_recipient_info(r)?;
            }
            validate_b64_field(
                "encrypted_metadata",
                &h.encrypted_metadata,
                MAX_ENCRYPTED_METADATA_B64_LEN,
            )?;
        }
        StreamHeader::V3(h) => {
            if h.recipients.is_empty() || h.recipients.len() > MAX_RECIPIENTS {
                return Err(IronCryptError::DecryptionError(format!(
                    "recipient count {} outside 1..={MAX_RECIPIENTS}",
                    h.recipients.len()
                )));
            }
            for r in &h.recipients {
                validate_recipient_info(r)?;
            }
        }
        StreamHeader::V2(h) => {
            if h.recipients.is_empty() || h.recipients.len() > MAX_RECIPIENTS {
                return Err(IronCryptError::DecryptionError(format!(
                    "recipient count {} outside 1..={MAX_RECIPIENTS}",
                    h.recipients.len()
                )));
            }
            for r in &h.recipients {
                validate_key_version(&r.key_version)?;
                validate_b64_field(
                    "encrypted_symmetric_key",
                    &r.encrypted_symmetric_key,
                    MAX_ENCAPSULATED_KEY_B64_LEN,
                )?;
            }
        }
        StreamHeader::V1(h) => {
            validate_key_version(&h.key_version)?;
            validate_b64_field(
                "encrypted_symmetric_key",
                &h.encrypted_symmetric_key,
                MAX_ENCAPSULATED_KEY_B64_LEN,
            )?;
        }
    }
    Ok(())
}

/// Encrypts a data stream using a configurable combination of algorithms.
#[allow(clippy::too_many_arguments)]
/// Encrypts a data stream (no application context / AAD).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream<'a, R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    password: &mut String,
    recipients: impl IntoIterator<Item = (&'a PublicKey, &'a str)> + Clone,
    signing_key: Option<(&'a PrivateKey, &'a str)>,
    criteria: &PasswordCriteria,
    argon_cfg: Argon2Config,
    hash_password: bool,
    sym_algo: SymmetricAlgorithm,
) -> Result<(), IronCryptError> {
    encrypt_stream_with_context(
        source,
        destination,
        password,
        recipients,
        signing_key,
        criteria,
        argon_cfg,
        hash_password,
        sym_algo,
        None,
    )
}

/// Encrypts a data stream with optional [`EncryptionContext`] bound as metadata AAD.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream_with_context<'a, R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    password: &mut String,
    recipients: impl IntoIterator<Item = (&'a PublicKey, &'a str)> + Clone,
    signing_key: Option<(&'a PrivateKey, &'a str)>,
    criteria: &PasswordCriteria,
    argon_cfg: Argon2Config,
    hash_password: bool,
    sym_algo: SymmetricAlgorithm,
    context: Option<&EncryptionContext>,
) -> Result<(), IronCryptError> {
    EncryptionContext::require_for_payment(context)?;
    let mut event = AuditEvent::new(Operation::Write);
    event.symmetric_algorithm = Some(format!("{:?}", sym_algo));
    event.recipient_key_versions = recipients.clone().into_iter().map(|(_, v)| v.to_string()).collect();
    if event.recipient_key_versions.is_empty() || event.recipient_key_versions.len() > MAX_RECIPIENTS
    {
        return Err(IronCryptError::EncryptionError(format!(
            "recipient count {} outside 1..={MAX_RECIPIENTS}",
            event.recipient_key_versions.len()
        )));
    }
    for (pk, _) in recipients.clone() {
        PaymentSecurityProfile::ensure_ecc_public(pk)?;
    }
    if let Some((key, _)) = signing_key {
        PaymentSecurityProfile::ensure_ecc_private(key)?;
    }
    if let Some((key, version)) = signing_key {
        event.signer_key_version = Some(version.to_string());
        event.signature_algorithm = Some(match key {
            #[cfg(feature = "rsa-algo")]
            PrivateKey::Rsa(_) => "rsa-pss-sha256".to_string(),
            PrivateKey::Ecc(_) => "ecdsa-p256-sha256".to_string(),
        });
    }

    let result = (|| {
        // Pre-buffer only when required: signing needs the full plaintext for the
        // header signature; XChaCha20-Poly1305 is one-shot AEAD (no stream API here).
        // AES-GCM without signing streams directly from `source`.
        let must_prebuffer =
            signing_key.is_some() || matches!(sym_algo, SymmetricAlgorithm::ChaCha20Poly1305);

        let prebuffered: Option<Vec<u8>> = if must_prebuffer {
            let mut source_data = Vec::new();
            source.read_to_end(&mut source_data)?;
            Some(source_data)
        } else {
            None
        };

        let (signature, signature_algorithm, signer_key_version) =
            if let Some((key, version)) = signing_key {
                let source_data = prebuffered.as_ref().expect("signing requires prebuffer");
                let hash = hashing::hash_bytes(source_data)?;
                let (sig, algo) = match key {
                    #[cfg(feature = "rsa-algo")]
                    PrivateKey::Rsa(rsa_private_key) => (
                        rsa_utils::sign_hash_pss(rsa_private_key, &hash)?,
                        "rsa-pss-sha256".to_string(),
                    ),
                    PrivateKey::Ecc(ecc_secret_key) => (
                        ecc_utils::sign_hash_ecc(ecc_secret_key, &hash)?,
                        "ecdsa-p256-sha256".to_string(),
                    ),
                };
                (
                    Some(hex::encode(sig)),
                    Some(algo),
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

        let mut symmetric_key = new_dek32();

        let file_content_nonce_len = match sym_algo {
            SymmetricAlgorithm::Aes256Gcm => 12,
            SymmetricAlgorithm::ChaCha20Poly1305 => 24,
        };
        let mut file_content_nonce_bytes = vec![0u8; file_content_nonce_len];
        OsRng.fill_bytes(&mut file_content_nonce_bytes);

        let mut recipient_infos = Vec::new();

        for (public_key, key_version) in recipients {
            let recipient_info = match public_key {
                #[cfg(feature = "rsa-algo")]
                PublicKey::Rsa(rsa_pub_key) => {
                    let padding = Oaep::new::<Sha256>();
                    let encrypted_symmetric_key =
                        rsa_pub_key.encrypt(&mut OsRng, padding, symmetric_key.as_ref())?;
                    RecipientInfo::Rsa {
                        key_version: key_version.to_string(),
                        encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
                    }
                }
                PublicKey::Ecc(ecc_pub_key) => {
                    let kek = ecc_utils::ecies_key_encap(ecc_pub_key, symmetric_key.as_ref())?;
                    let ephemeral_public_key_pem = kek.ephemeral_pk.to_public_key_pem(LineEnding::LF)?;
                    RecipientInfo::Ecc {
                        key_version: key_version.to_string(),
                        ephemeral_public_key: base64_standard.encode(ephemeral_public_key_pem),
                        encrypted_symmetric_key: base64_standard.encode(kek.encapsulated_key),
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
        let mut metadata_nonce_bytes = vec![0u8; 12];
        OsRng.fill_bytes(&mut metadata_nonce_bytes);
        let cipher = Aes256Gcm::new(symmetric_key.as_ref().into());
        let aad = context_aad(context);
        let encrypted_metadata = cipher
            .encrypt(
                Nonce::from_slice(&metadata_nonce_bytes),
                aead_payload(sensitive_metadata_json.as_bytes(), &aad),
            )
            .map_err(|e| IronCryptError::EncryptionError(format!("Metadata encryption failed: {}", e)))?;

        let header = StreamHeader::V4(EncryptedStreamHeaderV4 {
            symmetric_algorithm: sym_algo,
            recipients: recipient_infos,
            encrypted_metadata: base64_standard.encode(&encrypted_metadata),
            metadata_nonce: base64_standard.encode(&metadata_nonce_bytes),
            context: context.cloned(),
        });

        let header_json = serde_json::to_string(&header)?;
        if header_json.len() > MAX_STREAM_HEADER_SIZE as usize {
            return Err(IronCryptError::EncryptionError(format!(
                "stream header length {} exceeds MAX_STREAM_HEADER_SIZE ({MAX_STREAM_HEADER_SIZE})",
                header_json.len()
            )));
        }
        destination.write_u64::<BigEndian>(header_json.len() as u64)?;
        destination.write_all(header_json.as_bytes())?;

        match sym_algo {
            SymmetricAlgorithm::Aes256Gcm => {
                // Stream encryptor takes ownership of a copy; wipe ours immediately after.
                let key_copy = *symmetric_key;
                symmetric_key.zeroize();
                let mut encryptor =
                    Aes256GcmStreamEncryptor::new(key_copy, &file_content_nonce_bytes);
                let mut buffer = [0u8; BUFFER_SIZE];
                if let Some(ref data) = prebuffered {
                    let mut source_cursor = Cursor::new(data.as_slice());
                    loop {
                        let bytes_read = source_cursor.read(&mut buffer)?;
                        if bytes_read == 0 {
                            break;
                        }
                        let ciphertext_chunk = encryptor.update(&buffer[..bytes_read]);
                        destination.write_all(&ciphertext_chunk)?;
                    }
                } else {
                    loop {
                        let bytes_read = source.read(&mut buffer)?;
                        if bytes_read == 0 {
                            break;
                        }
                        let ciphertext_chunk = encryptor.update(&buffer[..bytes_read]);
                        destination.write_all(&ciphertext_chunk)?;
                    }
                }
                let (final_chunk, tag) = encryptor.finalize();
                destination.write_all(&final_chunk)?;
                destination.write_all(&tag)?;
            }
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                let plaintext = prebuffered.as_ref().expect("ChaCha requires prebuffer");
                let cipher = XChaCha20Poly1305::new_from_slice(symmetric_key.as_ref())?;
                let nonce = XNonce::from_slice(&file_content_nonce_bytes);
                let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
                destination.write_all(&ciphertext)?;
                symmetric_key.zeroize();
            }
        }
        // Remaining wipe on drop if not already zeroized.
        Ok(())
    })();

    if let Err(e) = &result {
        event.set_failure(e);
    }

    event.log();

    result
}

/// Encrypt a stream using a caller-supplied DEK and pre-built recipient infos
/// (typically [`RecipientInfo::Provider`] after a remote wrap).
///
/// Under Payment, `context` is mandatory and bound as metadata AEAD AAD.
/// `symmetric_key` is zeroized before this function returns.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream_with_dek<'a, R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    password: &mut String,
    symmetric_key: &mut [u8; 32],
    recipient_infos: Vec<RecipientInfo>,
    signing_key: Option<(&'a PrivateKey, &'a str)>,
    criteria: &PasswordCriteria,
    argon_cfg: Argon2Config,
    hash_password: bool,
    sym_algo: SymmetricAlgorithm,
    context: Option<&EncryptionContext>,
) -> Result<(), IronCryptError> {
    EncryptionContext::require_for_payment(context)?;
    let mut event = AuditEvent::new(Operation::Write);
    if let Some(ctx) = context {
        event.tenant_id = Some(ctx.tenant_id.clone());
    }
    event.symmetric_algorithm = Some(format!("{:?}", sym_algo));
    event.recipient_key_versions = recipient_infos
        .iter()
        .map(|r| match r {
            RecipientInfo::Rsa { key_version, .. }
            | RecipientInfo::Ecc { key_version, .. }
            | RecipientInfo::Provider { key_version, .. } => key_version.clone(),
        })
        .collect();
    if event.recipient_key_versions.is_empty() || event.recipient_key_versions.len() > MAX_RECIPIENTS
    {
        symmetric_key.zeroize();
        return Err(IronCryptError::EncryptionError(format!(
            "recipient count {} outside 1..={MAX_RECIPIENTS}",
            event.recipient_key_versions.len()
        )));
    }

    let result: Result<(), IronCryptError> = (|| {

        let must_prebuffer =
            signing_key.is_some() || matches!(sym_algo, SymmetricAlgorithm::ChaCha20Poly1305);
        let prebuffered: Option<Vec<u8>> = if must_prebuffer {
            let mut source_data = Vec::new();
            source.read_to_end(&mut source_data)?;
            Some(source_data)
        } else {
            None
        };

        let (signature, signature_algorithm, signer_key_version) =
            if let Some((key, version)) = signing_key {
                let source_data = prebuffered.as_ref().expect("signing requires prebuffer");
                let hash = hashing::hash_bytes(source_data)?;
                let (sig, algo) = match key {
                    #[cfg(feature = "rsa-algo")]
                    PrivateKey::Rsa(rsa_private_key) => (
                        rsa_utils::sign_hash_pss(rsa_private_key, &hash)?,
                        "rsa-pss-sha256".to_string(),
                    ),
                    PrivateKey::Ecc(ecc_secret_key) => (
                        ecc_utils::sign_hash_ecc(ecc_secret_key, &hash)?,
                        "ecdsa-p256-sha256".to_string(),
                    ),
                };
                (
                    Some(hex::encode(sig)),
                    Some(algo),
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

        let file_content_nonce_len = match sym_algo {
            SymmetricAlgorithm::Aes256Gcm => 12,
            SymmetricAlgorithm::ChaCha20Poly1305 => 24,
        };
        let mut file_content_nonce_bytes = vec![0u8; file_content_nonce_len];
        OsRng.fill_bytes(&mut file_content_nonce_bytes);

        let sensitive_metadata = SensitiveHeaderData {
            nonce: base64_standard.encode(&file_content_nonce_bytes),
            password_hash,
            signature,
            signature_algorithm,
            signer_key_version,
        };
        let sensitive_metadata_json = serde_json::to_string(&sensitive_metadata)?;
        let mut metadata_nonce_bytes = vec![0u8; 12];
        OsRng.fill_bytes(&mut metadata_nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(symmetric_key)?;
        let aad = context_aad(context);
        let encrypted_metadata = cipher
            .encrypt(
                Nonce::from_slice(&metadata_nonce_bytes),
                aead_payload(sensitive_metadata_json.as_bytes(), &aad),
            )
            .map_err(|e| {
                IronCryptError::EncryptionError(format!("Metadata encryption failed: {}", e))
            })?;

        let header = StreamHeader::V4(EncryptedStreamHeaderV4 {
            symmetric_algorithm: sym_algo,
            recipients: recipient_infos,
            encrypted_metadata: base64_standard.encode(&encrypted_metadata),
            metadata_nonce: base64_standard.encode(&metadata_nonce_bytes),
            context: context.cloned(),
        });

        let header_json = serde_json::to_string(&header)?;
        if header_json.len() > MAX_STREAM_HEADER_SIZE as usize {
            return Err(IronCryptError::EncryptionError(format!(
                "stream header length {} exceeds MAX_STREAM_HEADER_SIZE ({MAX_STREAM_HEADER_SIZE})",
                header_json.len()
            )));
        }
        destination.write_u64::<BigEndian>(header_json.len() as u64)?;
        destination.write_all(header_json.as_bytes())?;

        match sym_algo {
            SymmetricAlgorithm::Aes256Gcm => {
                let mut encryptor =
                    Aes256GcmStreamEncryptor::new(*symmetric_key, &file_content_nonce_bytes);
                symmetric_key.zeroize();
                let mut buffer = [0u8; BUFFER_SIZE];
                if let Some(ref data) = prebuffered {
                    let mut source_cursor = Cursor::new(data.as_slice());
                    loop {
                        let bytes_read = source_cursor.read(&mut buffer)?;
                        if bytes_read == 0 {
                            break;
                        }
                        let ciphertext_chunk = encryptor.update(&buffer[..bytes_read]);
                        destination.write_all(&ciphertext_chunk)?;
                    }
                } else {
                    loop {
                        let bytes_read = source.read(&mut buffer)?;
                        if bytes_read == 0 {
                            break;
                        }
                        let ciphertext_chunk = encryptor.update(&buffer[..bytes_read]);
                        destination.write_all(&ciphertext_chunk)?;
                    }
                }
                let (last_chunk, tag) = encryptor.finalize();
                destination.write_all(&last_chunk)?;
                destination.write_all(&tag)?;
            }
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                let data = prebuffered.expect("chacha requires prebuffer");
                let cipher = XChaCha20Poly1305::new_from_slice(symmetric_key)?;
                let nonce = XNonce::from_slice(&file_content_nonce_bytes);
                let ciphertext = cipher.encrypt(nonce, data.as_ref())?;
                destination.write_all(&ciphertext)?;
                symmetric_key.zeroize();
            }
        }
        Ok(())
    })();

    symmetric_key.zeroize();
    if let Err(e) = &result {
        event.set_failure(e);
    }
    event.log();
    result
}

/// Read and validate the encrypted-stream header, leaving `source` positioned at the body.
pub fn read_stream_header<R: Read>(source: &mut R) -> Result<StreamHeader, IronCryptError> {
    let header_len = source.read_u64::<BigEndian>()?;
    if header_len == 0 || header_len as u128 > MAX_STREAM_HEADER_SIZE as u128 {
        return Err(IronCryptError::DecryptionError(format!(
            "stream header length {header_len} exceeds MAX_STREAM_HEADER_SIZE ({MAX_STREAM_HEADER_SIZE})"
        )));
    }
    let mut header_bytes = vec![0; header_len as usize];
    source.read_exact(&mut header_bytes)?;
    let header: StreamHeader = serde_json::from_slice(&header_bytes)?;
    validate_stream_header_bounds(&header)?;
    Ok(header)
}

/// Locate a recipient by `key_version` (RSA / ECC / Provider).
pub fn find_recipient<'a>(
    header: &'a StreamHeader,
    key_version: &str,
) -> Option<&'a RecipientInfo> {
    match header {
        StreamHeader::V4(h) => h.recipients.iter().find(|r| recipient_version(r) == key_version),
        StreamHeader::V3(h) => h.recipients.iter().find(|r| recipient_version(r) == key_version),
        StreamHeader::V2(_) | StreamHeader::V1(_) => None,
    }
}

fn recipient_version(r: &RecipientInfo) -> &str {
    match r {
        RecipientInfo::Rsa { key_version, .. }
        | RecipientInfo::Ecc { key_version, .. }
        | RecipientInfo::Provider { key_version, .. } => key_version,
    }
}

/// Decrypt stream body after the DEK has been unwrapped (local or provider).
///
/// `source` must already be positioned after the header that produced `header`.
/// `symmetric_key` is zeroized before return.
pub fn decrypt_stream_with_dek<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    header: StreamHeader,
    symmetric_key: &mut [u8],
    password: &str,
    verifying_key: Option<&PublicKey>,
) -> Result<(), IronCryptError> {
    let mut event = AuditEvent::new(Operation::Read);
    let result = (|| {
        let (nonce_bytes, sym_algo, signature_info, password_ok) = match header {
            StreamHeader::V4(h) => {
                if PaymentSecurityProfile::require_encryption_context() {
                    EncryptionContext::require_for_payment(h.context.as_ref())?;
                }
                if let Some(ctx) = h.context.as_ref() {
                    event.tenant_id = Some(ctx.tenant_id.clone());
                }
                event.symmetric_algorithm = Some(format!("{:?}", h.symmetric_algorithm));
                let metadata_nonce = base64_standard.decode(h.metadata_nonce)?;
                let encrypted_metadata = base64_standard.decode(h.encrypted_metadata)?;
                let cipher = Aes256Gcm::new_from_slice(symmetric_key)?;
                let aad = context_aad(h.context.as_ref());
                let sensitive_metadata_json = cipher
                    .decrypt(
                        Nonce::from_slice(&metadata_nonce),
                        aead_payload(encrypted_metadata.as_ref(), &aad),
                    )
                    .map_err(|e| {
                        IronCryptError::DecryptionError(format!(
                            "Failed to decrypt metadata: {}",
                            e
                        ))
                    })?;
                let sensitive_metadata: SensitiveHeaderData =
                    serde_json::from_slice(&sensitive_metadata_json)?;
                let password_ok = if let Some(expected_hash_b64) = &sensitive_metadata.password_hash
                {
                    check_password_hash(expected_hash_b64, password)
                } else {
                    true
                };
                let sig_info = if let (Some(sig), Some(algo), Some(version)) = (
                    sensitive_metadata.signature,
                    sensitive_metadata.signature_algorithm,
                    sensitive_metadata.signer_key_version,
                ) {
                    event.signature_algorithm = Some(algo.clone());
                    event.signer_key_version = Some(version.clone());
                    Some((sig, algo, version))
                } else {
                    None
                };
                (
                    base64_standard.decode(sensitive_metadata.nonce)?,
                    h.symmetric_algorithm,
                    sig_info,
                    password_ok,
                )
            }
            StreamHeader::V3(h) => {
                if PaymentSecurityProfile::require_encryption_context() {
                    return Err(IronCryptError::DecryptionError(
                        "Payment profile rejects stream headers without EncryptionContext (V3)"
                            .into(),
                    ));
                }
                event.symmetric_algorithm = Some(format!("{:?}", h.symmetric_algorithm));
                let password_ok = if let Some(expected_hash_b64) = &h.password_hash {
                    check_password_hash(expected_hash_b64, password)
                } else {
                    true
                };
                (
                    base64_standard.decode(h.nonce)?,
                    h.symmetric_algorithm,
                    None,
                    password_ok,
                )
            }
            other => {
                return Err(IronCryptError::DecryptionError(format!(
                    "decrypt_stream_with_dek requires V3/V4 header, got {:?}",
                    std::mem::discriminant(&other)
                )));
            }
        };

        if !password_ok {
            return Err(IronCryptError::DecryptionError(
                "Invalid password or ciphertext".into(),
            ));
        }

        match sym_algo {
            SymmetricAlgorithm::Aes256Gcm => {
                let key_array: [u8; 32] = {
                    if symmetric_key.len() != 32 {
                        return Err(IronCryptError::DecryptionError(
                            "DEK must be 32 bytes".into(),
                        ));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(symmetric_key);
                    arr
                };
                let mut decryptor = Aes256GcmStreamDecryptor::new(key_array, &nonce_bytes);
                let mut buffer = [0u8; BUFFER_SIZE];
                let mut plaintext = Vec::new();
                loop {
                    let bytes_read = source.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    let chunk = decryptor.update(&buffer[..bytes_read]);
                    plaintext.extend_from_slice(&chunk);
                }
                let last = decryptor.finalize()?;
                plaintext.extend_from_slice(&last);
                if let Some((sig_hex, algo, _)) = &signature_info {
                    if let Some(vk) = verifying_key {
                        let hash = hashing::hash_bytes(&plaintext)?;
                        let sig = hex::decode(sig_hex)
                            .map_err(|e| IronCryptError::SignatureError(e.to_string()))?;
                        match (vk, algo.as_str()) {
                            #[cfg(feature = "rsa-algo")]
                            (PublicKey::Rsa(pk), "rsa-pss-sha256") => {
                                rsa_utils::verify_signature_pss(pk, &hash, &sig)?;
                            }
                            (PublicKey::Ecc(pk), "ecdsa-p256-sha256") => {
                                ecc_utils::verify_signature_ecc(pk, &hash, &sig)?;
                            }
                            _ => {
                                return Err(IronCryptError::SignatureVerificationFailed(
                                    "mismatched verifying key / algorithm".into(),
                                ));
                            }
                        }
                    }
                }
                destination.write_all(&plaintext)?;
            }
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                let mut ciphertext = Vec::new();
                source.read_to_end(&mut ciphertext)?;
                let cipher = XChaCha20Poly1305::new_from_slice(symmetric_key)?;
                let plaintext = cipher
                    .decrypt(XNonce::from_slice(&nonce_bytes), ciphertext.as_ref())
                    .map_err(|_| {
                        IronCryptError::DecryptionError("Invalid password or ciphertext".into())
                    })?;
                destination.write_all(&plaintext)?;
            }
        }
        Ok(())
    })();

    symmetric_key.zeroize();
    if let Err(e) = &result {
        event.set_failure(e);
    } else {
        event.outcome = Outcome::Success;
    }
    event.log();
    result
}

/// Decrypts a data stream using default ECIES options
/// (legacy nonce disabled under the Payment profile).
#[allow(clippy::too_many_arguments)]
pub fn decrypt_stream<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    private_key: &PrivateKey,
    key_version: &str,
    password: &str,
    verifying_key: Option<&PublicKey>,
) -> Result<(), IronCryptError> {
    decrypt_stream_with_options(
        source,
        destination,
        private_key,
        key_version,
        password,
        verifying_key,
        ecc_utils::EciesDecapOptions::default(),
    )
}

/// Decrypts a data stream with explicit ECIES decapsulation options.
///
/// Pass `EciesDecapOptions { allow_legacy_nonce: true }` from migration tools only.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_stream_with_options<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    private_key: &PrivateKey,
    key_version: &str,
    password: &str,
    verifying_key: Option<&PublicKey>,
    ecies_options: ecc_utils::EciesDecapOptions,
) -> Result<(), IronCryptError> {
    PaymentSecurityProfile::ensure_ecc_private(private_key)?;
    if let Some(vk) = verifying_key {
        PaymentSecurityProfile::ensure_ecc_public(vk)?;
    }

    let mut event = AuditEvent::new(Operation::Read);
    event.key_version = Some(key_version.to_string());

    let result = (|| {
        let header_len = source.read_u64::<BigEndian>()?;
        if header_len == 0 || header_len as u128 > MAX_STREAM_HEADER_SIZE as u128 {
            return Err(IronCryptError::DecryptionError(format!(
                "stream header length {header_len} exceeds MAX_STREAM_HEADER_SIZE ({MAX_STREAM_HEADER_SIZE})"
            )));
        }
        let mut header_bytes = vec![0; header_len as usize];
        source.read_exact(&mut header_bytes)?;
        let header: StreamHeader = serde_json::from_slice(&header_bytes)?;
        validate_stream_header_bounds(&header)?;

        let (symmetric_key, nonce_bytes, sym_algo, signature_info, password_ok) = match header {
            StreamHeader::V4(h) => {
                event.symmetric_algorithm = Some(format!("{:?}", h.symmetric_algorithm));
                let recipient_info = h
                    .recipients
                    .iter()
                    .find(|r| match r {
                        RecipientInfo::Rsa { key_version: v, .. } => v == key_version,
                        RecipientInfo::Ecc { key_version: v, .. } => v == key_version,
                        RecipientInfo::Provider { key_version: v, .. } => v == key_version,
                    })
                    .ok_or_else(|| {
                        IronCryptError::DecryptionError(format!(
                            "No key found for recipient version '{}'",
                            key_version
                        ))
                    })?;

                let sk = match (private_key, recipient_info) {
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

                        ecc_utils::ecies_key_decap_with_options(
                            ecc_priv_key,
                            &eph_pub_key,
                            &encapsulated_key,
                            ecies_options,
                        )?
                    }
                    (_, RecipientInfo::Provider { provider, .. }) => {
                        return Err(IronCryptError::DecryptionError(format!(
                            "Recipient uses CryptoProvider '{provider}': call \
                             read_stream_header + provider.unwrap_key + decrypt_stream_with_dek"
                        )));
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
                let aad = context_aad(h.context.as_ref());
                let sensitive_metadata_json = cipher.decrypt(
                        Nonce::from_slice(&metadata_nonce),
                        aead_payload(encrypted_metadata.as_ref(), &aad),
                    )
                    .map_err(|e| IronCryptError::DecryptionError(format!("Failed to decrypt metadata: {}", e)))?;
                let sensitive_metadata: SensitiveHeaderData = serde_json::from_slice(&sensitive_metadata_json)?;

                let password_ok = if let Some(expected_hash_b64) = &sensitive_metadata.password_hash {
                    check_password_hash(expected_hash_b64, password)
                } else {
                    true
                };

                let sig_info = if let (Some(sig), Some(algo), Some(version)) =
                    (sensitive_metadata.signature, sensitive_metadata.signature_algorithm, sensitive_metadata.signer_key_version)
                {
                    event.signature_algorithm = Some(algo.clone());
                    event.signer_key_version = Some(version.clone());
                    Some((sig, algo, version))
                } else {
                    None
                };

                (
                    sk,
                    base64_standard.decode(sensitive_metadata.nonce)?,
                    h.symmetric_algorithm,
                    sig_info,
                    password_ok,
                )
            }
            StreamHeader::V3(h) => {
                event.symmetric_algorithm = Some(format!("{:?}", h.symmetric_algorithm));
                let recipient_info = h
                    .recipients
                    .iter()
                    .find(|r| match r {
                        RecipientInfo::Rsa { key_version: v, .. } => v == key_version,
                        RecipientInfo::Ecc { key_version: v, .. } => v == key_version,
                        RecipientInfo::Provider { key_version: v, .. } => v == key_version,
                    })
                    .ok_or_else(|| {
                        IronCryptError::DecryptionError(format!(
                            "No key found for recipient version '{}'",
                            key_version
                        ))
                    })?;

                let sk = match (private_key, recipient_info) {
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

                        ecc_utils::ecies_key_decap_with_options(
                            ecc_priv_key,
                            &eph_pub_key,
                            &encapsulated_key,
                            ecies_options,
                        )?
                    }
                    (_, RecipientInfo::Provider { provider, .. }) => {
                        return Err(IronCryptError::DecryptionError(format!(
                            "Recipient uses CryptoProvider '{provider}': call \
                             read_stream_header + provider.unwrap_key + decrypt_stream_with_dek"
                        )));
                    }
                    _ => {
                        return Err(IronCryptError::DecryptionError(
                            "Mismatched private key and recipient info type".into(),
                        ))
                    }
                };

                let password_ok = if let Some(expected_hash_b64) = &h.password_hash {
                    check_password_hash(expected_hash_b64, password)
                } else {
                    true
                };

                let sig_info = None;

                (
                    sk,
                    base64_standard.decode(h.nonce)?,
                    h.symmetric_algorithm,
                    sig_info,
                    password_ok,
                )
            }
            // Backward compatibility for V1 and V2
            StreamHeader::V1(h) => {
                #[cfg(not(feature = "rsa-algo"))]
                {
                    let _ = (h, private_key, password);
                    return Err(IronCryptError::UnsupportedOperation(
                        "V1 headers require RSA decryption (rsa-algo feature disabled)".into(),
                    ));
                }
                #[cfg(feature = "rsa-algo")]
                {
                    let password_ok = if let Some(hash) = &h.password_hash {
                        check_password_hash(hash, password)
                    } else {
                        true
                    };
                    (
                        {
                            event.symmetric_algorithm =
                                Some(format!("{:?}", SymmetricAlgorithm::Aes256Gcm));
                            let key_bytes = base64_standard.decode(&h.encrypted_symmetric_key)?;
                            if let PrivateKey::Rsa(rsa_priv_key) = private_key {
                                zeroizing_vec(rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?)
                            } else {
                                return Err(IronCryptError::DecryptionError(
                                    "V1 headers only support RSA keys".into(),
                                ));
                            }
                        },
                        base64_standard.decode(&h.nonce)?,
                        SymmetricAlgorithm::Aes256Gcm,
                        None,
                        password_ok,
                    )
                }
            }
            StreamHeader::V2(h) => {
                #[cfg(not(feature = "rsa-algo"))]
                {
                    let _ = (h, private_key, password, key_version);
                    return Err(IronCryptError::UnsupportedOperation(
                        "V2 headers require RSA decryption (rsa-algo feature disabled)".into(),
                    ));
                }
                #[cfg(feature = "rsa-algo")]
                {
                    let password_ok = if let Some(hash) = &h.password_hash {
                        check_password_hash(hash, password)
                    } else {
                        true
                    };
                    (
                        {
                            event.symmetric_algorithm =
                                Some(format!("{:?}", SymmetricAlgorithm::Aes256Gcm));
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
                            let key_bytes =
                                base64_standard.decode(&recipient_info.encrypted_symmetric_key)?;
                            if let PrivateKey::Rsa(rsa_priv_key) = private_key {
                                zeroizing_vec(rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?)
                            } else {
                                return Err(IronCryptError::DecryptionError(
                                    "V2 headers only support RSA keys".into(),
                                ));
                            }
                        },
                        base64_standard.decode(&h.nonce)?,
                        SymmetricAlgorithm::Aes256Gcm,
                        None,
                        password_ok,
                    )
                }
            }
        };

        // Reject wrong passwords before any plaintext leaves this function.
        if !password_ok {
            return Err(IronCryptError::PasswordVerificationError);
        }

        let needs_buffer = signature_info.is_some()
            || matches!(sym_algo, SymmetricAlgorithm::ChaCha20Poly1305);

        if needs_buffer {
            let mut plaintext_buffer = Vec::new();
            match sym_algo {
                SymmetricAlgorithm::Aes256Gcm => {
                    let key_array: [u8; 32] = symmetric_key.as_slice().try_into().map_err(|_| {
                        IronCryptError::DecryptionError(
                            "Decrypted key has incorrect size.".to_string(),
                        )
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
                    let nonce = XNonce::from_slice(&nonce_bytes);
                    plaintext_buffer = cipher.decrypt(nonce, source_data.as_ref())?;
                }
            }

            if let Some((signature_hex, algo, _signer_version)) = signature_info {
                let key_for_verification = verifying_key.ok_or_else(|| {
                    IronCryptError::SignatureVerificationFailed(
                        "Signature found in file but no verification key was provided.".to_string(),
                    )
                })?;

                let hash = hashing::hash_bytes(&plaintext_buffer)?;
                let signature = hex::decode(signature_hex).map_err(|e| {
                    IronCryptError::SignatureError(format!("Failed to decode signature: {}", e))
                })?;

                match (algo.as_str(), key_for_verification) {
                    #[cfg(feature = "rsa-algo")]
                    ("rsa-pss-sha256", PublicKey::Rsa(k)) => {
                        rsa_utils::verify_signature_pss(k, &hash, &signature)?;
                    }
                    #[cfg(feature = "rsa-algo")]
                    ("rsa-pkcs1v15-sha256", PublicKey::Rsa(k)) => {
                        rsa_utils::verify_signature_pkcs1v15(k, &hash, &signature)?;
                    }
                    ("ecdsa-p256-sha256", PublicKey::Ecc(k)) => {
                        ecc_utils::verify_signature_ecc(k, &hash, &signature)?;
                    }
                    (other, _) => {
                        return Err(IronCryptError::SignatureVerificationFailed(format!(
                            "Unsupported signature algorithm or key type: {}",
                            other
                        )));
                    }
                }
            }

            destination.write_all(&plaintext_buffer)?;
        } else {
            // AES-GCM without signature: decrypt and write in streaming fashion.
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
                destination.write_all(&plaintext_chunk)?;
            }
            let final_chunk = decryptor.finalize()?;
            destination.write_all(&final_chunk)?;
        }

        Ok(())
    })();

    if let Err(e) = &result {
        event.set_failure(e);
    }

    event.log();

    result
}

/// Verifies a password against a base64-encoded Argon2 hash.
pub(crate) fn check_password_hash(hash_b64: &str, password: &str) -> bool {
    let Ok(expected_hash_bytes) = base64_standard.decode(hash_b64) else {
        return false;
    };
    let mut expected_hash_str = match String::from_utf8(expected_hash_bytes) {
        Ok(s) => s,
        Err(e) => {
            let mut b = e.into_bytes();
            b.zeroize();
            return false;
        }
    };

    let ok = match PasswordHash::new(&expected_hash_str) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok(),
        Err(_) => false,
    };
    expected_hash_str.zeroize();
    ok
}

/// Derives a dedicated AES-GCM nonce for sealing an optional password hash field.
fn derive_password_hash_nonce(content_nonce: &[u8]) -> [u8; 12] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ironcrypt-pwd-hash-nonce-v1");
    hasher.update(content_nonce);
    let digest = hasher.finalize();
    let mut out = [0u8; 12];
    out.copy_from_slice(&digest[..12]);
    out
}

/// Encrypts an Argon2 hash string so it is never stored in cleartext inside EncryptedData JSON.
pub(crate) fn seal_password_hash(
    symmetric_key: &[u8],
    content_nonce: &[u8],
    hash_str: &str,
) -> Result<String, IronCryptError> {
    let nonce = derive_password_hash_nonce(content_nonce);
    let cipher = Aes256Gcm::new_from_slice(symmetric_key)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), hash_str.as_bytes())
        .map_err(|e| IronCryptError::EncryptionError(format!("Failed to seal password hash: {e}")))?;
    Ok(base64_standard.encode(ciphertext))
}

/// Verifies a password against a sealed (or legacy cleartext) password_hash field.
pub(crate) fn verify_sealed_or_legacy_password_hash(
    symmetric_key: &[u8],
    content_nonce: &[u8],
    password_hash_field: &str,
    password: &str,
) -> bool {
    // Preferred: sealed Argon2 string encrypted under the content key.
    if let Ok(sealed_bytes) = base64_standard.decode(password_hash_field) {
        let nonce = derive_password_hash_nonce(content_nonce);
        if let Ok(cipher) = Aes256Gcm::new_from_slice(symmetric_key) {
            if let Ok(hash_bytes) =
                cipher.decrypt(Nonce::from_slice(&nonce), sealed_bytes.as_ref())
            {
                if let Ok(hash_str) = String::from_utf8(hash_bytes) {
                    if let Ok(parsed) = PasswordHash::new(&hash_str) {
                        return Argon2::default()
                            .verify_password(password.as_bytes(), &parsed)
                            .is_ok();
                    }
                }
            }
        }
    }

    // Legacy payloads stored the Argon2 PHC string base64-encoded in cleartext.
    check_password_hash(password_hash_field, password)
}
