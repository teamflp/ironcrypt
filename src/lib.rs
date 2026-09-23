//! # IronCrypt: A Robust and Simple Cryptography Library for Rust
//!
//! IronCrypt provides a high-level API designed to simplify common cryptographic tasks,
//! with a focus on modern algorithms and secure practices. It can be used both as a
//! command-line tool and as a Rust library integrated into your applications.
//!
//! ## Core Features
//!
//! - **Streaming Encryption:** Efficiently encrypt and decrypt large files and data streams
//!   without loading them entirely into memory.
//! - **Hybrid Encryption:** Combines the speed of symmetric encryption (AES-256-GCM)
//!   for data with the security of asymmetric encryption (RSA) for key management.
//! - **State-of-the-Art Password Hashing:** Uses Argon2, a modern and resilient algorithm
//!   designed to counter GPU-based brute-force attacks.
//! - **Advanced Key Management:** Supports versioning of RSA keys and includes a rotation
//!   mechanism to update keys without having to manually re-encrypt everything.
//! - **Flexible Configuration:** Allows fine-tuning of security parameters like RSA key
//!   size, Argon2 "costs," and password strength criteria.
//!
//! ## Quick Start
//!
//! ### Example 1: Encrypting and Verifying a Password
//!
//! The example below shows how to use the `IronCrypt` struct to securely hash a password
//! and verify it later.
//!
//! ```rust
//! use ironcrypt::{IronCrypt, IronCryptConfig, DataType, config::KeyManagementConfig};
//! use std::collections::HashMap;
//! use std::error::Error;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     // 1. Use a temporary directory for keys to keep tests isolated.
//!     let temp_dir = tempfile::tempdir()?;
//!     let key_dir = temp_dir.path().to_str().unwrap();
//!
//!     // 2. Configure IronCrypt to use the temporary directory.
//!     let mut config = IronCryptConfig::default();
//!     let mut data_type_config = HashMap::new();
//!     data_type_config.insert(
//!         DataType::Generic,
//!         KeyManagementConfig {
//!             key_directory: key_dir.to_string(),
//!             key_version: "v1".to_string(),
//!             passphrase: None,
//!         },
//!     );
//!     config.data_type_config = Some(data_type_config);
//!
//!     // 3. Initialize IronCrypt.
//!     let crypt = IronCrypt::new(config, DataType::Generic).await?;
//!
//!     // 4. Encrypt a password.
//!     let password = "MySecurePassword123!";
//!     let encrypted_json = crypt.encrypt_password(password)?;
//!     println!("Encrypted password: {}", encrypted_json);
//!
//!     // 5. Verify the password.
//!     let is_valid = crypt.verify_password(&encrypted_json, password)?;
//!     assert!(is_valid);
//!     println!("Password verification successful!");
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Example 2: Streaming File Encryption
//!
//! This example shows how to encrypt a data stream (here, an in-memory `Cursor`,
//! but it works the same way with a `File`).
//!
//! ```rust
//! use ironcrypt::{encrypt_stream, decrypt_stream, generate_rsa_keys, PasswordCriteria, Argon2Config, PublicKey, PrivateKey, algorithms::SymmetricAlgorithm};
//! use std::io::Cursor;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Generate an RSA key pair (in a real application, load them from a file).
//!     let (private_key, public_key) = generate_rsa_keys(2048)?;
//!
//!     // 2. Prepare the source and destination streams.
//!     let original_data = "This is a secret message that will be streamed for encryption.";
//!     let mut source = Cursor::new(original_data.as_bytes());
//!     let mut encrypted_dest = Cursor::new(Vec::new());
//!
//!     // 3. Encrypt the stream.
//!     let mut password = "AnotherStrongPassword123!".to_string();
//!     let pk_enum = PublicKey::Rsa(public_key);
//!     let recipients = vec![(&pk_enum, "v1")];
//!     encrypt_stream(
//!         &mut source,
//!         &mut encrypted_dest,
//!         &mut password,
//!         recipients,
//!         None, // signing_key
//!         &PasswordCriteria::default(),
//!         Argon2Config::default(),
//!         true, // Indicates that the password should be hashed
//!         SymmetricAlgorithm::Aes256Gcm,
//!     )?;
//!
//!     // 4. Go back to the beginning of the encrypted stream to read it.
//!     encrypted_dest.set_position(0);
//!
//!     // 5. Decrypt the stream.
//!     let mut decrypted_dest = Cursor::new(Vec::new());
//!     decrypt_stream(
//!         &mut encrypted_dest,
//!         &mut decrypted_dest,
//!         &PrivateKey::Rsa(private_key),
//!         "v1",
//!         "AnotherStrongPassword123!",
//!         None // verifying_key
//!     )?;
//!
//!     // 6. Verify that the decrypted data matches the original data.
//!     let decrypted_data = String::from_utf8(decrypted_dest.into_inner())?;
//!     assert_eq!(original_data, decrypted_data);
//!     println!("Stream encryption and decryption successful!");
//!
//!     Ok(())
//! }
//! ```
//!
//! For more advanced examples, including custom configurations,
//! check out the `examples/` directory of the project.

// --- Modules ---
// Payment builds must not link the `rsa` crate (RUSTSEC-2023-0071).
#[cfg(all(feature = "payment", feature = "rsa-algo"))]
compile_error!(
    "features `payment` and `rsa-algo` are mutually exclusive. \
     Build Payment with: cargo build --no-default-features --features payment-daemon \
     (or payment-aws / payment-vault / payment-hsm)."
);

pub mod ffi;
pub mod password;
pub mod algorithms;
pub mod api_roles;
pub mod audit;
#[cfg(feature = "cli")]
pub mod archive_safe;
pub mod auth;
pub mod api_key_store;
pub mod config;
pub mod context;
pub mod criteria;
pub mod crypto_allowlist;
pub mod crypto_provider;
pub mod dual_control;
pub mod ecc_utils;
pub mod encrypt;
pub mod envelope;
pub mod fingerprint;
pub mod handle_error;
pub mod hashing;
pub mod ironcrypt;
pub mod key_lifecycle;
pub mod limits;
pub mod memsec;
pub mod metrics;
pub mod keys;
pub mod payment;
pub mod rate_limit;
pub mod resilience;
pub mod secret_input;
#[cfg(feature = "rsa-algo")]
pub mod rsa_utils;
pub mod secrets;
pub mod signing;
pub mod standards;
pub mod webhook;

// --- Public Re-exports ---

// Main configuration
pub use config::{AuditConfig, AuditSigningMode, DataType, IronCryptConfig};

// Key types
pub use keys::{PrivateKey, PublicKey};

// Password criteria
pub use criteria::PasswordCriteria;

// Cryptographic standards
pub use standards::CryptoStandard;

// Payment security profile
pub use payment::PaymentSecurityProfile;
pub use crypto_allowlist::{ensure_suite_allowed, is_suite_listed, ALLOWED_SUITES, CryptoSuite};
pub use envelope::{
    CURRENT_JSON_FORMAT_VERSION, CURRENT_STREAM_VERSION, EnvelopeStatus,
    ensure_json_format_allowed, ensure_stream_header_allowed, stream_header_status,
};

// Encryption context (AAD)
pub use context::EncryptionContext;

// Key lifecycle
pub use key_lifecycle::{
    KeyState, KeyVersionMeta, KeyringManifest, RotationPolicy, RotationReport,
};

// Crypto providers (distinct from SecretStore)
pub use crypto_provider::{CryptoProvider, HaCryptoProvider, LocalKeyProvider, WrappedKey};
#[cfg(feature = "aws-kms")]
pub use crypto_provider::AwsKmsProvider;
#[cfg(feature = "hsm")]
pub use crypto_provider::HsmProvider;
#[cfg(feature = "vault")]
pub use crypto_provider::VaultTransitProvider;

// Hard limits
pub use limits::{
    DEFAULT_CIRCUIT_COOLDOWN_SECS, DEFAULT_CIRCUIT_FAILURE_THRESHOLD, DEFAULT_CRYPTO_CONCURRENCY,
    DEFAULT_HTTP_BODY_LIMIT, DEFAULT_PROVIDER_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS,
    MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_ENTRY_BYTES, MAX_ARCHIVE_UNPACKED_BYTES, MAX_RECIPIENTS,
    MAX_STREAM_HEADER_SIZE,
};

pub use metrics::{init_metrics, metrics_finish, metrics_start, provider_op_finish, SAFE_METRIC_LABEL_KEYS};

pub use memsec::{
    dek32_from, mlock_enabled, new_dek32, try_mlock, try_munlock, wipe_string, zeroizing_vec,
    MlockGuard, ZeroizeOnDrop, Dek32,
};
pub use secret_input::{
    passphrase_as_str, resolve_passphrase, resolve_passphrase_or_prompt, PASSPHRASE_ENV,
    PASSPHRASE_FD_ENV, PASSPHRASE_FILE_ENV, PASSPHRASE_STDIN_ENV,
};
pub use auth::{
    expand_full_permissions, rotate_api_key_file, rotate_api_keys, ApiKeyConfig, ApiKeyRotation,
    AuthenticatedPrincipal, Permission,
};
pub use api_key_store::{
    build_api_key_store, parse_api_keys_json, ApiKeyBackend, ApiKeyStore, EnvApiKeyStore,
    FileApiKeyStore,
};
pub use resilience::{CircuitBreaker, RetryPolicy, with_retry, with_timeout};
pub use rate_limit::{bucket_key as rate_limit_bucket_key, build_rate_limiter, MemoryRateLimiter, RateLimiter};
pub use fingerprint::{Fingerprint, FingerprintSigner, FINGERPRINT_VERSION};
pub use dual_control::{verify_quorum, AdminAction, Approval, DualControlPolicy};
pub use api_roles::tokenization::{
    reject_cardholder_auth_data, RefusingTokenizationProvider, Token, TokenizationProvider,
    POLICY as TOKENIZATION_POLICY,
};
pub use ecc_utils::ECIES_HKDF_INFO_V1;
pub use webhook::{WebhookSigner, DEFAULT_MAX_SKEW_SECS, WEBHOOK_SIG_VERSION};
pub use audit::{
    append_audit_jsonl, attest_audit_file_with_provider, audit_event_to_siem, audit_sign_targets,
    error_category, export_audit_jsonl_for_siem, purge_expired_audit_segments,
    sanitize_error_message, sanitize_secret_name, sign_audit_configured, sign_audit_file,
    sign_audit_file_hmac, sign_audit_from_config, sign_audit_rolling_directory,
    verify_audit_file_hmac, verify_audit_file_signature, verify_audit_jsonl, AUDIT_CHAIN_GENESIS,
    SIEM_ALLOWLIST_KEYS,
};
// Streaming encryption and decryption functions
pub use encrypt::{decrypt_stream, decrypt_stream_with_options, encrypt_stream, encrypt_stream_with_context};
pub use encrypt::{
    decrypt_stream_with_dek, encrypt_stream_with_dek, find_recipient, read_stream_header,
    EncryptedStreamHeaderV1, EncryptedStreamHeaderV2, RecipientInfo, StreamHeader,
};
/// Contains the parameters for the Argon2 hashing algorithm.
pub use encrypt::Argon2Config;
/// Struct containing the encrypted data and associated metadata.
pub use encrypt::EncryptedData;

// Error handling
pub use handle_error::IronCryptError;

// Password hashing / login verify (non-recoverable)
pub use hashing::{hash_password, hash_password_with_config, password_needs_rehash, verify_password};

// Main library struct
pub use ironcrypt::IronCrypt;

// RSA key utilities (optional — disabled under Payment graphs)
#[cfg(feature = "rsa-algo")]
pub use rsa_utils::{generate_rsa_keys, load_private_key, load_public_key, save_keys_to_files};

// Secret management
#[cfg(feature = "vault")]
pub use secrets::vault;
pub use secrets::SecretStore;
#[cfg(feature = "aws")]
pub use secrets::aws;
#[cfg(feature = "azure")]
pub use secrets::azure;
#[cfg(feature = "gcp")]
pub use secrets::google;

/// Tries to load a public key from a file, attempting to parse it as RSA and then ECC.
///
/// Under the `payment` feature, only ECC keys are accepted (RSA is rejected even if
/// the PEM parses successfully). Without `rsa-algo`, only ECC is attempted.
pub fn load_any_public_key(path: &str) -> Result<PublicKey, IronCryptError> {
    #[cfg(feature = "rsa-algo")]
    if PaymentSecurityProfile::allow_rsa() {
        if let Ok(key) = rsa_utils::load_public_key(path) {
            return Ok(PublicKey::Rsa(key));
        }
    }
    if let Ok(key) = ecc_utils::load_public_key(path) {
        return Ok(PublicKey::Ecc(key));
    }
    #[cfg(feature = "rsa-algo")]
    if !PaymentSecurityProfile::allow_rsa() {
        // Surface a clear Payment error when the file is RSA-only.
        if rsa_utils::load_public_key(path).is_ok() {
            return Err(IronCryptError::ConfigurationError(
                "Payment profile forbids RSA public keys; use ECC (P-256).".into(),
            ));
        }
    }
    Err(IronCryptError::KeyLoadingError(format!(
        "Failed to load public key from {}: unsupported format",
        path
    )))
}

/// Tries to load a private key from a file, attempting to parse it as RSA and then ECC.
///
/// Under the `payment` feature, only ECC keys are accepted.
pub fn load_any_private_key(
    path: &str,
    passphrase: Option<&str>,
) -> Result<PrivateKey, IronCryptError> {
    #[cfg(feature = "rsa-algo")]
    if PaymentSecurityProfile::allow_rsa() {
        if let Ok(key) = rsa_utils::load_private_key(path, passphrase) {
            return Ok(PrivateKey::Rsa(key));
        }
    }
    if let Ok(key) = ecc_utils::load_secret_key(path, passphrase) {
        return Ok(PrivateKey::Ecc(key));
    }
    #[cfg(feature = "rsa-algo")]
    if !PaymentSecurityProfile::allow_rsa() {
        if rsa_utils::load_private_key(path, passphrase).is_ok() {
            return Err(IronCryptError::ConfigurationError(
                "Payment profile forbids RSA private keys; use ECC (P-256) or a CryptoProvider."
                    .into(),
            ));
        }
    }
    Err(IronCryptError::KeyLoadingError(format!(
        "Failed to load private key from {}: unsupported format or wrong passphrase",
        path
    )))
}

// Ensure every ```rust``` block in README.md compiles (and runs) under
// `cargo test --doc`. Sketch / framework samples use ```rust,ignore```.
#[cfg(doctest)]
doc_comment::doctest!("../README.md");
