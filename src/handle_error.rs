// handle_error.rs

use aes_gcm::Error as AesGcmError;
use argon2::password_hash::Error as ArgonError;
use base64::DecodeError as Base64DecodeError;
use cipher::InvalidLength as CipherInvalidLength;
use p256::pkcs8;
use rsa::errors::Error as RsaError;
use serde_json::Error as SerdeJsonError;
use std::error::Error;
use std::io::Error as IoError;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IronCryptError {
    #[error("Password strength error: {0}")]
    PasswordStrengthError(String),

    #[error("Hashing error: {0}")]
    HashingError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    #[error("Key loading error: {0}")]
    KeyLoadingError(String),

    #[error("Key saving error: {0}")]
    KeySavingError(String),

    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    #[error("I/O error: {0}")]
    IOError(#[from] IoError),

    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] FromUtf8Error),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Password verification failed")]
    PasswordVerificationError,

    #[error("Argon2 configuration error: {0}")]
    Argon2Error(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Secret store error: {0}")]
    SecretStoreError(String),

    #[error("PKCS#8 error: {0}")]
    Pkcs8Error(#[from] pkcs8::Error),

    #[error("SPKI error: {0}")]
    SpkiError(#[from] pkcs8::spki::Error),

    #[error("Elliptic curve error: {0}")]
    EllipticCurveError(#[from] p256::elliptic_curve::Error),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
}

impl From<Box<dyn Error + Send + Sync>> for IronCryptError {
    fn from(err: Box<dyn Error + Send + Sync>) -> Self {
        IronCryptError::SecretStoreError(err.to_string())
    }
}

impl From<ArgonError> for IronCryptError {
    fn from(err: ArgonError) -> Self {
        IronCryptError::HashingError(format!("{err}"))
    }
}

impl From<AesGcmError> for IronCryptError {
    fn from(err: AesGcmError) -> Self {
        IronCryptError::EncryptionError(format!("AES-GCM error: {err}"))
    }
}

impl From<CipherInvalidLength> for IronCryptError {
    fn from(err: CipherInvalidLength) -> Self {
        IronCryptError::EncryptionError(format!("Invalid key length: {err}"))
    }
}

impl From<Base64DecodeError> for IronCryptError {
    fn from(err: Base64DecodeError) -> Self {
        IronCryptError::DecryptionError(format!("Base64 decoding error: {err}"))
    }
}

impl From<RsaError> for IronCryptError {
    fn from(err: RsaError) -> Self {
        IronCryptError::DecryptionError(format!("RSA error: {err}"))
    }
}

impl From<SerdeJsonError> for IronCryptError {
    fn from(err: SerdeJsonError) -> Self {
        IronCryptError::DecryptionError(format!("JSON error: {err}"))
    }
}

impl From<argon2::Error> for IronCryptError {
    fn from(err: argon2::Error) -> Self {
        IronCryptError::Argon2Error(format!("{err}"))
    }
}

impl From<hkdf::InvalidLength> for IronCryptError {
    fn from(err: hkdf::InvalidLength) -> Self {
        IronCryptError::KeyDerivationError(format!("HKDF error: {err}"))
    }
}

impl From<String> for IronCryptError {
    fn from(err: String) -> Self {
        IronCryptError::DecryptionError(err)
    }
}