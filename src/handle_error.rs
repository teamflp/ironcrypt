// handle_error.rs

use aes_gcm::Error as AesGcmError;
use argon2::password_hash::Error as ArgonError;
use base64::DecodeError as Base64DecodeError;
use cipher::InvalidLength as CipherInvalidLength;
use rsa::errors::Error as RsaError;
use serde_json::Error as SerdeJsonError;
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

    #[error("I/O error: {0}")]
    IOError(#[from] IoError),

    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] FromUtf8Error),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Argon2 configuration error: {0}")]
    Argon2Error(String),
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
