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

/// Represents all possible errors that can occur within the IronCrypt library.
#[derive(Debug, Error)]
pub enum IronCryptError {
    /// Error returned when a password does not meet the defined strength criteria.
    #[error("Password strength error: {0}")]
    PasswordStrengthError(String),

    /// An error occurred during the password hashing process with Argon2.
    #[error("Hashing error: {0}")]
    HashingError(String),

    /// An error occurred during symmetric (AES) or asymmetric (RSA) encryption.
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// An error occurred during symmetric (AES) or asymmetric (RSA) decryption.
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Failed to generate a new RSA key pair.
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    /// Failed to load an RSA key from a file.
    #[error("Key loading error: {0}")]
    KeyLoadingError(String),

    /// Failed to save an RSA key to a file.
    #[error("Key saving error: {0}")]
    KeySavingError(String),

    /// A standard I/O error occurred (e.g., file not found, permission denied).
    #[error("I/O error: {0}")]
    IOError(#[from] IoError),

    /// An error occurred when converting a byte sequence to a UTF-8 string.
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] FromUtf8Error),

    /// The provided password does not match the stored hash during verification.
    #[error("Invalid password")]
    InvalidPassword,

    /// An error occurred during the configuration of the Argon2 algorithm.
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
