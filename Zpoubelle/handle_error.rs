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
    #[error("Erreur de robustesse du mot de passe: {0}")]
    PasswordStrengthError(String),

    #[error("Erreur lors du hachage: {0}")]
    HashingError(String),

    #[error("Erreur de chiffrement: {0}")]
    EncryptionError(String),

    #[error("Erreur de déchiffrement: {0}")]
    DecryptionError(String),

    #[error("Erreur lors de la génération des clés : {0}")]
    KeyGenerationError(String),

    #[error("Erreur lors du chargement de la clé : {0}")]
    KeyLoadingError(String),

    #[error("Erreur lors de la sauvegarde de la clé : {0}")]
    KeySavingError(String),

    #[error("Erreur d'entrée/sortie: {0}")]
    IOError(#[from] IoError),

    #[error("Erreur de conversion UTF-8: {0}")]
    Utf8Error(#[from] FromUtf8Error),

    #[error("Mot de passe invalide")]
    InvalidPassword,

    #[error("Erreur lors de la configuration d'Argon2: {0}")]
    Argon2Error(String),
}

impl From<ArgonError> for IronCryptError {
    fn from(err: ArgonError) -> Self {
        IronCryptError::HashingError(format!("{}", err))
    }
}

impl From<AesGcmError> for IronCryptError {
    fn from(err: AesGcmError) -> Self {
        IronCryptError::EncryptionError(format!("Erreur AES-GCM : {}", err))
    }
}

impl From<CipherInvalidLength> for IronCryptError {
    fn from(err: CipherInvalidLength) -> Self {
        IronCryptError::EncryptionError(format!("Erreur de longueur de clé : {}", err))
    }
}

impl From<Base64DecodeError> for IronCryptError {
    fn from(err: Base64DecodeError) -> Self {
        IronCryptError::DecryptionError(format!("Erreur de décodage Base64 : {}", err))
    }
}

impl From<RsaError> for IronCryptError {
    fn from(err: RsaError) -> Self {
        IronCryptError::DecryptionError(format!("Erreur RSA : {}", err))
    }
}

impl From<SerdeJsonError> for IronCryptError {
    fn from(err: SerdeJsonError) -> Self {
        IronCryptError::DecryptionError(format!("Erreur JSON : {}", err))
    }
}

impl From<argon2::Error> for IronCryptError {
    fn from(err: argon2::Error) -> Self {
        IronCryptError::Argon2Error(format!("{}", err))
    }
}
