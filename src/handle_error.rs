/*
use std::fmt;

#[derive(Debug)]
pub enum IronCryptError {
    PasswordStrengthError(String),
    HashingError(argon2::password_hash::Error),
    EncryptionError(String),
    DecryptionError(String),
    IOError(std::io::Error),
    Utf8Error(std::string::FromUtf8Error),
}

// Implémentation du trait `Display` pour `IronCryptError`
impl fmt::Display for IronCryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IronCryptError::PasswordStrengthError(msg) => write!(f, "Erreur de robustesse du mot de passe: {}", msg),
            IronCryptError::HashingError(err) => write!(f, "Erreur lors du hachage: {}", err),
            IronCryptError::EncryptionError(msg) => write!(f, "Erreur de chiffrement: {}", msg),
            IronCryptError::DecryptionError(msg) => write!(f, "Erreur de déchiffrement: {}", msg),
            IronCryptError::IOError(err) => write!(f, "Erreur d'entrée/sortie: {}", err),
            IronCryptError::Utf8Error(err) => write!(f, "Erreur de conversion UTF-8: {}", err),
        }
    }
}
*/

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

    #[error("Erreur d'entrée/sortie: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Erreur de conversion UTF-8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}
impl From<argon2::password_hash::Error> for IronCryptError {
    fn from(err: argon2::password_hash::Error) -> Self {
        IronCryptError::HashingError(format!("{:?}", err))
    }
}
