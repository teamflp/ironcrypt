// handle_error.rs

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
    IOError(#[from] std::io::Error),

    #[error("Erreur de conversion UTF-8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Mot de passe invalide")]
    InvalidPassword,
}

impl From<argon2::password_hash::Error> for IronCryptError {
    fn from(err: argon2::password_hash::Error) -> Self {
        IronCryptError::HashingError(format!("{}", err))
    }
}
