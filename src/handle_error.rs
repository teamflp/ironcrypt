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
