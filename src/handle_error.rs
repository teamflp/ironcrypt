// handle_errors.rs
#[derive(Debug)]
pub enum IronCryptError {
    PasswordStrengthError(String),
    HashingError(argon2::password_hash::Error),
    EncryptionError(String),
    DecryptionError(String),
    IOError(std::io::Error),
    Utf8Error(std::string::FromUtf8Error),
}

impl From<std::io::Error> for IronCryptError {
    fn from(err: std::io::Error) -> Self {
        IronCryptError::IOError(err)
    }
}

impl From<std::string::FromUtf8Error> for IronCryptError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        IronCryptError::Utf8Error(err)
    }
}

impl From<argon2::password_hash::Error> for IronCryptError {
    fn from(err: argon2::password_hash::Error) -> Self {
        IronCryptError::HashingError(err)
    }
}
