use crate::IronCryptError;
use p256::{
    pkcs8::{
        spki::DecodePublicKey, DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding,
    },
    PublicKey, SecretKey,
};
use rand::rngs::OsRng;

/// Generates a new P-256 key pair.
///
/// # Returns
///
/// A `Result` containing a tuple of (`SecretKey`, `PublicKey`) or an `IronCryptError`.
pub fn generate_ecc_keys() -> Result<(SecretKey, PublicKey), IronCryptError> {
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    Ok((secret_key, public_key))
}

/// Saves an ECC key pair to specified file paths in PEM format.
///
/// # Arguments
///
/// * `secret_key` - The secret key to save.
/// * `public_key` - The public key to save.
/// * `private_key_path` - The path to save the private key.
/// * `public_key_path` - The path to save the public key.
/// * `passphrase` - An optional passphrase to encrypt the private key.
pub fn save_keys_to_files(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    private_key_path: &str,
    public_key_path: &str,
    passphrase: Option<&str>,
) -> Result<(), IronCryptError> {
    // Save the public key in PEM format
    public_key.write_public_key_pem_file(public_key_path, LineEnding::LF)?;

    // Save the private key, potentially encrypted
    let pkcs8_doc = if let Some(pass) = passphrase {
        secret_key.to_pkcs8_encrypted_pem(&mut OsRng, pass.as_bytes(), Default::default())?
    } else {
        secret_key.to_pkcs8_pem(LineEnding::LF)?
    };
    std::fs::write(private_key_path, pkcs8_doc.as_bytes())?;

    Ok(())
}

/// Loads an ECC public key from a PEM file.
///
/// # Arguments
///
/// * `path` - The path to the PEM file.
///
/// # Returns
///
/// A `Result` containing the `PublicKey` or an `IronCryptError`.
pub fn load_public_key(path: &str) -> Result<PublicKey, IronCryptError> {
    PublicKey::from_public_key_pem(&std::fs::read_to_string(path)?)
        .map_err(IronCryptError::from)
}

/// Loads an ECC secret key from a PEM file.
///
/// # Arguments
///
/// * `path` - The path to the PEM file.
/// * `passphrase` - An optional passphrase if the key is encrypted.
///
/// # Returns
///
/// A `Result` containing the `SecretKey` or an `IronCryptError`.
pub fn load_secret_key(path: &str, passphrase: Option<&str>) -> Result<SecretKey, IronCryptError> {
    let pem = &std::fs::read_to_string(path)?;
    let secret_key = if let Some(pass) = passphrase {
        SecretKey::from_pkcs8_encrypted_pem(pem, pass.as_bytes())?
    } else {
        SecretKey::from_pkcs8_pem(pem)?
    };
    Ok(secret_key)
}
