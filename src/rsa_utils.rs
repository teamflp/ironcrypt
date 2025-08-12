use crate::IronCryptError;
use argon2::password_hash::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};

// PKCS#8 (recommended modern format)
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};

// PKCS#1 (legacy format)
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};

use std::fs::File;
use std::io::Write;

/// Generates a new RSA key pair.
pub fn generate_rsa_keys(bits: u32) -> Result<(RsaPrivateKey, RsaPublicKey), IronCryptError> {
    if bits < 2048 {
        return Err(IronCryptError::KeyGenerationError(
            "RSA key size must be at least 2048 bits.".to_string(),
        ));
    }
    let priv_key = RsaPrivateKey::new(&mut OsRng, bits as usize)
        .map_err(|e| IronCryptError::KeyGenerationError(e.to_string()))?;
    let pub_key = RsaPublicKey::from(&priv_key);
    Ok((priv_key, pub_key))
}

/// Saves the RSA key pair to PEM-encoded files in the modern PKCS#8 format.
pub fn save_keys_to_files(
    priv_key: &RsaPrivateKey,
    pub_key: &RsaPublicKey,
    priv_path: &str,
    pub_path: &str,
) -> Result<(), IronCryptError> {
    // Private key: PKCS#8 ("-----BEGIN PRIVATE KEY-----")
    let priv_pem = priv_key
        .to_pkcs8_pem(Default::default())
        .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?;

    // Public key: SPKI/PKCS#8 ("-----BEGIN PUBLIC KEY-----")
    let pub_pem = pub_key
        .to_public_key_pem(Default::default())
        .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?;

    let mut fpriv = File::create(priv_path)?;
    fpriv.write_all(priv_pem.as_bytes())?;

    let mut fpub = File::create(pub_path)?;
    fpub.write_all(pub_pem.as_bytes())?;

    Ok(())
}

// Helper functions to detect PEM format by checking the header.
fn is_pkcs1_private_pem(pem: &str) -> bool {
    pem.trim_start().starts_with("-----BEGIN RSA PRIVATE KEY-----")
}
fn is_pkcs1_public_pem(pem: &str) -> bool {
    pem.trim_start().starts_with("-----BEGIN RSA PUBLIC KEY-----")
}

/// Loads an RSA public key from a PEM-encoded file.
/// Automatically detects and handles both PKCS#1 and PKCS#8 (SPKI) formats.
pub fn load_public_key(path: &str) -> Result<RsaPublicKey, IronCryptError> {
    let pem = std::fs::read_to_string(path)?;

    if is_pkcs1_public_pem(&pem) {
        RsaPublicKey::from_pkcs1_pem(&pem).map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    } else {
        // Assume PKCS#8 (SPKI) otherwise.
        RsaPublicKey::from_public_key_pem(&pem).map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    }
}

/// Loads an RSA private key from a PEM-encoded file.
/// Automatically detects and handles both PKCS#1 and PKCS#8 formats.
pub fn load_private_key(path: &str) -> Result<RsaPrivateKey, IronCryptError> {
    let pem = std::fs::read_to_string(path)?;

    if is_pkcs1_private_pem(&pem) {
        RsaPrivateKey::from_pkcs1_pem(&pem).map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    } else {
        // Assume PKCS#8 otherwise.
        RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    }
}
