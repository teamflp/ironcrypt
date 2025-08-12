use crate::IronCryptError;
use argon2::password_hash::rand_core::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::fs::File;
use std::io::Write;

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

pub fn save_keys_to_files(
    priv_key: &RsaPrivateKey,
    pub_key: &RsaPublicKey,
    priv_path: &str,
    pub_path: &str,
) -> Result<(), IronCryptError> {
    // Save private key in PKCS#8 format
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?;

    // Save public key in PKCS#1 format (as it's common)
    let pub_pem = pub_key
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?;

    let mut fpriv = File::create(priv_path)?;
    fpriv.write_all(priv_pem.as_bytes())?;

    let mut fpub = File::create(pub_path)?;
    fpub.write_all(pub_pem.as_bytes())?;

    Ok(())
}

pub fn load_public_key(path: &str) -> Result<RsaPublicKey, IronCryptError> {
    let pem_str = &std::fs::read_to_string(path)?;
    // Try parsing as PKCS#1 first, then as PKCS#8
    RsaPublicKey::from_pkcs1_pem(pem_str)
        .or_else(|_| RsaPublicKey::from_public_key_pem(pem_str))
        .map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
}

pub fn load_private_key(path: &str) -> Result<RsaPrivateKey, IronCryptError> {
    let pem_str = &std::fs::read_to_string(path)?;
    // Inspect the PEM header to decide which format to use
    if pem_str.starts_with("-----BEGIN PRIVATE KEY-----") {
        // This is PKCS#8
        RsaPrivateKey::from_pkcs8_pem(pem_str)
            .map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    } else if pem_str.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        // This is PKCS#1
        RsaPrivateKey::from_pkcs1_pem(pem_str)
            .map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    } else {
        Err(IronCryptError::KeyLoadingError(
            "Unsupported or unknown private key format".to_string(),
        ))
    }
}
