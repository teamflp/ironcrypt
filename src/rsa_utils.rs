// use crate::rsa_utils::{generate_rsa_keys as other_generate_rsa_keys, load_private_key, load_public_key, save_keys_to_files};
use crate::IronCryptError;
use argon2::password_hash::rand_core::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::fs::File;
use std::io::Write;

pub fn generate_rsa_keys(bits: u32) -> Result<(RsaPrivateKey, RsaPublicKey), IronCryptError> {
    let priv_key = RsaPrivateKey::new(&mut OsRng, bits as usize)
        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
    let pub_key = RsaPublicKey::from(&priv_key);
    Ok((priv_key, pub_key))
}

pub fn save_keys_to_files(
    priv_key: &RsaPrivateKey,
    pub_key: &RsaPublicKey,
    priv_path: &str,
    pub_path: &str,
) -> Result<(), IronCryptError> {
    let priv_pem = priv_key
        .to_pkcs1_pem(Default::default())
        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
    let pub_pem = pub_key
        .to_pkcs1_pem(Default::default())
        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;

    let mut fpriv = File::create(priv_path)?;
    fpriv.write_all(priv_pem.as_bytes())?;

    let mut fpub = File::create(pub_path)?;
    fpub.write_all(pub_pem.as_bytes())?;

    Ok(())
}

pub fn load_public_key(path: &str) -> Result<RsaPublicKey, IronCryptError> {
    let pem = std::fs::read_to_string(path)?;
    let pub_key = RsaPublicKey::from_pkcs1_pem(&pem)
        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
    Ok(pub_key)
}

pub fn load_private_key(path: &str) -> Result<RsaPrivateKey, IronCryptError> {
    let pem = std::fs::read_to_string(path)?;
    let priv_key = RsaPrivateKey::from_pkcs1_pem(&pem)
        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
    Ok(priv_key)
}
