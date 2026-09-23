use crate::IronCryptError;
use argon2::password_hash::rand_core::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};

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
    passphrase: Option<&str>,
) -> Result<(), IronCryptError> {
    // Save private key in PKCS#8 format
    let priv_pem = if let Some(pass) = passphrase {
        priv_key
            .to_pkcs8_encrypted_pem(&mut OsRng, pass.as_bytes(), LineEnding::LF)
            .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?
    } else {
        priv_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?
    };

    // Save public key in PKCS#1 format (as it's common)
    let pub_pem = pub_key
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?;

    crate::key_lifecycle::atomic_write(std::path::Path::new(priv_path), priv_pem.as_bytes())?;
    crate::key_lifecycle::atomic_write(std::path::Path::new(pub_path), pub_pem.as_bytes())?;

    Ok(())
}

pub fn load_public_key(path: &str) -> Result<RsaPublicKey, IronCryptError> {
    let pem_str = &std::fs::read_to_string(path)?;
    // Try parsing as PKCS#1 first, then as PKCS#8
    RsaPublicKey::from_pkcs1_pem(pem_str)
        .or_else(|_| RsaPublicKey::from_public_key_pem(pem_str))
        .map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
}

pub fn load_private_key(
    path: &str,
    passphrase: Option<&str>,
) -> Result<RsaPrivateKey, IronCryptError> {
    let pem_str = &std::fs::read_to_string(path)?;

    if let Some(pass) = passphrase {
        if pem_str.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
            return RsaPrivateKey::from_pkcs8_encrypted_pem(pem_str, pass.as_bytes())
                .map_err(|e| IronCryptError::KeyLoadingError(format!("Failed to decrypt key. Is the passphrase correct? Original error: {}", e)));
        }
    }

    if pem_str.starts_with("-----BEGIN PRIVATE KEY-----") {
        RsaPrivateKey::from_pkcs8_pem(pem_str)
            .map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    } else if pem_str.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        RsaPrivateKey::from_pkcs1_pem(pem_str)
            .map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    } else if pem_str.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        Err(IronCryptError::KeyLoadingError(
            "Private key is encrypted, but no passphrase was provided.".to_string(),
        ))
    } else {
        Err(IronCryptError::KeyLoadingError(
            "Unsupported or unknown private key format".to_string(),
        ))
    }
}

use sha2::Sha256;
use signature::hazmat::{PrehashSigner, PrehashVerifier, RandomizedPrehashSigner};
use signature::SignatureEncoding;

/// Signs a pre-hash with RSA-PSS (SHA-256). Preferred modern default.
pub fn sign_hash(
    private_key: &RsaPrivateKey,
    hash: &[u8],
) -> Result<Vec<u8>, IronCryptError> {
    sign_hash_pss(private_key, hash)
}

/// Signs a pre-hash with RSA-PSS (SHA-256).
pub fn sign_hash_pss(
    private_key: &RsaPrivateKey,
    hash: &[u8],
) -> Result<Vec<u8>, IronCryptError> {
    use rsa::pss::{BlindedSigningKey, Signature};
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key.clone());
    let signature: Signature = signing_key
        .sign_prehash_with_rng(&mut OsRng, hash)
        .map_err(|e| IronCryptError::SignatureError(e.to_string()))?;
    Ok(signature.to_vec())
}

/// Legacy PKCS#1 v1.5 signatures (kept for verifying older payloads).
pub fn sign_hash_pkcs1v15(
    private_key: &RsaPrivateKey,
    hash: &[u8],
) -> Result<Vec<u8>, IronCryptError> {
    use rsa::pkcs1v15::{Signature, SigningKey};
    let signing_key = SigningKey::<Sha256>::new_unprefixed(private_key.clone());
    let signature: Signature = signing_key
        .sign_prehash(hash)
        .map_err(|e| IronCryptError::SignatureError(e.to_string()))?;
    Ok(signature.to_vec())
}

/// Verifies RSA-PSS (preferred) then falls back to PKCS#1 v1.5 for legacy signatures.
pub fn verify_signature(
    public_key: &RsaPublicKey,
    hash: &[u8],
    signature_bytes: &[u8],
) -> Result<(), IronCryptError> {
    match verify_signature_pss(public_key, hash, signature_bytes) {
        Ok(()) => Ok(()),
        Err(_) => verify_signature_pkcs1v15(public_key, hash, signature_bytes),
    }
}

pub fn verify_signature_pss(
    public_key: &RsaPublicKey,
    hash: &[u8],
    signature_bytes: &[u8],
) -> Result<(), IronCryptError> {
    use rsa::pss::{Signature, VerifyingKey};
    let signature = Signature::try_from(signature_bytes)
        .map_err(|e| IronCryptError::SignatureError(e.to_string()))?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
    verifying_key
        .verify_prehash(hash, &signature)
        .map_err(|e| IronCryptError::SignatureVerificationFailed(e.to_string()))
}

pub fn verify_signature_pkcs1v15(
    public_key: &RsaPublicKey,
    hash: &[u8],
    signature_bytes: &[u8],
) -> Result<(), IronCryptError> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    let signature = Signature::try_from(signature_bytes)
        .map_err(|e| IronCryptError::SignatureError(e.to_string()))?;
    let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(public_key.clone());
    verifying_key
        .verify_prehash(hash, &signature)
        .map_err(|e| IronCryptError::SignatureVerificationFailed(e.to_string()))
}

pub fn load_private_key_from_str(
    pem_str: &str,
    passphrase: Option<&str>,
) -> Result<RsaPrivateKey, IronCryptError> {
    if let Some(pass) = passphrase {
        if pem_str.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
            return RsaPrivateKey::from_pkcs8_encrypted_pem(pem_str, pass.as_bytes())
                .map_err(|e| IronCryptError::KeyLoadingError(format!("Failed to decrypt key. Is the passphrase correct? Original error: {}", e)));
        }
    }

    if pem_str.starts_with("-----BEGIN PRIVATE KEY-----") {
        RsaPrivateKey::from_pkcs8_pem(pem_str)
            .map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    } else if pem_str.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        RsaPrivateKey::from_pkcs1_pem(pem_str)
            .map_err(|e| IronCryptError::KeyLoadingError(e.to_string()))
    } else if pem_str.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        Err(IronCryptError::KeyLoadingError(
            "Private key is encrypted, but no passphrase was provided.".to_string(),
        ))
    } else {
        Err(IronCryptError::KeyLoadingError(
            "Unsupported or unknown private key format".to_string(),
        ))
    }
}
