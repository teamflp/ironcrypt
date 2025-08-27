use crate::IronCryptError;
use p256::{
    pkcs8::{
        spki::DecodePublicKey, DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding,
    },
    PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use p256::ecdh;

/// Generates a new P-256 key pair.
pub fn generate_ecc_keys() -> Result<(SecretKey, PublicKey), IronCryptError> {
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    Ok((secret_key, public_key))
}

/// Saves an ECC key pair to specified file paths in PEM format.
pub fn save_keys_to_files(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    private_key_path: &str,
    public_key_path: &str,
    passphrase: Option<&str>,
) -> Result<(), IronCryptError> {
    public_key.write_public_key_pem_file(public_key_path, LineEnding::LF)?;
    let pkcs8_doc = if let Some(pass) = passphrase {
        secret_key.to_pkcs8_encrypted_pem(&mut OsRng, pass.as_bytes(), Default::default())?
    } else {
        secret_key.to_pkcs8_pem(LineEnding::LF)?
    };
    std::fs::write(private_key_path, pkcs8_doc.as_bytes())?;
    Ok(())
}

/// Loads an ECC public key from a PEM file.
pub fn load_public_key(path: &str) -> Result<PublicKey, IronCryptError> {
    PublicKey::from_public_key_pem(&std::fs::read_to_string(path)?).map_err(IronCryptError::from)
}

/// Loads an ECC secret key from a PEM file.
pub fn load_secret_key(path: &str, passphrase: Option<&str>) -> Result<SecretKey, IronCryptError> {
    let pem = &std::fs::read_to_string(path)?;
    let secret_key = if let Some(pass) = passphrase {
        SecretKey::from_pkcs8_encrypted_pem(pem, pass.as_bytes())?
    } else {
        SecretKey::from_pkcs8_pem(pem)?
    };
    Ok(secret_key)
}

/// The result of an ECIES key encapsulation operation.
#[derive(Debug)]
pub struct EciesKek {
    pub ephemeral_pk: PublicKey,
    pub encapsulated_key: Vec<u8>,
}

/// Encapsulates a symmetric key using ECIES (ECDH + HKDF + AES-GCM Key Wrap).
pub fn ecies_key_encap(
    recipient_pk: &PublicKey,
    symmetric_key: &[u8],
) -> Result<EciesKek, IronCryptError> {
    let ephemeral_sk = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let ephemeral_pk = ephemeral_sk.public_key();

    let shared_secret = ephemeral_sk.diffie_hellman(recipient_pk);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_ref());
    let mut kek = [0u8; 32];
    hkdf.expand(b"ironcrypt-ecies-kek", &mut kek)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let nonce = Nonce::from_slice(b"ironcrypt-iv");
    let encapsulated_key = cipher.encrypt(nonce, symmetric_key)
        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;

    Ok(EciesKek {
        ephemeral_pk,
        encapsulated_key,
    })
}

/// Decapsulates a symmetric key using ECIES.
pub fn ecies_key_decap(
    recipient_sk: &SecretKey,
    ephemeral_pk: &PublicKey,
    encapsulated_key: &[u8],
) -> Result<Vec<u8>, IronCryptError> {
    let shared_secret =
        ecdh::diffie_hellman(recipient_sk.to_nonzero_scalar(), ephemeral_pk.as_affine());

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_ref());
    let mut kek = [0u8; 32];
    hkdf.expand(b"ironcrypt-ecies-kek", &mut kek)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let nonce = Nonce::from_slice(b"ironcrypt-iv");
    let symmetric_key = cipher.decrypt(nonce, encapsulated_key)
        .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

    Ok(symmetric_key)
}
