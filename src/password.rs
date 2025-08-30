use crate::{
    algorithms::SymmetricAlgorithm,
    ecc_utils,
    encrypt::EncryptedData,
    handle_error::IronCryptError,
    keys::{PrivateKey, PublicKey},
    encrypt::RecipientInfo,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use chacha20poly1305::XChaCha20Poly1305;
use p256::pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use p256::pkcs8::LineEnding;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::Oaep;
use sha2::Sha256;
use zeroize::Zeroize;

/// Encrypts a password based on a public key and returns the encrypted data as a JSON string.
///
/// This function centralizes the password encryption logic, making it reusable
/// by both the main library and the FFI layer.
pub fn encrypt(
    password: &str,
    public_key: &PublicKey,
    key_version: &str,
) -> Result<String, IronCryptError> {
    // The "data" we encrypt is the password's hash, not the password itself.
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 1, None)?,
    );
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();

    let mut symmetric_key = [0u8; 32];
    OsRng.fill_bytes(&mut symmetric_key);

    // We'll use Aes256Gcm for password compatibility, as it's the original algorithm used.
    let sym_algo = SymmetricAlgorithm::Aes256Gcm;
    let nonce_len = 12; // AES-256-GCM uses a 12-byte nonce
    let mut nonce_bytes = vec![0u8; nonce_len];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Encrypt the hash itself
    let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), password_hash.as_bytes())?;

    let recipient_info = match public_key {
        PublicKey::Rsa(rsa_pub_key) => {
            let padding = Oaep::new::<Sha256>();
            let encrypted_symmetric_key =
                rsa_pub_key.encrypt(&mut OsRng, padding, &symmetric_key)?;
            RecipientInfo::Rsa {
                key_version: key_version.to_string(),
                encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
            }
        }
        PublicKey::Ecc(ecc_pub_key) => {
            let kek = ecc_utils::ecies_key_encap(ecc_pub_key, &symmetric_key)?;
            let ephemeral_public_key_pem = kek
                .ephemeral_pk
                .to_public_key_pem(LineEnding::LF)
                .map_err(|e| IronCryptError::KeySavingError(e.to_string()))?;

            RecipientInfo::Ecc {
                key_version: key_version.to_string(),
                ephemeral_public_key: base64_standard.encode(ephemeral_public_key_pem),
                encrypted_symmetric_key: base64_standard.encode(kek.encapsulated_key),
            }
        }
    };

    let enc_data = EncryptedData {
        symmetric_algorithm: sym_algo,
        recipient_info,
        nonce: base64_standard.encode(&nonce_bytes),
        ciphertext: base64_standard.encode(&ciphertext),
        // The password_hash field is now redundant since the ciphertext IS the encrypted hash.
        // However, keeping it for compatibility with the existing struct.
        // In a new version, this could be removed.
        password_hash: Some(password_hash),
    };

    symmetric_key.zeroize();
    Ok(serde_json::to_string(&enc_data)?)
}


/// Verifies a password against an encrypted JSON payload using the provided private key.
pub fn verify(
    encrypted_json: &str,
    password: &str,
    private_key: &PrivateKey,
) -> Result<bool, IronCryptError> {
    let ed: EncryptedData = serde_json::from_str(encrypted_json)?;

    let mut symmetric_key = match (private_key, &ed.recipient_info) {
        (
            PrivateKey::Rsa(rsa_priv_key),
            RecipientInfo::Rsa {
                encrypted_symmetric_key,
                ..
            },
        ) => {
            let key_bytes = base64_standard.decode(encrypted_symmetric_key)?;
            rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?
        }
        (
            PrivateKey::Ecc(ecc_priv_key),
            RecipientInfo::Ecc {
                ephemeral_public_key,
                encrypted_symmetric_key,
                ..
            },
        ) => {
            let eph_pub_key_pem = base64_standard.decode(ephemeral_public_key)?;
            let eph_pub_key = p256::PublicKey::from_public_key_pem(
                &String::from_utf8(eph_pub_key_pem)?,
            )?;
            let encapsulated_key = base64_standard.decode(encrypted_symmetric_key)?;

            ecc_utils::ecies_key_decap(ecc_priv_key, &eph_pub_key, &encapsulated_key)?
        }
        _ => {
            return Err(IronCryptError::DecryptionError(
                "Mismatched private key and recipient info type".into(),
            ))
        }
    };

    let ciphertext = base64_standard.decode(&ed.ciphertext)?;
    let nonce_bytes = base64_standard.decode(&ed.nonce)?;

    let decrypted_hash_bytes = match ed.symmetric_algorithm {
        SymmetricAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
            cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        }
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(&symmetric_key)?;
            cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        }
    }
    .map_err(|_| IronCryptError::DecryptionError("Invalid ciphertext or key".to_string()))?;

    symmetric_key.zeroize();

    let decrypted_hash_str = String::from_utf8(decrypted_hash_bytes)?;

    // Verify the user's password against the decrypted hash.
    let parsed_hash = argon2::PasswordHash::new(&decrypted_hash_str)
        .map_err(|_| IronCryptError::PasswordVerificationError)?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(_) => Err(IronCryptError::PasswordVerificationError),
    }
}
