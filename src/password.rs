use crate::{
    algorithms::SymmetricAlgorithm,
    ecc_utils,
    encrypt::Argon2Config,
    encrypt::EncryptedData,
    handle_error::IronCryptError,
    keys::{PrivateKey, PublicKey},
    encrypt::RecipientInfo,
    payment::PaymentSecurityProfile,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use p256::pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use p256::pkcs8::LineEnding;
use rand::rngs::OsRng;
use rand::RngCore;
#[cfg(feature = "rsa-algo")]
use rsa::Oaep;
#[cfg(feature = "rsa-algo")]
use sha2::Sha256;
use zeroize::Zeroize;
use crate::memsec::{new_dek32, wipe_string};
#[cfg(feature = "rsa-algo")]
use crate::memsec::zeroizing_vec;

/// Encrypts a password based on a public key and returns the encrypted data as a JSON string.
///
/// This function centralizes the password encryption logic, making it reusable
/// by both the main library and the FFI layer.
///
/// The Argon2 hash is stored only inside the ciphertext (envelope encryption).
/// The `password_hash` JSON field is left empty so the hash is never exposed in cleartext.
pub fn encrypt(
    password: &str,
    public_key: &PublicKey,
    key_version: &str,
    argon_cfg: &Argon2Config,
) -> Result<String, IronCryptError> {
    PaymentSecurityProfile::ensure_ecc_public(public_key)?;

    // The "data" we encrypt is the password's hash, not the password itself.
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            argon_cfg.memory_cost,
            argon_cfg.time_cost,
            argon_cfg.parallelism,
            None,
        )?,
    );
    let salt = SaltString::generate(&mut OsRng);
    let mut password_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();

    let symmetric_key = new_dek32();

    // We'll use Aes256Gcm for password compatibility, as it's the original algorithm used.
    let sym_algo = SymmetricAlgorithm::Aes256Gcm;
    let nonce_len = 12; // AES-256-GCM uses a 12-byte nonce
    let mut nonce_bytes = vec![0u8; nonce_len];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Encrypt the hash itself
    let cipher = Aes256Gcm::new_from_slice(symmetric_key.as_ref())?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), password_hash.as_bytes())?;
    wipe_string(&mut password_hash);

    let recipient_info = match public_key {
        #[cfg(feature = "rsa-algo")]
        PublicKey::Rsa(rsa_pub_key) => {
            let padding = Oaep::new::<Sha256>();
            let encrypted_symmetric_key =
                rsa_pub_key.encrypt(&mut OsRng, padding, symmetric_key.as_ref())?;
            RecipientInfo::Rsa {
                key_version: key_version.to_string(),
                encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
            }
        }
        PublicKey::Ecc(ecc_pub_key) => {
            let kek = ecc_utils::ecies_key_encap(ecc_pub_key, symmetric_key.as_ref())?;
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
        format_version: crate::envelope::CURRENT_JSON_FORMAT_VERSION,
        symmetric_algorithm: sym_algo,
        recipient_info,
        nonce: base64_standard.encode(&nonce_bytes),
        ciphertext: base64_standard.encode(&ciphertext),
        // Hash lives only in ciphertext — never duplicate it in cleartext JSON.
        password_hash: None,
        context: None,
    };

    // `symmetric_key` wiped on drop (including if serialize fails).
    Ok(serde_json::to_string(&enc_data)?)
}


/// Verifies a password against an encrypted JSON payload using the provided private key.
pub fn verify(
    encrypted_json: &str,
    password: &str,
    private_key: &PrivateKey,
) -> Result<bool, IronCryptError> {
    PaymentSecurityProfile::ensure_ecc_private(private_key)?;

    let ed: EncryptedData = serde_json::from_str(encrypted_json)?;

    let mut symmetric_key = match (private_key, &ed.recipient_info) {
        #[cfg(feature = "rsa-algo")]
        (
            PrivateKey::Rsa(rsa_priv_key),
            RecipientInfo::Rsa {
                encrypted_symmetric_key,
                ..
            },
        ) => {
            let key_bytes = base64_standard.decode(encrypted_symmetric_key)?;
            zeroizing_vec(rsa_priv_key.decrypt(Oaep::new::<Sha256>(), &key_bytes)?)
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
            let cipher = Aes256Gcm::new_from_slice(symmetric_key.as_ref())?;
            cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        }
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(symmetric_key.as_ref())?;
            cipher.decrypt(XNonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        }
    }
    .map_err(|_| IronCryptError::DecryptionError("Invalid ciphertext or key".to_string()))?;

    symmetric_key.zeroize();

    let mut decrypted_hash_str = match String::from_utf8(decrypted_hash_bytes) {
        Ok(s) => s,
        Err(e) => {
            let mut b = e.into_bytes();
            b.zeroize();
            return Err(IronCryptError::DecryptionError(
                "Invalid password hash encoding".into(),
            ));
        }
    };

    // Verify the user's password against the decrypted hash.
    let parsed_hash = match argon2::PasswordHash::new(&decrypted_hash_str) {
        Ok(h) => h,
        Err(_) => {
            wipe_string(&mut decrypted_hash_str);
            return Err(IronCryptError::PasswordVerificationError);
        }
    };

    // `Argon2::default()` is intentional here: the PHC-formatted hash string
    // embeds its own memory/time/parallelism params, so verification re-derives
    // them from `parsed_hash` regardless of the instance's config. This lets
    // Argon2 cost settings change over time without breaking old hashes.
    let result = match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(_) => Err(IronCryptError::PasswordVerificationError),
    };
    wipe_string(&mut decrypted_hash_str);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc_utils;

    #[test]
    fn encrypt_verify_roundtrip_does_not_leak_hash() {
        let (priv_key, pub_key) = ecc_utils::generate_ecc_keys().unwrap();
        let json = encrypt(
            "Str0ngP@ssw0rd42!",
            &PublicKey::Ecc(pub_key),
            "v1",
            &Argon2Config::default(),
        )
        .unwrap();

        let ed: EncryptedData = serde_json::from_str(&json).unwrap();
        assert!(
            ed.password_hash.is_none(),
            "Argon2 hash must not appear in cleartext JSON"
        );

        assert!(verify(
            &json,
            "Str0ngP@ssw0rd42!",
            &PrivateKey::Ecc(priv_key),
        )
        .unwrap());
    }

    #[test]
    fn encrypt_verify_rejects_wrong_password() {
        let (priv_key, pub_key) = ecc_utils::generate_ecc_keys().unwrap();
        let json = encrypt(
            "Str0ngP@ssw0rd42!",
            &PublicKey::Ecc(pub_key),
            "v1",
            &Argon2Config::default(),
        )
        .unwrap();

        assert!(!verify(&json, "WrongP@ssw0rd99!", &PrivateKey::Ecc(priv_key)).unwrap());
    }
}
