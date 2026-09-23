use crate::IronCryptError;
use crate::payment::PaymentSecurityProfile;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use p256::ecdh;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::{
    pkcs8::{
        spki::DecodePublicKey, DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding,
    },
    PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use sha2::Sha256;
use signature::{Signer, Verifier};
use zeroize::Zeroizing;
use crate::memsec::zeroizing_vec;

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
    let pub_pem = public_key.to_public_key_pem(LineEnding::LF)?;
    let pkcs8_doc = if let Some(pass) = passphrase {
        secret_key.to_pkcs8_encrypted_pem(&mut OsRng, pass.as_bytes(), Default::default())?
    } else {
        secret_key.to_pkcs8_pem(LineEnding::LF)?
    };
    crate::key_lifecycle::atomic_write(
        std::path::Path::new(public_key_path),
        pub_pem.as_bytes(),
    )?;
    crate::key_lifecycle::atomic_write(
        std::path::Path::new(private_key_path),
        pkcs8_doc.as_bytes(),
    )?;
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

const ECIES_NONCE_LEN: usize = 12;
/// Legacy fixed nonce used by older IronCrypt builds.
/// Kept only behind [`EciesDecapOptions::allow_legacy_nonce`] for migration tools —
/// never enabled under the Payment profile.
const ECIES_LEGACY_NONCE: &[u8; ECIES_NONCE_LEN] = b"ironcrypt-iv";

/// Domain-separated HKDF info for ECIES KEK derivation (ECIES-v1).
///
/// See [`PROTOCOL.md`](../../PROTOCOL.md).
pub const ECIES_HKDF_INFO_V1: &[u8] =
    b"ironcrypt-ecies-v1|usage=kek|alg=aes-256-gcm|curve=p256";

/// Options for ECIES decapsulation.
#[derive(Debug, Clone, Copy)]
pub struct EciesDecapOptions {
    /// When `true`, accept historical payloads that used a fixed nonce / old HKDF info.
    /// Payment builds default this to `false`.
    pub allow_legacy_nonce: bool,
}

impl Default for EciesDecapOptions {
    fn default() -> Self {
        Self {
            allow_legacy_nonce: PaymentSecurityProfile::allow_ecies_legacy_nonce(),
        }
    }
}

/// Encapsulates a symmetric key using ECIES (ECDH + HKDF + AES-GCM Key Wrap).
///
/// The encapsulated blob is `random_nonce (12) || AES-GCM(ciphertext || tag)`.
pub fn ecies_key_encap(
    recipient_pk: &PublicKey,
    symmetric_key: &[u8],
) -> Result<EciesKek, IronCryptError> {
    use rand::RngCore;

    let ephemeral_sk = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let ephemeral_pk = ephemeral_sk.public_key();

    let shared_secret = ephemeral_sk.diffie_hellman(recipient_pk);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_ref());
    let mut kek = Zeroizing::new([0u8; 32]);
    hkdf.expand(ECIES_HKDF_INFO_V1, kek.as_mut())?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek.as_ref()));
    // `kek` wiped on drop even if encrypt fails below.

    let mut nonce_bytes = [0u8; ECIES_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), symmetric_key)
        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;

    let mut encapsulated_key = Vec::with_capacity(ECIES_NONCE_LEN + ciphertext.len());
    encapsulated_key.extend_from_slice(&nonce_bytes);
    encapsulated_key.extend_from_slice(&ciphertext);

    Ok(EciesKek {
        ephemeral_pk,
        encapsulated_key,
    })
}

/// Decapsulates a symmetric key using ECIES with default options
/// (legacy nonce disabled under the Payment profile).
pub fn ecies_key_decap(
    recipient_sk: &SecretKey,
    ephemeral_pk: &PublicKey,
    encapsulated_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, IronCryptError> {
    ecies_key_decap_with_options(
        recipient_sk,
        ephemeral_pk,
        encapsulated_key,
        EciesDecapOptions::default(),
    )
}

/// Decapsulates a symmetric key using ECIES.
pub fn ecies_key_decap_with_options(
    recipient_sk: &SecretKey,
    ephemeral_pk: &PublicKey,
    encapsulated_key: &[u8],
    options: EciesDecapOptions,
) -> Result<Zeroizing<Vec<u8>>, IronCryptError> {
    let shared_secret =
        ecdh::diffie_hellman(recipient_sk.to_nonzero_scalar(), ephemeral_pk.as_affine());

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_ref());
    let mut kek = Zeroizing::new([0u8; 32]);

    let infos: &[&[u8]] = if options.allow_legacy_nonce {
        &[ECIES_HKDF_INFO_V1, b"ironcrypt-ecies-kek"]
    } else {
        &[ECIES_HKDF_INFO_V1]
    };

    let mut last_err: Option<String> = None;
    for info in infos {
        if hkdf.expand(info, kek.as_mut()).is_err() {
            continue;
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek.as_ref()));

        // Preferred format: random nonce || ciphertext
        if encapsulated_key.len() > ECIES_NONCE_LEN {
            let (nonce, ciphertext) = encapsulated_key.split_at(ECIES_NONCE_LEN);
            if let Ok(symmetric_key) = cipher.decrypt(Nonce::from_slice(nonce), ciphertext) {
                return Ok(zeroizing_vec(symmetric_key));
            }
        }

        if options.allow_legacy_nonce {
            match cipher.decrypt(Nonce::from_slice(ECIES_LEGACY_NONCE), encapsulated_key) {
                Ok(symmetric_key) => {
                    return Ok(zeroizing_vec(symmetric_key));
                }
                Err(e) => last_err = Some(e.to_string()),
            }
        } else {
            last_err = Some("ECIES decapsulation failed".into());
        }
    }

    Err(IronCryptError::DecryptionError(
        last_err.unwrap_or_else(|| "ECIES decapsulation failed".into()),
    ))
}

/// Signs a hash using ECDSA with a P-256 key.
pub fn sign_hash_ecc(secret_key: &SecretKey, hash: &[u8]) -> Result<Vec<u8>, IronCryptError> {
    let signing_key = SigningKey::from(secret_key);
    let signature: Signature = signing_key.sign(hash);
    Ok(signature.to_vec())
}

/// Verifies an ECDSA signature of a hash.
pub fn verify_signature_ecc(
    public_key: &PublicKey,
    hash: &[u8],
    signature_bytes: &[u8],
) -> Result<(), IronCryptError> {
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| IronCryptError::SignatureError(e.to_string()))?;
    let verifying_key = VerifyingKey::from(public_key);
    verifying_key
        .verify(hash, &signature)
        .map_err(|e| IronCryptError::SignatureVerificationFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn ecies_uses_random_nonce_roundtrip() {
        let (sk, pk) = generate_ecc_keys().unwrap();
        let msg = b"0123456789abcdef0123456789abcdef";
        let kek = ecies_key_encap(&pk, msg).unwrap();
        assert!(
            kek.encapsulated_key.len() > 12,
            "encapsulated key must include nonce prefix"
        );
        let kek2 = ecies_key_encap(&pk, msg).unwrap();
        assert_ne!(&kek.encapsulated_key[..12], &kek2.encapsulated_key[..12]);

        let recovered = ecies_key_decap(&sk, &kek.ephemeral_pk, &kek.encapsulated_key).unwrap();
        assert_eq!(recovered.as_slice(), msg);
    }

    #[test]
    fn ecies_rejects_legacy_when_disallowed() {
        let (sk, pk) = generate_ecc_keys().unwrap();
        let ephemeral_sk = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let ephemeral_pk = ephemeral_sk.public_key();
        let shared = ephemeral_sk.diffie_hellman(&pk);
        let hkdf = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes().as_ref());
        let mut kek = [0u8; 32];
        hkdf.expand(b"ironcrypt-ecies-kek", &mut kek).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
        kek.zeroize();
        let msg = b"0123456789abcdef0123456789abcdef";
        let legacy_ct = cipher
            .encrypt(Nonce::from_slice(ECIES_LEGACY_NONCE), msg.as_slice())
            .unwrap();

        assert!(ecies_key_decap_with_options(
            &sk,
            &ephemeral_pk,
            &legacy_ct,
            EciesDecapOptions {
                allow_legacy_nonce: false,
            },
        )
        .is_err());

        let ok = ecies_key_decap_with_options(
            &sk,
            &ephemeral_pk,
            &legacy_ct,
            EciesDecapOptions {
                allow_legacy_nonce: true,
            },
        )
        .unwrap();
        assert_eq!(ok.as_slice(), msg);
    }
}
