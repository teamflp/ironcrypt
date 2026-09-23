//! In-process key provider for development and migration.
//!
//! Private keys remain in memory for this backend. It must **not** be used as the
//! sole production Payment crypto backend — prefer a KMS/HSM `CryptoProvider`.

use async_trait::async_trait;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::{
    crypto_provider::{CryptoProvider, WrappedKey},
    keys::{PrivateKey, PublicKey},
    ecc_utils, IronCryptError,
};
#[cfg(feature = "rsa-algo")]
use rsa::Oaep;
#[cfg(feature = "rsa-algo")]
use sha2::Sha256;

const LOCAL_AAD_PREFIX: &[u8] = b"ironcrypt-local-v1";

/// Local (in-process) implementation of [`CryptoProvider`].
///
/// Uses the loaded asymmetric key pair to wrap DEKs (RSA-OAEP or ECIES) and
/// AES-256-GCM for direct encrypt/decrypt of small payloads.
pub struct LocalKeyProvider {
    key_id: String,
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl LocalKeyProvider {
    /// Creates a local provider bound to a single key version / id.
    pub fn new(
        key_id: impl Into<String>,
        public_key: PublicKey,
        private_key: PrivateKey,
    ) -> Result<Self, IronCryptError> {
        match (&public_key, &private_key) {
            #[cfg(feature = "rsa-algo")]
            (PublicKey::Rsa(_), PrivateKey::Rsa(_)) | (PublicKey::Ecc(_), PrivateKey::Ecc(_)) => {
                Ok(Self {
                    key_id: key_id.into(),
                    public_key,
                    private_key,
                })
            }
            #[cfg(not(feature = "rsa-algo"))]
            (PublicKey::Ecc(_), PrivateKey::Ecc(_)) => Ok(Self {
                key_id: key_id.into(),
                public_key,
                private_key,
            }),
            #[cfg(feature = "rsa-algo")]
            _ => Err(IronCryptError::ConfigurationError(
                "LocalKeyProvider public/private key types must match".into(),
            )),
        }
    }

    fn ensure_key_id(&self, key_id: &str) -> Result<(), IronCryptError> {
        if key_id != self.key_id {
            return Err(IronCryptError::ConfigurationError(format!(
                "LocalKeyProvider key_id mismatch: expected '{}', got '{}'",
                self.key_id, key_id
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl CryptoProvider for LocalKeyProvider {
    fn name(&self) -> &'static str {
        "local"
    }

    fn private_material_exportable(&self) -> bool {
        true
    }

    async fn wrap_key(
        &self,
        key_id: &str,
        plaintext_key: &[u8],
    ) -> Result<WrappedKey, IronCryptError> {
        self.ensure_key_id(key_id)?;
        let ciphertext = match &self.public_key {
            #[cfg(feature = "rsa-algo")]
            PublicKey::Rsa(pk) => {
                let padding = Oaep::new::<Sha256>();
                pk.encrypt(&mut OsRng, padding, plaintext_key)
                    .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?
            }
            PublicKey::Ecc(pk) => {
                let encap = ecc_utils::ecies_key_encap(pk, plaintext_key)?;
                // Encode: ephemeral_pk_der_len(u16 BE) || ephemeral_pk_der || encapsulated
                let eph_der = {
                    use p256::pkcs8::EncodePublicKey;
                    encap
                        .ephemeral_pk
                        .to_public_key_der()
                        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?
                        .as_bytes()
                        .to_vec()
                };
                if eph_der.len() > u16::MAX as usize {
                    return Err(IronCryptError::EncryptionError(
                        "ephemeral public key too large".into(),
                    ));
                }
                let mut out = Vec::with_capacity(2 + eph_der.len() + encap.encapsulated_key.len());
                out.extend_from_slice(&(eph_der.len() as u16).to_be_bytes());
                out.extend_from_slice(&eph_der);
                out.extend_from_slice(&encap.encapsulated_key);
                out
            }
        };
        Ok(WrappedKey {
            key_id: self.key_id.clone(),
            ciphertext,
        })
    }

    async fn unwrap_key(
        &self,
        key_id: &str,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        self.ensure_key_id(key_id)?;
        match &self.private_key {
            #[cfg(feature = "rsa-algo")]
            PrivateKey::Rsa(sk) => {
                let padding = Oaep::new::<Sha256>();
                sk.decrypt(padding, wrapped)
                    .map_err(|e| IronCryptError::DecryptionError(e.to_string()))
            }
            PrivateKey::Ecc(sk) => {
                if wrapped.len() < 2 {
                    return Err(IronCryptError::DecryptionError(
                        "wrapped ECC key too short".into(),
                    ));
                }
                let eph_len = u16::from_be_bytes([wrapped[0], wrapped[1]]) as usize;
                if wrapped.len() < 2 + eph_len {
                    return Err(IronCryptError::DecryptionError(
                        "wrapped ECC key truncated".into(),
                    ));
                }
                let eph_der = &wrapped[2..2 + eph_len];
                let encapsulated = &wrapped[2 + eph_len..];
                let ephemeral_pk = {
                    use p256::pkcs8::DecodePublicKey;
                    p256::PublicKey::from_public_key_der(eph_der)
                        .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?
                };
                ecc_utils::ecies_key_decap(sk, &ephemeral_pk, encapsulated)
                    .map(|z| z.to_vec())
            }
        }
    }

    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        // Direct encrypt: wrap a random AES key, then AES-GCM the payload.
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);
        let wrapped = self.wrap_key(key_id, &dek).await?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let mut full_aad = LOCAL_AAD_PREFIX.to_vec();
        if let Some(extra) = aad {
            full_aad.extend_from_slice(extra);
        }

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: &full_aad,
                },
            )
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;

        dek.zeroize();

        // Format: wrap_len(u32 BE) || wrapped || nonce(12) || ciphertext
        let wrap_len = wrapped.ciphertext.len() as u32;
        let mut out =
            Vec::with_capacity(4 + wrapped.ciphertext.len() + 12 + ciphertext.len());
        out.extend_from_slice(&wrap_len.to_be_bytes());
        out.extend_from_slice(&wrapped.ciphertext);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        if ciphertext.len() < 4 + 12 {
            return Err(IronCryptError::DecryptionError(
                "local provider ciphertext too short".into(),
            ));
        }
        let wrap_len = u32::from_be_bytes(ciphertext[0..4].try_into().unwrap()) as usize;
        if ciphertext.len() < 4 + wrap_len + 12 {
            return Err(IronCryptError::DecryptionError(
                "local provider ciphertext truncated".into(),
            ));
        }
        let wrapped = &ciphertext[4..4 + wrap_len];
        let nonce = &ciphertext[4 + wrap_len..4 + wrap_len + 12];
        let body = &ciphertext[4 + wrap_len + 12..];

        let mut dek = self.unwrap_key(key_id, wrapped).await?;
        if dek.len() != 32 {
            dek.zeroize();
            return Err(IronCryptError::DecryptionError(
                "unexpected unwrapped DEK length".into(),
            ));
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
        let mut full_aad = LOCAL_AAD_PREFIX.to_vec();
        if let Some(extra) = aad {
            full_aad.extend_from_slice(extra);
        }

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                aes_gcm::aead::Payload {
                    msg: body,
                    aad: &full_aad,
                },
            )
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()));

        dek.zeroize();
        plaintext
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc_utils::generate_ecc_keys;

    #[tokio::test]
    async fn local_ecc_wrap_roundtrip() {
        let (sk, pk) = generate_ecc_keys().unwrap();
        let provider = LocalKeyProvider::new(
            "v1",
            PublicKey::Ecc(pk),
            PrivateKey::Ecc(sk),
        )
        .unwrap();
        let dek = b"0123456789abcdef0123456789abcdef";
        let wrapped = provider.wrap_key("v1", dek).await.unwrap();
        let recovered = provider.unwrap_key("v1", &wrapped.ciphertext).await.unwrap();
        assert_eq!(recovered, dek);
    }

    #[tokio::test]
    async fn local_encrypt_binds_aad() {
        let (sk, pk) = generate_ecc_keys().unwrap();
        let provider = LocalKeyProvider::new(
            "v1",
            PublicKey::Ecc(pk),
            PrivateKey::Ecc(sk),
        )
        .unwrap();
        let ct = provider
            .encrypt("v1", b"secret-payment-data", Some(b"tenant:42"))
            .await
            .unwrap();
        let pt = provider
            .decrypt("v1", &ct, Some(b"tenant:42"))
            .await
            .unwrap();
        assert_eq!(pt, b"secret-payment-data");
        assert!(provider
            .decrypt("v1", &ct, Some(b"tenant:99"))
            .await
            .is_err());
    }
}
