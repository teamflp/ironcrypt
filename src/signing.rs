use crate::{ecc_utils, IronCryptError, PrivateKey, PublicKey};
#[cfg(feature = "rsa-algo")]
use crate::rsa_utils;

/// Signs a pre-computed hash using the appropriate algorithm based on the key type.
pub fn sign_hash_with_any_key(
    private_key: &PrivateKey,
    hash: &[u8],
) -> Result<Vec<u8>, IronCryptError> {
    match private_key {
        #[cfg(feature = "rsa-algo")]
        PrivateKey::Rsa(rsa_private_key) => rsa_utils::sign_hash(rsa_private_key, hash),
        PrivateKey::Ecc(ecc_secret_key) => ecc_utils::sign_hash_ecc(ecc_secret_key, hash),
    }
}

/// Verifies a signature against a pre-computed hash using the appropriate algorithm.
pub fn verify_signature_with_any_key(
    public_key: &PublicKey,
    hash: &[u8],
    signature: &[u8],
) -> Result<(), IronCryptError> {
    match public_key {
        #[cfg(feature = "rsa-algo")]
        PublicKey::Rsa(rsa_public_key) => {
            rsa_utils::verify_signature(rsa_public_key, hash, signature)
        }
        PublicKey::Ecc(ecc_public_key) => {
            ecc_utils::verify_signature_ecc(ecc_public_key, hash, signature)
        }
    }
}
