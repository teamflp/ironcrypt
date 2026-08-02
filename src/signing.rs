use crate::{ecc_utils, rsa_utils, IronCryptError, PrivateKey, PublicKey};

/// Signs a pre-computed hash using the appropriate algorithm based on the key type.
///
/// # Arguments
///
/// * `private_key` - The private key (either RSA or ECC) to use for signing.
/// * `hash` - The raw byte slice of the hash to be signed.
///
/// # Returns
///
/// A `Result` containing the raw signature bytes or an `IronCryptError`.
pub fn sign_hash_with_any_key(
    private_key: &PrivateKey,
    hash: &[u8],
) -> Result<Vec<u8>, IronCryptError> {
    match private_key {
        PrivateKey::Rsa(rsa_private_key) => rsa_utils::sign_hash(rsa_private_key, hash),
        PrivateKey::Ecc(ecc_secret_key) => ecc_utils::sign_hash_ecc(ecc_secret_key, hash),
    }
}

/// Verifies a signature against a pre-computed hash using the appropriate algorithm.
///
/// # Arguments
///
/// * `public_key` - The public key (RSA or ECC) to use for verification.
/// * `hash` - The raw byte slice of the hash that was signed.
/// * `signature` - The raw signature bytes to verify.
///
/// # Returns
///
/// A `Result` which is `Ok(())` on successful verification or an `IronCryptError` on failure.
pub fn verify_signature_with_any_key(
    public_key: &PublicKey,
    hash: &[u8],
    signature: &[u8],
) -> Result<(), IronCryptError> {
    match public_key {
        PublicKey::Rsa(rsa_public_key) => {
            rsa_utils::verify_signature(rsa_public_key, hash, signature)
        }
        PublicKey::Ecc(ecc_public_key) => {
            ecc_utils::verify_signature_ecc(ecc_public_key, hash, signature)
        }
    }
}
