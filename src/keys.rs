use p256::{PublicKey as EccPublicKey, SecretKey as EccSecretKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// An enum to hold different types of public keys.
pub enum PublicKey {
    Rsa(RsaPublicKey),
    Ecc(EccPublicKey),
}

/// An enum to hold different types of private keys.
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ecc(EccSecretKey),
}

impl PublicKey {
    /// Returns the key version associated with the public key.
    /// This is a placeholder and will need to be handled more robustly.
    pub fn key_version<'a>(&self, version: &'a str) -> &'a str {
        version
    }
}
