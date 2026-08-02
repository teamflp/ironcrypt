use p256::{PublicKey as EccPublicKey, SecretKey as EccSecretKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// An enum to hold different types of public keys.
pub enum PublicKey {
    Rsa(RsaPublicKey),
    Ecc(EccPublicKey),
}

/// An enum to hold different types of private keys.
///
/// RSA private keys are large; boxing them would churn the call sites for little gain.
#[allow(clippy::large_enum_variant)]
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ecc(EccSecretKey),
}
