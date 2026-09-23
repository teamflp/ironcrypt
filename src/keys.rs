use p256::{PublicKey as EccPublicKey, SecretKey as EccSecretKey};
#[cfg(feature = "rsa-algo")]
use rsa::{RsaPrivateKey, RsaPublicKey};

/// An enum to hold different types of public keys.
pub enum PublicKey {
    #[cfg(feature = "rsa-algo")]
    Rsa(RsaPublicKey),
    Ecc(EccPublicKey),
}

/// An enum to hold different types of private keys.
///
/// RSA private keys are large; boxing them would churn the call sites for little gain.
#[allow(clippy::large_enum_variant)]
pub enum PrivateKey {
    #[cfg(feature = "rsa-algo")]
    Rsa(RsaPrivateKey),
    Ecc(EccSecretKey),
}
