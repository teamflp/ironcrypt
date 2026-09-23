use serde::{Deserialize, Serialize};
use std::fmt;

/// Defines the supported symmetric encryption algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM, a widely used and secure symmetric cipher.
    #[default]
    Aes256Gcm,
    /// ChaCha20-Poly1305, a modern and fast symmetric cipher.
    ChaCha20Poly1305,
}

impl fmt::Display for SymmetricAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Defines the supported asymmetric encryption algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AsymmetricAlgorithm {
    /// RSA, a widely used public-key cryptosystem.
    #[default]
    Rsa,
    /// Elliptic Curve Cryptography (ECC), a modern alternative to RSA.
    Ecc,
}
