use serde::{Deserialize, Serialize};
use std::fmt;

/// Defines the supported symmetric encryption algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM, a widely used and secure symmetric cipher.
    Aes256Gcm,
    /// ChaCha20-Poly1305, a modern and fast symmetric cipher.
    ChaCha20Poly1305,
}

impl Default for SymmetricAlgorithm {
    fn default() -> Self {
        SymmetricAlgorithm::Aes256Gcm
    }
}

impl fmt::Display for SymmetricAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Defines the supported asymmetric encryption algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AsymmetricAlgorithm {
    /// RSA, a widely used public-key cryptosystem.
    Rsa,
    /// Elliptic Curve Cryptography (ECC), a modern alternative to RSA.
    Ecc,
}

impl Default for AsymmetricAlgorithm {
    fn default() -> Self {
        AsymmetricAlgorithm::Rsa
    }
}
