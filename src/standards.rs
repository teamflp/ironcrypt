use serde::{Deserialize, Serialize};

/// Defines the cryptographic standards available for configuration.
///
/// Each standard corresponds to a set of predefined cryptographic parameters
/// that align with common regulatory and security requirements.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CryptoStandard {
    /// Allows for manual configuration of all cryptographic parameters.
    Custom,
    /// A standard based on current NIST (National Institute of Standards and Technology)
    /// recommendations, providing a strong and modern security posture.
    Nist,
    /// A standard designed to be compliant with FIPS (Federal Information Processing Standard)
    /// 140-2, often required for U.S. government and other regulated industries.
    Fips140_2,
    /// A standard based on the recommendations of the French National Agency for
    /// the Security of Information Systems (ANSSI).
    Anssi,
}

use crate::algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm};

impl Default for CryptoStandard {
    /// The default standard is `Nist`, which offers a strong and modern security baseline.
    fn default() -> Self {
        CryptoStandard::Nist
    }
}

/// A struct to hold the cryptographic parameters for a given standard.
pub struct StandardConfig {
    pub symmetric_algorithm: SymmetricAlgorithm,
    pub asymmetric_algorithm: AsymmetricAlgorithm,
    pub rsa_key_size: u32,
}

impl CryptoStandard {
    /// Returns the cryptographic parameters associated with the standard.
    ///
    /// Returns `None` for the `Custom` standard, as its parameters are user-defined.
    pub fn get_params(&self) -> Option<StandardConfig> {
        match self {
            CryptoStandard::Nist => Some(StandardConfig {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                asymmetric_algorithm: AsymmetricAlgorithm::Rsa,
                rsa_key_size: 3072, // NIST recommends a minimum of 2048, 3072 is stronger
            }),
            CryptoStandard::Fips140_2 => Some(StandardConfig {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                asymmetric_algorithm: AsymmetricAlgorithm::Rsa,
                rsa_key_size: 3072, // FIPS requires a minimum of 2048 for new keys, 3072 is a safe choice
            }),
            CryptoStandard::Anssi => Some(StandardConfig {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                asymmetric_algorithm: AsymmetricAlgorithm::Rsa,
                rsa_key_size: 3072, // ANSSI recommends a minimum of 3072 for RSA keys
            }),
            CryptoStandard::Custom => None,
        }
    }
}
