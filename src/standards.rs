use serde::{Deserialize, Serialize};

use crate::algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm};

/// Defines the cryptographic standards available for configuration.
///
/// Each variant selects a **parameter preset**. None of these names imply that
/// the IronCrypt binary itself is a validated cryptographic module (FIPS 140 /
/// ANSSI certification). Prefer the documentation names
/// `FipsCompatibleProfile` / `AnssiCompatibleProfile` when describing posture.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum CryptoStandard {
    /// Allows for manual configuration of all cryptographic parameters.
    /// Forbidden by [`crate::payment::PaymentSecurityProfile`].
    Custom,
    /// Preset based on current NIST recommendations.
    Nist,
    /// FIPS-*compatible* parameter preset (not a FIPS module validation).
    /// Serde also accepts the historical name `Fips140_2`.
    #[serde(alias = "Fips140_2")]
    FipsCompatibleProfile,
    /// ANSSI-*compatible* parameter preset (not a certification claim).
    /// Serde also accepts the historical name `Anssi`.
    #[serde(alias = "Anssi")]
    AnssiCompatibleProfile,
    /// Locked preset for payment / financial workloads (ECC + AES-256-GCM).
    PaymentCompatible,
}

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
    /// Historical serde/TOML name `Fips140_2` maps to [`Self::FipsCompatibleProfile`].
    /// Prefer the CompatibleProfile name in new code — this is a parameter preset, not a FIPS validation.
    #[allow(non_upper_case_globals)]
    #[deprecated(
        note = "use CryptoStandard::FipsCompatibleProfile — parameter preset, not a FIPS validation"
    )]
    pub const Fips140_2: CryptoStandard = CryptoStandard::FipsCompatibleProfile;

    /// Historical name `Anssi` maps to [`Self::AnssiCompatibleProfile`].
    #[allow(non_upper_case_globals)]
    #[deprecated(note = "use CryptoStandard::AnssiCompatibleProfile")]
    pub const Anssi: CryptoStandard = CryptoStandard::AnssiCompatibleProfile;

    /// Returns the cryptographic parameters associated with the standard.
    ///
    /// Returns `None` for the `Custom` standard, as its parameters are user-defined.
    pub fn get_params(&self) -> Option<StandardConfig> {
        match self {
            CryptoStandard::Nist => Some(StandardConfig {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                asymmetric_algorithm: AsymmetricAlgorithm::Rsa,
                rsa_key_size: 3072,
            }),
            CryptoStandard::FipsCompatibleProfile => Some(StandardConfig {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                asymmetric_algorithm: AsymmetricAlgorithm::Rsa,
                rsa_key_size: 3072,
            }),
            CryptoStandard::AnssiCompatibleProfile => Some(StandardConfig {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                asymmetric_algorithm: AsymmetricAlgorithm::Ecc,
                rsa_key_size: 3072,
            }),
            CryptoStandard::PaymentCompatible => Some(StandardConfig {
                symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
                asymmetric_algorithm: AsymmetricAlgorithm::Ecc,
                rsa_key_size: 3072,
            }),
            CryptoStandard::Custom => None,
        }
    }
}
