//! Maintained allowlist of cryptographic suites IronCrypt may use.
//!
//! Payment builds only accept suites with `payment_ok`. This is a **policy
//! table**, not a certification.

use crate::{
    algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm},
    IronCryptError,
};

/// A named algorithm suite (symmetric + asymmetric pairing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoSuite {
    pub symmetric: SymmetricAlgorithm,
    pub asymmetric: AsymmetricAlgorithm,
    /// Whether this suite is allowed when the Payment profile is active.
    pub payment_ok: bool,
}

/// Canonical allowlist. Keep in sync with [`crate::standards::CryptoStandard`] presets.
pub const ALLOWED_SUITES: &[CryptoSuite] = &[
    CryptoSuite {
        symmetric: SymmetricAlgorithm::Aes256Gcm,
        asymmetric: AsymmetricAlgorithm::Ecc,
        payment_ok: true,
    },
    CryptoSuite {
        symmetric: SymmetricAlgorithm::Aes256Gcm,
        asymmetric: AsymmetricAlgorithm::Rsa,
        payment_ok: false,
    },
    CryptoSuite {
        symmetric: SymmetricAlgorithm::ChaCha20Poly1305,
        asymmetric: AsymmetricAlgorithm::Ecc,
        payment_ok: false,
    },
    CryptoSuite {
        symmetric: SymmetricAlgorithm::ChaCha20Poly1305,
        asymmetric: AsymmetricAlgorithm::Rsa,
        payment_ok: false,
    },
];

/// True if `(symmetric, asymmetric)` appears on the allowlist (any profile).
pub fn is_suite_listed(symmetric: SymmetricAlgorithm, asymmetric: AsymmetricAlgorithm) -> bool {
    ALLOWED_SUITES
        .iter()
        .any(|s| s.symmetric == symmetric && s.asymmetric == asymmetric)
}

/// Enforce allowlist. When `payment_locked` is true, only `payment_ok` suites pass.
pub fn ensure_suite_allowed(
    symmetric: SymmetricAlgorithm,
    asymmetric: AsymmetricAlgorithm,
    payment_locked: bool,
) -> Result<(), IronCryptError> {
    let entry = ALLOWED_SUITES
        .iter()
        .find(|s| s.symmetric == symmetric && s.asymmetric == asymmetric);
    match entry {
        None => Err(IronCryptError::ConfigurationError(format!(
            "crypto suite ({symmetric:?}, {asymmetric:?}) is not on the IronCrypt allowlist"
        ))),
        Some(s) if payment_locked && !s.payment_ok => Err(IronCryptError::ConfigurationError(
            format!(
                "Payment profile forbids suite ({symmetric:?}, {asymmetric:?}); \
                 use AES-256-GCM + ECC (P-256)"
            ),
        )),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_suite_is_listed() {
        assert!(is_suite_listed(
            SymmetricAlgorithm::Aes256Gcm,
            AsymmetricAlgorithm::Ecc
        ));
        ensure_suite_allowed(
            SymmetricAlgorithm::Aes256Gcm,
            AsymmetricAlgorithm::Ecc,
            true,
        )
        .unwrap();
    }

    #[test]
    fn rsa_suite_blocked_when_payment_locked() {
        assert!(ensure_suite_allowed(
            SymmetricAlgorithm::Aes256Gcm,
            AsymmetricAlgorithm::Rsa,
            true,
        )
        .is_err());
        assert!(ensure_suite_allowed(
            SymmetricAlgorithm::Aes256Gcm,
            AsymmetricAlgorithm::Rsa,
            false,
        )
        .is_ok());
    }
}
