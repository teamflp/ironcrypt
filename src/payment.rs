//! Locked security profile for payment / financial workloads.
//!
//! Enabling the `payment` Cargo feature wires stricter defaults. Call
//! [`PaymentSecurityProfile::validate`] (or [`enforce`]) before constructing
//! runtime components that handle payment data.

use crate::{
    algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm},
    config::IronCryptConfig,
    limits::{MAX_ARGON2_MEMORY_KIB, MAX_ARGON2_PARALLELISM, MAX_ARGON2_TIME_COST},
    standards::CryptoStandard,
    IronCryptError,
};

/// Fixed security posture for IronCrypt when used as a payment security core.
///
/// This is a *parameter / policy profile*, not a regulatory certification.
#[derive(Debug, Clone, Copy, Default)]
pub struct PaymentSecurityProfile;

impl PaymentSecurityProfile {
    /// Whether the Payment profile is active for this build.
    pub fn is_enabled() -> bool {
        cfg!(feature = "payment")
    }

    /// Apply locked Payment defaults onto `config` (algorithms, Argon2 floors).
    pub fn apply(config: &mut IronCryptConfig) {
        config.standard = CryptoStandard::PaymentCompatible;
        config.symmetric_algorithm = SymmetricAlgorithm::Aes256Gcm;
        config.asymmetric_algorithm = AsymmetricAlgorithm::Ecc;
        if config.rsa_key_size < 3072 {
            config.rsa_key_size = 3072;
        }
        if config.argon2_memory_cost < 65_536 {
            config.argon2_memory_cost = 65_536;
        }
        if config.argon2_time_cost < 3 {
            config.argon2_time_cost = 3;
        }
        if config.argon2_parallelism < 1 {
            config.argon2_parallelism = 1;
        }
    }

    /// Validate that `config` is acceptable for Payment production use.
    pub fn validate(config: &IronCryptConfig) -> Result<(), IronCryptError> {
        match config.standard {
            CryptoStandard::Custom => {
                return Err(IronCryptError::ConfigurationError(
                    "Payment profile forbids CryptoStandard::Custom; use PaymentCompatible \
                     (or an allowlisted preset)."
                        .into(),
                ));
            }
            CryptoStandard::PaymentCompatible
            | CryptoStandard::Nist
            | CryptoStandard::FipsCompatibleProfile
            | CryptoStandard::AnssiCompatibleProfile => {}
        }

        if config.symmetric_algorithm != SymmetricAlgorithm::Aes256Gcm {
            return Err(IronCryptError::ConfigurationError(format!(
                "Payment profile requires Aes256Gcm, got {:?}",
                config.symmetric_algorithm
            )));
        }

        if config.asymmetric_algorithm != AsymmetricAlgorithm::Ecc {
            return Err(IronCryptError::ConfigurationError(
                "Payment profile requires ECC (P-256) key encapsulation; RSA private-key \
                 paths are not permitted in the locked Payment profile \
                 (see RUSTSEC-2023-0071 / Marvin Attack)."
                    .into(),
            ));
        }

        crate::crypto_allowlist::ensure_suite_allowed(
            config.symmetric_algorithm,
            config.asymmetric_algorithm,
            true,
        )?;

        if config.argon2_memory_cost > MAX_ARGON2_MEMORY_KIB
            || config.argon2_time_cost > MAX_ARGON2_TIME_COST
            || config.argon2_parallelism > MAX_ARGON2_PARALLELISM
        {
            return Err(IronCryptError::ConfigurationError(
                "Argon2 parameters exceed Payment safety caps (DoS protection)".into(),
            ));
        }

        if let Some(secrets) = &config.secrets {
            if secrets.provider.eq_ignore_ascii_case("hsm") {
                return Err(IronCryptError::ConfigurationError(
                    "Payment profile forbids the legacy PKCS#11 `hsm` SecretStore backend. \
                     Use a CryptoProvider HSM/KMS implementation that never exports private keys."
                        .into(),
                ));
            }
        }

        if let Some(cp) = &config.crypto_provider {
            crate::crypto_provider::validate_provider_config(cp, true)?;
        }

        if let Some(audit) = &config.audit {
            audit.ensure_payment_safe()?;
        }

        Ok(())
    }

    /// Apply locked defaults then validate — convenience for daemon/CLI startup.
    pub fn enforce(config: &mut IronCryptConfig) -> Result<(), IronCryptError> {
        Self::apply(config);
        Self::validate(config)
    }

    /// Whether ECIES legacy fixed-nonce decrypt is allowed.
    pub fn allow_ecies_legacy_nonce() -> bool {
        !Self::is_enabled()
    }

    /// Whether plaintext secret-export HTTP endpoints may be mounted.
    pub fn allow_plaintext_secret_http() -> bool {
        !Self::is_enabled()
    }

    /// Whether clients may send `X-Password` (recoverable password gate on streams).
    ///
    /// Under Payment this is always `false` — use envelope encryption without an
    /// application password, or gate access at the API layer.
    pub fn allow_x_password_header() -> bool {
        !Self::is_enabled()
    }

    /// Whether plain HTTP (no TLS) may be used outside loopback.
    pub fn require_tls() -> bool {
        Self::is_enabled()
    }

    /// Whether every encrypt path must carry a non-empty [`crate::context::EncryptionContext`].
    pub fn require_encryption_context() -> bool {
        Self::is_enabled()
    }

    /// Whether login must use Argon2 hash/verify (not asymmetric encryption of the hash).
    pub fn require_hash_only_login() -> bool {
        Self::is_enabled()
    }

    /// Whether RSA key material / RSA crypto paths are permitted at runtime.
    ///
    /// Under Payment this is always `false` (Marvin Attack / RUSTSEC-2023-0071).
    pub fn allow_rsa() -> bool {
        !Self::is_enabled()
    }

    /// Reject RSA public keys when the Payment profile is active.
    pub fn ensure_ecc_public(key: &crate::keys::PublicKey) -> Result<(), IronCryptError> {
        if Self::allow_rsa() {
            return Ok(());
        }
        match key {
            crate::keys::PublicKey::Ecc(_) => Ok(()),
            #[cfg(feature = "rsa-algo")]
            crate::keys::PublicKey::Rsa(_) => Err(IronCryptError::ConfigurationError(
                "Payment profile forbids RSA public keys at runtime; use ECC (P-256).".into(),
            )),
        }
    }

    /// Reject RSA private keys when the Payment profile is active.
    pub fn ensure_ecc_private(key: &crate::keys::PrivateKey) -> Result<(), IronCryptError> {
        if Self::allow_rsa() {
            return Ok(());
        }
        match key {
            crate::keys::PrivateKey::Ecc(_) => Ok(()),
            #[cfg(feature = "rsa-algo")]
            crate::keys::PrivateKey::Rsa(_) => Err(IronCryptError::ConfigurationError(
                "Payment profile forbids RSA private keys at runtime; use ECC (P-256) \
                 or a CryptoProvider (KMS/HSM)."
                    .into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_custom_and_rsa() {
        let mut config = IronCryptConfig::default();
        config.standard = CryptoStandard::Custom;
        config.asymmetric_algorithm = AsymmetricAlgorithm::Rsa;
        assert!(PaymentSecurityProfile::validate(&config).is_err());
    }

    #[test]
    fn enforce_locks_ecc_aes() {
        let mut config = IronCryptConfig::default();
        config.standard = CryptoStandard::Custom;
        PaymentSecurityProfile::enforce(&mut config).unwrap();
        assert_eq!(config.asymmetric_algorithm, AsymmetricAlgorithm::Ecc);
        assert_eq!(config.symmetric_algorithm, SymmetricAlgorithm::Aes256Gcm);
        assert_eq!(config.standard, CryptoStandard::PaymentCompatible);
    }

    #[test]
    fn allow_rsa_tracks_feature() {
        assert_eq!(
            PaymentSecurityProfile::allow_rsa(),
            !PaymentSecurityProfile::is_enabled()
        );
    }

    #[test]
    fn rejects_local_crypto_provider_when_configured() {
        let mut config = IronCryptConfig::default();
        PaymentSecurityProfile::apply(&mut config);
        config.crypto_provider = Some(crate::config::CryptoProviderConfig {
            provider: "local".into(),
            ..Default::default()
        });
        assert!(PaymentSecurityProfile::validate(&config).is_err());
    }

    #[test]
    fn rejects_pem_audit_signing_key() {
        let mut config = IronCryptConfig::default();
        PaymentSecurityProfile::apply(&mut config);
        config.audit = Some(crate::config::AuditConfig {
            signing_key_path: Some("/tmp/audit.pem".into()),
            signing_mode: crate::config::AuditSigningMode::Pem,
            ..Default::default()
        });
        assert!(PaymentSecurityProfile::validate(&config).is_err());

        config.audit = Some(crate::config::AuditConfig {
            signing_mode: crate::config::AuditSigningMode::HmacEnv,
            ..Default::default()
        });
        assert!(PaymentSecurityProfile::validate(&config).is_ok());
    }
}
