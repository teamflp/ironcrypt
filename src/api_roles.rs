//! Explicit separation of **hashing**, **encryption**, and **tokenization** roles.
//!
//! IronCrypt is a crypto / security core — not a PCI card vault. Call sites must
//! pick the right API surface:
//!
//! | Role | Use | Do not use for |
//! |------|-----|----------------|
//! | [`hashing`] | Login credentials (Argon2id PHC) | Recoverable secrets |
//! | [`encryption`] | Recoverable secrets / records + AAD | Password verification alone |
//! | [`fingerprint`] | Secret-keyed integrity MAC | Confidentiality |
//! | Tokenization | **Out of scope** — see [`tokenization`] | — |
//!
//! See also `PROTOCOL.md` and `PAYMENT_SECURITY.md` at the crate root.

use crate::IronCryptError;

/// Login / credential hashing (non-recoverable).
///
/// Prefer [`crate::IronCrypt::hash_login_password`] /
/// [`crate::IronCrypt::verify_login_password`] under Payment.
pub mod hashing {
    pub use crate::hashing::{
        hash_password, hash_password_with_config, password_needs_rehash, verify_password,
    };
}

/// Confidentiality via hybrid encryption / CryptoProvider.
///
/// Prefer [`crate::IronCrypt::encrypt_with_context`] /
/// [`crate::IronCrypt::encrypt_secret`] with a non-empty [`crate::EncryptionContext`].
pub mod encryption {
    pub use crate::encrypt::{
        decrypt_stream, decrypt_stream_with_options, encrypt_stream, encrypt_stream_with_context,
    };
    pub use crate::context::EncryptionContext;
}

/// Secret-keyed fingerprints (HMAC), not encryption.
pub mod fingerprint {
    pub use crate::fingerprint::{Fingerprint, FingerprintSigner, FINGERPRINT_VERSION};
}

/// Tokenization / PAN vault — **intentionally not implemented**.
///
/// Use a dedicated tokenization service. IronCrypt must not receive CVV/PIN or
/// be treated as a surrogate PAN store. [`reject_cardholder_auth_data`] helps
/// fail closed when callers accidentally pass digit-only card-shaped input.
///
/// The [`TokenizationProvider`] trait exists so Payment apps can depend on a
/// clear type boundary — the only in-tree impl is [`RefusingTokenizationProvider`].
pub mod tokenization {
    use super::IronCryptError;
    use async_trait::async_trait;

    /// Human-readable policy for operators / API docs.
    pub const POLICY: &str = "IronCrypt does not provide payment tokenization. \
Use encrypt_secret only for non-CHD application secrets with EncryptionContext; \
never store CVV/PIN; never use IronCrypt as a PAN vault.";

    /// Opaque token handle returned by a real tokenizer (never a PAN).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Token(pub String);

    /// Dedicated tokenization service contract — **not** implemented by IronCrypt.
    ///
    /// Downstream Payment code should inject a vendor SDK behind this trait
    /// (or call it out-of-process). In-tree only [`RefusingTokenizationProvider`]
    /// exists so misuse fails closed.
    #[async_trait]
    pub trait TokenizationProvider: Send + Sync {
        fn name(&self) -> &'static str;

        async fn tokenize(&self, pan: &str) -> Result<Token, IronCryptError>;

        async fn detokenize(&self, token: &Token) -> Result<String, IronCryptError>;
    }

    /// Always returns [`IronCryptError::UnsupportedOperation`] — Payment default.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct RefusingTokenizationProvider;

    #[async_trait]
    impl TokenizationProvider for RefusingTokenizationProvider {
        fn name(&self) -> &'static str {
            "refusing"
        }

        async fn tokenize(&self, pan: &str) -> Result<Token, IronCryptError> {
            reject_cardholder_auth_data(pan)?;
            Err(IronCryptError::UnsupportedOperation(POLICY.into()))
        }

        async fn detokenize(&self, _token: &Token) -> Result<String, IronCryptError> {
            Err(IronCryptError::UnsupportedOperation(POLICY.into()))
        }
    }

    /// Reject strings that look like raw PAN (Luhn) or isolated CVV (3–4 digits).
    ///
    /// This is a safety rail, not a complete CHD detector.
    pub fn reject_cardholder_auth_data(value: &str) -> Result<(), IronCryptError> {
        let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 3 || digits.len() == 4 {
            if value.chars().all(|c| c.is_ascii_digit() || c.is_whitespace()) {
                return Err(IronCryptError::UnsupportedOperation(
                    "refusing CVV/PIN-shaped input; IronCrypt must not store cardholder auth data"
                        .into(),
                ));
            }
        }
        if (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
            return Err(IronCryptError::UnsupportedOperation(
                "refusing PAN-shaped input; use a dedicated tokenization service, not IronCrypt"
                    .into(),
            ));
        }
        Ok(())
    }

    fn luhn_ok(digits: &str) -> bool {
        let mut sum = 0u32;
        let mut alt = false;
        for c in digits.chars().rev() {
            let mut n = c.to_digit(10).unwrap_or(0);
            if alt {
                n *= 2;
                if n > 9 {
                    n -= 9;
                }
            }
            sum += n;
            alt = !alt;
        }
        sum % 10 == 0
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_known_test_pan() {
            assert!(reject_cardholder_auth_data("4111111111111111").is_err());
        }

        #[test]
        fn rejects_cvv_shaped() {
            assert!(reject_cardholder_auth_data("123").is_err());
            assert!(reject_cardholder_auth_data("1234").is_err());
        }

        #[test]
        fn allows_normal_secret() {
            assert!(reject_cardholder_auth_data("merchant_webhook_secret_v1").is_ok());
        }

        #[tokio::test]
        async fn refusing_provider_never_tokenizes() {
            let p = RefusingTokenizationProvider;
            assert!(p.tokenize("merchant_webhook_secret_v1").await.is_err());
            assert!(p.tokenize("4111111111111111").await.is_err());
        }
    }
}

/// Recommended `EncryptionContext.purpose` values for Payment apps.
pub mod purposes {
    pub const LOGIN_HASH: &str = "login_hash"; // documentation only — hashing has no AAD
    pub const APP_SECRET: &str = "app_secret";
    pub const RECORD: &str = "record";
    pub const FINGERPRINT: &str = "fingerprint";
}
