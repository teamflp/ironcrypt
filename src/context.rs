//! Application encryption context bound as AEAD AAD (multi-tenant isolation).

use crate::{payment::PaymentSecurityProfile, IronCryptError};
use serde::{Deserialize, Serialize};

/// Stable application context authenticated with ciphertext / metadata.
///
/// Encoded as domain-separated bytes for AES-GCM AAD:
/// `ironcrypt-ctx-v1|tenant=<…>|purpose=<…>|record=<…>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionContext {
    pub tenant_id: String,
    pub purpose: String,
    pub record_id: String,
}

impl EncryptionContext {
    pub fn new(
        tenant_id: impl Into<String>,
        purpose: impl Into<String>,
        record_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            purpose: purpose.into(),
            record_id: record_id.into(),
        }
    }

    /// Reject empty identifiers (required under Payment, recommended always).
    pub fn validate(&self) -> Result<(), IronCryptError> {
        for (name, value) in [
            ("tenant_id", self.tenant_id.as_str()),
            ("purpose", self.purpose.as_str()),
            ("record_id", self.record_id.as_str()),
        ] {
            if value.is_empty() || value.len() > 256 {
                return Err(IronCryptError::ConfigurationError(format!(
                    "EncryptionContext.{name} must be 1..=256 bytes"
                )));
            }
            if value.contains('|') || value.contains('=') {
                return Err(IronCryptError::ConfigurationError(format!(
                    "EncryptionContext.{name} must not contain '|' or '='"
                )));
            }
        }
        Ok(())
    }

    /// Canonical AAD bytes used by AES-GCM metadata / payload binding.
    pub fn to_aad_bytes(&self) -> Vec<u8> {
        format!(
            "ironcrypt-ctx-v1|tenant={}|purpose={}|record={}",
            self.tenant_id, self.purpose, self.record_id
        )
        .into_bytes()
    }

    /// Validate and, under Payment, require a context to be present.
    pub fn require_for_payment(ctx: Option<&Self>) -> Result<(), IronCryptError> {
        if PaymentSecurityProfile::require_encryption_context() {
            let ctx = ctx.ok_or_else(|| {
                IronCryptError::ConfigurationError(
                    "Payment profile requires EncryptionContext (tenant_id, purpose, record_id)"
                        .into(),
                )
            })?;
            ctx.validate()?;
        } else if let Some(ctx) = ctx {
            ctx.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_is_stable() {
        let c = EncryptionContext::new("t1", "card", "r9");
        assert_eq!(
            String::from_utf8(c.to_aad_bytes()).unwrap(),
            "ironcrypt-ctx-v1|tenant=t1|purpose=card|record=r9"
        );
    }

    #[test]
    fn rejects_empty_or_separators() {
        assert!(EncryptionContext::new("", "p", "r").validate().is_err());
        assert!(EncryptionContext::new("t|x", "p", "r").validate().is_err());
    }
}
