//! HMAC message / webhook signatures for Payment integrations.
//!
//! Header format (compatible with common Stripe-style schemes):
//! ```text
//! IronCrypt-Signature: t=<unix_secs>,v1=<hex(hmac-sha256)>
//! ```
//! Canonical payload: `{t}.{key_id}.{version}.{body_bytes}`

use crate::IronCryptError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// Default signature scheme version embedded in the canonical string.
pub const WEBHOOK_SIG_VERSION: u32 = 1;

/// Maximum accepted clock skew when verifying (5 minutes).
pub const DEFAULT_MAX_SKEW_SECS: u64 = 300;

/// Signs and verifies webhook / outbound message payloads.
#[derive(Clone)]
pub struct WebhookSigner {
    key_id: String,
    secret: Zeroizing<Vec<u8>>,
    version: u32,
}

impl Drop for WebhookSigner {
    fn drop(&mut self) {
        // Zeroizing already clears on drop; keep explicit for clarity.
        self.secret.zeroize();
    }
}

impl WebhookSigner {
    pub fn new(key_id: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id: key_id.into(),
            secret: Zeroizing::new(secret.into()),
            version: WEBHOOK_SIG_VERSION,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// Build the `IronCrypt-Signature` header value for `body`.
    pub fn sign(&self, body: &[u8]) -> Result<String, IronCryptError> {
        let ts = unix_now()?;
        let mac = self.mac_hex(ts, body)?;
        Ok(format!("t={ts},v1={mac}"))
    }

    /// Verify `IronCrypt-Signature` (or equivalent) against `body`.
    pub fn verify(
        &self,
        signature_header: &str,
        body: &[u8],
        max_skew_secs: u64,
    ) -> Result<(), IronCryptError> {
        let (ts, provided) = parse_signature_header(signature_header)?;
        let now = unix_now()?;
        let skew = now.abs_diff(ts);
        if skew > max_skew_secs {
            return Err(IronCryptError::SignatureVerificationFailed(format!(
                "webhook timestamp skew {skew}s exceeds max {max_skew_secs}s"
            )));
        }
        let expected = self.mac_hex(ts, body)?;
        if !constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
            return Err(IronCryptError::SignatureVerificationFailed(
                "webhook HMAC mismatch".into(),
            ));
        }
        Ok(())
    }

    fn mac_hex(&self, ts: u64, body: &[u8]) -> Result<String, IronCryptError> {
        let mut mac = HmacSha256::new_from_slice(self.secret.as_slice()).map_err(|_| {
            IronCryptError::KeyDerivationError("invalid webhook HMAC key".into())
        })?;
        // Canonical: t.key_id.version.body
        mac.update(ts.to_string().as_bytes());
        mac.update(b".");
        mac.update(self.key_id.as_bytes());
        mac.update(b".");
        mac.update(self.version.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

fn unix_now() -> Result<u64, IronCryptError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| IronCryptError::ConfigurationError("system clock before UNIX epoch".into()))
}

fn parse_signature_header(header: &str) -> Result<(u64, String), IronCryptError> {
    let mut ts: Option<u64> = None;
    let mut v1: Option<String> = None;
    for part in header.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("t=") {
            ts = Some(rest.parse().map_err(|_| {
                IronCryptError::SignatureVerificationFailed("invalid webhook timestamp".into())
            })?);
        } else if let Some(rest) = part.strip_prefix("v1=") {
            v1 = Some(rest.to_string());
        }
    }
    match (ts, v1) {
        (Some(t), Some(sig)) if !sig.is_empty() => Ok((t, sig)),
        _ => Err(IronCryptError::SignatureVerificationFailed(
            "webhook signature header missing t= or v1=".into(),
        )),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let signer = WebhookSigner::new("whk_test", b"super-secret-webhook-key");
        let body = br#"{"event":"payment.captured","id":"pay_1"}"#;
        let header = signer.sign(body).unwrap();
        signer
            .verify(&header, body, DEFAULT_MAX_SKEW_SECS)
            .unwrap();
    }

    #[test]
    fn rejects_tampered_body() {
        let signer = WebhookSigner::new("whk_test", b"super-secret-webhook-key");
        let header = signer.sign(b"ok").unwrap();
        assert!(signer.verify(&header, b"nope", DEFAULT_MAX_SKEW_SECS).is_err());
    }

    #[test]
    fn rejects_bad_header() {
        let signer = WebhookSigner::new("whk_test", b"key");
        assert!(signer.verify("v1=abcd", b"x", 60).is_err());
    }
}
