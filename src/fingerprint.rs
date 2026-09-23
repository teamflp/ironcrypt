//! Secret-keyed integrity fingerprints (HMAC) for Payment records.
//!
//! Distinct from [`crate::webhook::WebhookSigner`] (HTTP callbacks) and from
//! encryption / login hashing. Use this to bind a stable `key_id` to a digest
//! of application bytes without making the payload recoverable.
//!
//! Canonical string: `{key_id}.{version}.{hex(payload)}` is **not** used —
//! the MAC is over raw `payload` with domain separation in the key schedule
//! info (see [`FingerprintSigner::mac`]).

use crate::IronCryptError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// Fingerprint scheme version embedded in the output label.
pub const FINGERPRINT_VERSION: u32 = 1;

/// Domain separation for HMAC key usage.
const FP_INFO: &[u8] = b"ironcrypt-fingerprint-v1|alg=hmac-sha256";

/// Result of [`FingerprintSigner::fingerprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub key_id: String,
    pub version: u32,
    /// Lower-hex HMAC-SHA256.
    pub mac_hex: String,
}

impl Fingerprint {
    /// Compact wire form: `v1:<key_id>:<mac_hex>`.
    pub fn to_wire(&self) -> String {
        format!("v{}:{}:{}", self.version, self.key_id, self.mac_hex)
    }

    /// Parse [`Self::to_wire`].
    pub fn parse_wire(s: &str) -> Result<Self, IronCryptError> {
        let mut parts = s.splitn(3, ':');
        let ver = parts.next().ok_or_else(|| bad_fp("missing version"))?;
        let key_id = parts.next().ok_or_else(|| bad_fp("missing key_id"))?;
        let mac_hex = parts.next().ok_or_else(|| bad_fp("missing mac"))?;
        let version: u32 = ver
            .strip_prefix('v')
            .ok_or_else(|| bad_fp("version must start with v"))?
            .parse()
            .map_err(|_| bad_fp("invalid version number"))?;
        if key_id.is_empty() || mac_hex.is_empty() {
            return Err(bad_fp("empty key_id or mac"));
        }
        Ok(Self {
            key_id: key_id.to_string(),
            version,
            mac_hex: mac_hex.to_string(),
        })
    }
}

fn bad_fp(msg: &str) -> IronCryptError {
    IronCryptError::SignatureVerificationFailed(format!("fingerprint: {msg}"))
}

/// HMAC-SHA256 fingerprinter keyed by an opaque secret.
#[derive(Clone)]
pub struct FingerprintSigner {
    key_id: String,
    secret: Zeroizing<Vec<u8>>,
    version: u32,
}

impl Drop for FingerprintSigner {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl FingerprintSigner {
    pub fn new(key_id: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id: key_id.into(),
            secret: Zeroizing::new(secret.into()),
            version: FINGERPRINT_VERSION,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn fingerprint(&self, payload: &[u8]) -> Result<Fingerprint, IronCryptError> {
        let mac_hex = self.mac_hex(payload)?;
        Ok(Fingerprint {
            key_id: self.key_id.clone(),
            version: self.version,
            mac_hex,
        })
    }

    pub fn verify(&self, payload: &[u8], fp: &Fingerprint) -> Result<(), IronCryptError> {
        if fp.key_id != self.key_id || fp.version != self.version {
            return Err(bad_fp("key_id or version mismatch"));
        }
        let expected = self.mac_hex(payload)?;
        if !bool::from(expected.as_bytes().ct_eq(fp.mac_hex.as_bytes())) {
            return Err(bad_fp("mac mismatch"));
        }
        Ok(())
    }

    pub fn verify_wire(&self, payload: &[u8], wire: &str) -> Result<(), IronCryptError> {
        let fp = Fingerprint::parse_wire(wire)?;
        self.verify(payload, &fp)
    }

    fn mac_hex(&self, payload: &[u8]) -> Result<String, IronCryptError> {
        let mut mac = HmacSha256::new_from_slice(self.secret.as_slice()).map_err(|_| {
            IronCryptError::KeyDerivationError("invalid fingerprint HMAC key".into())
        })?;
        mac.update(FP_INFO);
        mac.update(b"|");
        mac.update(self.key_id.as_bytes());
        mac.update(b"|");
        mac.update(self.version.to_string().as_bytes());
        mac.update(b"|");
        mac.update(payload);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_roundtrip() {
        let signer = FingerprintSigner::new("fpk_live_1", b"fingerprint-secret-key!!");
        let payload = br#"{"order_id":"ord_1","amount":100}"#;
        let fp = signer.fingerprint(payload).unwrap();
        signer.verify(payload, &fp).unwrap();
        let wire = fp.to_wire();
        signer.verify_wire(payload, &wire).unwrap();
        assert!(signer.verify(b"tampered", &fp).is_err());
    }

    #[test]
    fn different_key_id_changes_mac() {
        let a = FingerprintSigner::new("a", b"same-secret-material!!!!!");
        let b = FingerprintSigner::new("b", b"same-secret-material!!!!!");
        let p = b"payload";
        assert_ne!(
            a.fingerprint(p).unwrap().mac_hex,
            b.fingerprint(p).unwrap().mac_hex
        );
    }
}
