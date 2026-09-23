//! Envelope format versioning policy (stream headers + JSON).
//!
//! | Version | Status (default) | Status (`payment`) | Notes |
//! |---------|------------------|--------------------|-------|
//! | Stream V4 | Current (r/w) | Current (r/w) | Encrypted metadata + optional context |
//! | Stream V3 | Supported (r) | Supported (r) | Prefer migrate to V4 |
//! | Stream V2 | Migratable (r) | Rejected | Use `ironcrypt migrate` |
//! | Stream V1 | Migratable (r) | Rejected | Use `ironcrypt migrate` |
//! | JSON `format_version` 1 | Current | Current | Requires context under Payment |

use crate::{
    encrypt::StreamHeader,
    payment::PaymentSecurityProfile,
    IronCryptError,
};

/// Current stream envelope written by new encrypt paths.
pub const CURRENT_STREAM_VERSION: u8 = 4;

/// Minimum stream version accepted for decrypt under Payment.
pub const PAYMENT_MIN_STREAM_VERSION: u8 = 3;

/// Current JSON [`crate::encrypt::EncryptedData`] format version.
pub const CURRENT_JSON_FORMAT_VERSION: u32 = 1;

/// How an envelope version may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeStatus {
    /// Preferred format for new ciphertext (read + write).
    Current,
    /// Decrypt allowed; writers should prefer Current.
    Supported,
    /// Decrypt only via explicit migration tooling (non-Payment).
    Migratable,
    /// Must not be accepted.
    Rejected,
}

/// Classify a parsed stream header under the active security profile.
pub fn stream_header_status(header: &StreamHeader) -> EnvelopeStatus {
    let ver = match header {
        StreamHeader::V4(_) => 4,
        StreamHeader::V3(_) => 3,
        StreamHeader::V2(_) => 2,
        StreamHeader::V1(_) => 1,
    };
    stream_version_status(ver)
}

/// Policy for a numeric stream header version.
pub fn stream_version_status(version: u8) -> EnvelopeStatus {
    match version {
        4 => EnvelopeStatus::Current,
        3 => EnvelopeStatus::Supported,
        1 | 2 => {
            if PaymentSecurityProfile::is_enabled() {
                EnvelopeStatus::Rejected
            } else {
                EnvelopeStatus::Migratable
            }
        }
        _ => EnvelopeStatus::Rejected,
    }
}

/// Reject envelopes that must not be decrypted in this build/profile.
pub fn ensure_stream_header_allowed(header: &StreamHeader) -> Result<(), IronCryptError> {
    match stream_header_status(header) {
        EnvelopeStatus::Current | EnvelopeStatus::Supported | EnvelopeStatus::Migratable => Ok(()),
        EnvelopeStatus::Rejected => Err(IronCryptError::DecryptionError(format!(
            "stream envelope version is rejected by policy \
             (Payment requires V{PAYMENT_MIN_STREAM_VERSION}+; \
             migrate legacy V1/V2 with `ironcrypt migrate` outside Payment builds)"
        ))),
    }
}

/// Validate JSON envelope `format_version` (missing → treat as 1 for compat).
pub fn ensure_json_format_allowed(format_version: Option<u32>) -> Result<(), IronCryptError> {
    let v = format_version.unwrap_or(1);
    if v == 0 || v > CURRENT_JSON_FORMAT_VERSION {
        return Err(IronCryptError::DecryptionError(format!(
            "unsupported EncryptedData format_version {v} \
             (supported: 1..={CURRENT_JSON_FORMAT_VERSION})"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::{EncryptedStreamHeaderV3, EncryptedStreamHeaderV4, StreamHeader};
    use crate::algorithms::SymmetricAlgorithm;

    #[test]
    fn v4_is_current() {
        let h = StreamHeader::V4(EncryptedStreamHeaderV4 {
            symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            recipients: vec![],
            encrypted_metadata: String::new(),
            metadata_nonce: String::new(),
            context: None,
        });
        assert_eq!(stream_header_status(&h), EnvelopeStatus::Current);
    }

    #[test]
    fn v3_is_supported() {
        let h = StreamHeader::V3(EncryptedStreamHeaderV3 {
            symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            recipients: vec![],
            nonce: String::new(),
            password_hash: None,
        });
        assert_eq!(stream_header_status(&h), EnvelopeStatus::Supported);
    }
}
