//! Shared helpers for binding application AAD into provider-specific contexts.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::collections::HashMap;

/// Protocol marker stored in every remote encryption context.
pub const CONTEXT_VERSION_KEY: &str = "ironcrypt-v";
pub const CONTEXT_VERSION_VALUE: &str = "1";
pub const CONTEXT_AAD_KEY: &str = "ironcrypt-aad";

/// Build an AWS KMS EncryptionContext from optional AAD bytes.
pub fn kms_encryption_context(aad: Option<&[u8]>) -> HashMap<String, String> {
    let mut ctx = HashMap::new();
    ctx.insert(
        CONTEXT_VERSION_KEY.to_string(),
        CONTEXT_VERSION_VALUE.to_string(),
    );
    if let Some(aad) = aad {
        if !aad.is_empty() {
            ctx.insert(CONTEXT_AAD_KEY.to_string(), B64.encode(aad));
        }
    }
    ctx
}

/// Base64 context string for Vault Transit derived-key / context binding.
pub fn vault_context_b64(aad: Option<&[u8]>) -> Option<String> {
    aad.filter(|a| !a.is_empty()).map(|a| B64.encode(a))
}

/// Magic prefix for DEK wraps on backends that cannot pass AAD to the KMS
/// (Azure Key Vault wrap). The context bytes sit inside the integrity-protected
/// plaintext, so a different context cannot unwrap the same blob.
const WRAP_FRAME_MAGIC: &[u8] = b"ICW1";

/// Prefix `dek` with `aad` before a wrap that has no native encryption context.
pub fn frame_dek_for_aad(dek: &[u8], aad: &[u8]) -> Result<Vec<u8>, crate::IronCryptError> {
    if aad.is_empty() || aad.len() > crate::limits::MAX_WRAP_AAD_LEN || dek.len() > 512 {
        return Err(crate::IronCryptError::EncryptionError(
            "refusing to frame a DEK with an empty, oversized, or invalid context".into(),
        ));
    }
    let mut out = Vec::with_capacity(8 + aad.len() + dek.len());
    out.extend_from_slice(WRAP_FRAME_MAGIC);
    out.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    out.extend_from_slice(aad);
    out.extend_from_slice(dek);
    Ok(out)
}

/// Recover a DEK framed by [`frame_dek_for_aad`]. Fails if `aad` does not match.
pub fn unframe_dek_for_aad(plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, crate::IronCryptError> {
    use subtle::ConstantTimeEq;
    if plain.len() < 8 || &plain[..4] != WRAP_FRAME_MAGIC {
        return Err(crate::IronCryptError::DecryptionError(
            "wrapped DEK is missing its context frame".into(),
        ));
    }
    let aad_len = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]) as usize;
    if aad_len == 0 || aad_len > crate::limits::MAX_WRAP_AAD_LEN || plain.len() < 8 + aad_len {
        return Err(crate::IronCryptError::DecryptionError(
            "wrapped DEK context frame is truncated".into(),
        ));
    }
    let got = &plain[8..8 + aad_len];
    let matches = got.len() == aad.len() && bool::from(got.ct_eq(aad));
    if !matches {
        return Err(crate::IronCryptError::DecryptionError(
            "wrapped DEK context does not match".into(),
        ));
    }
    Ok(plain[8 + aad_len..].to_vec())
}

/// `true` when `plain` is a context-framed DEK and must not be returned raw.
pub fn is_framed_dek(plain: &[u8]) -> bool {
    plain.starts_with(WRAP_FRAME_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kms_context_includes_version_and_aad() {
        let ctx = kms_encryption_context(Some(b"tenant:42"));
        assert_eq!(ctx.get(CONTEXT_VERSION_KEY).unwrap(), CONTEXT_VERSION_VALUE);
        assert_eq!(ctx.get(CONTEXT_AAD_KEY).unwrap(), &B64.encode(b"tenant:42"));
    }

    #[test]
    fn empty_aad_omits_aad_key() {
        let ctx = kms_encryption_context(None);
        assert!(!ctx.contains_key(CONTEXT_AAD_KEY));
        assert!(vault_context_b64(None).is_none());
    }

    #[test]
    fn framed_dek_rejects_a_different_context() {
        let framed = frame_dek_for_aad(b"0123456789abcdef0123456789abcdef", b"tenant-a").unwrap();
        let dek = unframe_dek_for_aad(&framed, b"tenant-a").unwrap();
        assert_eq!(dek, b"0123456789abcdef0123456789abcdef");
        assert!(unframe_dek_for_aad(&framed, b"tenant-b").is_err());
        assert!(is_framed_dek(&framed));
    }
}
