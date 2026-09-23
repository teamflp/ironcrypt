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
}
