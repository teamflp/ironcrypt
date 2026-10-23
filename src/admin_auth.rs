//! Bearer check for the admin `/tls` status route.
//!
//! Comparison is on SHA-256 digests so the check does not leak the token
//! length through an early exit.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// `true` when `presented` is the configured admin token.
pub fn bearer_token_matches(presented: &str, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let a = Sha256::digest(presented.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_wrong_or_empty_token() {
        assert!(bearer_token_matches("correct-token", "correct-token"));
        assert!(!bearer_token_matches("correct-token", "other-token"));
        assert!(!bearer_token_matches("", "correct-token"));
        assert!(!bearer_token_matches("correct-token", ""));
    }
}
