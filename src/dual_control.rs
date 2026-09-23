//! Dual control / M-of-N approvals for critical admin operations.
//!
//! This is an **in-process policy helper**, not a full workflow engine. Approvals
//! are **not cryptographically signed** — any process that can call
//! [`verify_quorum`] can also forge `Approval` values. Wire this to your
//! change-management / break-glass process (ticket IDs, HSM quorum, signed IdP
//! claims). IronCrypt records *whether* a quorum of distinct principals approved
//! an action; it does not replace IAM or physical dual-control on HSMs.
//!
//! **Not enforced by `ironcryptd` yet** — callers must invoke [`verify_quorum`]
//! before sensitive ops.

use crate::IronCryptError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Admin actions that should require dual control under Payment ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAction {
    /// Revoke or expire an API key ahead of schedule.
    RevokeApiKey,
    /// Force TLS material reload / rotate service certs.
    RotateServiceTls,
    /// Purge audit segments earlier than retention policy.
    PurgeAuditEarly,
    /// Export or re-wrap keyring metadata (not private keys).
    ExportKeyringMeta,
    /// Disable circuit breaker / raise rate limits temporarily.
    BreakGlassLimits,
}

impl AdminAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RevokeApiKey => "revoke_api_key",
            Self::RotateServiceTls => "rotate_service_tls",
            Self::PurgeAuditEarly => "purge_audit_early",
            Self::ExportKeyringMeta => "export_keyring_meta",
            Self::BreakGlassLimits => "break_glass_limits",
        }
    }
}

/// Quorum policy: at least `required` distinct principals must approve.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DualControlPolicy {
    /// Minimum distinct `principal_id` values (typically 2 for dual control).
    pub required: u32,
}

impl Default for DualControlPolicy {
    fn default() -> Self {
        Self { required: 2 }
    }
}

impl DualControlPolicy {
    pub fn dual() -> Self {
        Self { required: 2 }
    }

    pub fn of(n: u32) -> Self {
        Self {
            required: n.max(1),
        }
    }
}

/// One principal's approval of a concrete action + intent digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// Stable operator / API-key id (never the secret).
    pub principal_id: String,
    pub action: AdminAction,
    /// Hex SHA-256 of the canonical intent payload (ticket, target id, …).
    pub intent_digest_hex: String,
}

impl Approval {
    pub fn new(
        principal_id: impl Into<String>,
        action: AdminAction,
        intent_payload: &[u8],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(action.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(intent_payload);
        Self {
            principal_id: principal_id.into(),
            action,
            intent_digest_hex: hex::encode(hasher.finalize()),
        }
    }
}

/// Verify that `approvals` form a valid M-of-N quorum for `action` + intent.
pub fn verify_quorum(
    policy: &DualControlPolicy,
    action: AdminAction,
    intent_payload: &[u8],
    approvals: &[Approval],
) -> Result<(), IronCryptError> {
    let expected = Approval::new("_", action, intent_payload).intent_digest_hex;
    let mut principals = BTreeSet::new();
    for a in approvals {
        if a.action != action {
            return Err(IronCryptError::ConfigurationError(format!(
                "dual-control: approval action {:?} != {:?}",
                a.action, action
            )));
        }
        if a.intent_digest_hex != expected {
            return Err(IronCryptError::ConfigurationError(
                "dual-control: intent digest mismatch (wrong ticket / target)".into(),
            ));
        }
        if a.principal_id.trim().is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "dual-control: empty principal_id".into(),
            ));
        }
        // Normalize so "alice" / "alice " cannot count as two principals.
        let pid = a.principal_id.trim().to_string();
        principals.insert(pid);
    }
    if (principals.len() as u32) < policy.required {
        return Err(IronCryptError::ConfigurationError(format!(
            "dual-control: need {} distinct principals, got {} \
             (note: approvals are unsigned — wire to IdP/HSM before treating as a control)",
            policy.required,
            principals.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_control_requires_two_distinct() {
        let policy = DualControlPolicy::dual();
        let intent = b"revoke:ick_live_old";
        let a = Approval::new("alice", AdminAction::RevokeApiKey, intent);
        let b = Approval::new("bob", AdminAction::RevokeApiKey, intent);
        assert!(verify_quorum(&policy, AdminAction::RevokeApiKey, intent, &[a.clone()]).is_err());
        assert!(verify_quorum(&policy, AdminAction::RevokeApiKey, intent, &[a, b]).is_ok());
    }

    #[test]
    fn rejects_same_principal_twice() {
        let policy = DualControlPolicy::dual();
        let intent = b"tls-reload";
        let a = Approval::new("alice", AdminAction::RotateServiceTls, intent);
        let a2 = Approval::new("alice", AdminAction::RotateServiceTls, intent);
        assert!(verify_quorum(&policy, AdminAction::RotateServiceTls, intent, &[a, a2]).is_err());
    }

    #[test]
    fn rejects_wrong_intent() {
        let policy = DualControlPolicy::dual();
        let a = Approval::new("alice", AdminAction::PurgeAuditEarly, b"days=7");
        let b = Approval::new("bob", AdminAction::PurgeAuditEarly, b"days=7");
        assert!(verify_quorum(&policy, AdminAction::PurgeAuditEarly, b"days=1", &[a, b]).is_err());
    }

    #[test]
    fn trims_principal_aliases() {
        let policy = DualControlPolicy::dual();
        let intent = b"tls-reload";
        let a = Approval::new("alice", AdminAction::RotateServiceTls, intent);
        let b = Approval::new("alice ", AdminAction::RotateServiceTls, intent);
        assert!(verify_quorum(&policy, AdminAction::RotateServiceTls, intent, &[a, b]).is_err());
    }
}
