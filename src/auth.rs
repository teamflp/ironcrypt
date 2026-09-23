//! Daemon API-key catalog: hash records, never the secret.
//!
//! Overlapping rotation keeps two usable rows (old with shortened `expires_at`,
//! new with `not_before` / `replaces_key_id`) so clients can cut over without
//! downtime. See [`rotate_api_key_file`].

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::key_lifecycle::atomic_write;
use crate::IronCryptError;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Write,
    Read,
    Delete,
    Update,
    Full,
}

/// Daemon API key record (stored as hash — never the secret).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyConfig {
    pub description: String,
    /// SHA-512 hex of the API secret (`ick_live_…` string bytes, or legacy raw key bytes).
    pub key_hash: String,
    pub permissions: Vec<Permission>,
    #[serde(default)]
    pub allowed_services: Option<Vec<String>>,
    /// Public identifier / prefix (e.g. `ick_live_ab12cd34`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// Key is not usable before this instant (staging / overlap cutover).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Optional owner / principal label for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// When this key was issued as a rotation of another `key_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces_key_id: Option<String>,
}

impl ApiKeyConfig {
    pub const LIVE_PREFIX: &'static str = "ick_live_";

    /// Whether this key may authenticate right now.
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(nb) = self.not_before {
            if now < nb {
                return false;
            }
        }
        if let Some(exp) = self.expires_at {
            if exp <= now {
                return false;
            }
        }
        true
    }

    /// Expand a lone `Full` permission into Read/Write/Delete/Update.
    pub fn expand_full_permissions(&mut self) {
        if self.permissions.contains(&Permission::Full) {
            self.permissions.retain(|p| *p != Permission::Full);
            self.permissions.push(Permission::Read);
            self.permissions.push(Permission::Write);
            self.permissions.push(Permission::Delete);
            self.permissions.push(Permission::Update);
            self.permissions.sort();
            self.permissions.dedup();
        }
    }

    /// Build a live API secret (`ick_live_` + base64url) and `(secret, key_id_prefix, sha512_hex)`.
    ///
    /// Raw key bytes are zeroized before return; callers must treat `secret` as sensitive.
    pub fn generate_live_secret() -> (String, String, String) {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let secret_body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        raw.zeroize();
        let secret = format!("{}{}", Self::LIVE_PREFIX, secret_body);
        let prefix: String = secret.chars().take(Self::LIVE_PREFIX.len() + 8).collect();

        let mut hasher = Sha512::new();
        hasher.update(secret.as_bytes());
        let hash_hex = hex::encode(hasher.finalize());

        (secret, prefix, hash_hex)
    }
}

/// Expand `Full` on every record (daemon load path).
pub fn expand_full_permissions(keys: &mut [ApiKeyConfig]) {
    for k in keys.iter_mut() {
        k.expand_full_permissions();
    }
}

/// Result of an overlapping API-key rotation.
#[derive(Debug)]
pub struct ApiKeyRotation {
    /// New Bearer secret (show once).
    pub secret: String,
    pub new_key: ApiKeyConfig,
    /// Index of the previous key in the catalog (if rotated in place).
    pub previous_index: Option<usize>,
}

/// Append a new key and shorten the previous key's lifetime for overlap.
///
/// - Locates `previous` by `key_id` (or the sole usable key when `previous_key_id` is `None`).
/// - Sets previous `expires_at = now + grace` (keeps it usable during cutover).
/// - Appends a new key with the same permissions / services / owner, `not_before = now`,
///   and `replaces_key_id` pointing at the old key.
pub fn rotate_api_keys(
    keys: &mut Vec<ApiKeyConfig>,
    previous_key_id: Option<&str>,
    grace: Duration,
    description: Option<&str>,
    validity: Duration,
) -> Result<ApiKeyRotation, IronCryptError> {
    let now = Utc::now();
    let prev_idx = match previous_key_id {
        Some(id) => keys
            .iter()
            .position(|k| k.key_id.as_deref() == Some(id))
            .ok_or_else(|| {
                IronCryptError::ConfigurationError(format!(
                    "no API key with keyId '{id}' to rotate"
                ))
            })?,
        None => {
            let usable: Vec<usize> = keys
                .iter()
                .enumerate()
                .filter(|(_, k)| k.is_usable(now))
                .map(|(i, _)| i)
                .collect();
            match usable.as_slice() {
                [i] => *i,
                [] => {
                    return Err(IronCryptError::ConfigurationError(
                        "no usable API key to rotate; pass --previous-key-id or generate first"
                            .into(),
                    ))
                }
                _ => {
                    return Err(IronCryptError::ConfigurationError(
                        "multiple usable API keys; pass --previous-key-id".into(),
                    ))
                }
            }
        }
    };

    let (secret, prefix, hash_hex) = ApiKeyConfig::generate_live_secret();
    let prev = &keys[prev_idx];
    let old_id = prev.key_id.clone();
    let permissions = prev.permissions.clone();
    let allowed_services = prev.allowed_services.clone();
    let owner = prev.owner.clone();

    let grace_end = now + grace;
    {
        let prev = &mut keys[prev_idx];
        // Keep revoked keys revoked; otherwise cap expiry at grace end.
        if prev.revoked_at.is_none() {
            prev.expires_at = Some(match prev.expires_at {
                Some(exp) if exp <= grace_end => exp,
                _ => grace_end,
            });
        }
    }

    let new_key = ApiKeyConfig {
        description: description
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("Rotated from {}", old_id.as_deref().unwrap_or("previous"))),
        key_hash: hash_hex,
        permissions,
        allowed_services,
        key_id: Some(prefix),
        created_at: Some(now),
        not_before: Some(now),
        expires_at: Some(now + validity),
        revoked_at: None,
        last_used_at: None,
        owner,
        replaces_key_id: old_id,
    };
    keys.push(new_key.clone());

    Ok(ApiKeyRotation {
        secret,
        new_key,
        previous_index: Some(prev_idx),
    })
}

/// Load → rotate → atomically rewrite a `keys.json` file.
pub fn rotate_api_key_file(
    path: &std::path::Path,
    previous_key_id: Option<&str>,
    grace_days: i64,
    validity_days: i64,
    description: Option<&str>,
) -> Result<ApiKeyRotation, IronCryptError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        IronCryptError::ConfigurationError(format!(
            "read API keys file {}: {e}",
            path.display()
        ))
    })?;
    let mut keys: Vec<ApiKeyConfig> = serde_json::from_str(&raw).map_err(|e| {
        IronCryptError::ConfigurationError(format!("parse API keys file: {e}"))
    })?;
    expand_full_permissions(&mut keys);

    let rotation = rotate_api_keys(
        &mut keys,
        previous_key_id,
        Duration::days(grace_days.max(0)),
        description,
        Duration::days(validity_days.max(1)),
    )?;

    let json = serde_json::to_string_pretty(&keys).map_err(|e| {
        IronCryptError::ConfigurationError(format!("serialize API keys: {e}"))
    })?;
    atomic_write(path, json.as_bytes())?;
    Ok(rotation)
}

/// Principal attached after successful API-key auth (never contains the secret).
#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal {
    pub key_id: Option<String>,
    pub owner: Option<String>,
    pub permissions: Vec<Permission>,
}

impl AuthenticatedPrincipal {
    /// Best-effort audit label: owner, else key_id.
    pub fn audit_label(&self) -> Option<String> {
        self.owner.clone().or_else(|| self.key_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(key_id: &str, hash: &str) -> ApiKeyConfig {
        ApiKeyConfig {
            description: "t".into(),
            key_hash: hash.into(),
            permissions: vec![Permission::Read],
            allowed_services: None,
            key_id: Some(key_id.into()),
            created_at: Some(Utc::now() - Duration::days(10)),
            not_before: None,
            expires_at: Some(Utc::now() + Duration::days(30)),
            revoked_at: None,
            last_used_at: None,
            owner: Some("ops".into()),
            replaces_key_id: None,
        }
    }

    #[test]
    fn not_before_blocks_early() {
        let mut k = sample("ick_live_aaaa", "aa");
        k.not_before = Some(Utc::now() + Duration::hours(1));
        assert!(!k.is_usable(Utc::now()));
    }

    #[test]
    fn expired_and_revoked_rejected() {
        let mut k = sample("ick_live_bbbb", "bb");
        k.expires_at = Some(Utc::now() - Duration::seconds(1));
        assert!(!k.is_usable(Utc::now()));
        k.expires_at = Some(Utc::now() + Duration::days(1));
        k.revoked_at = Some(Utc::now());
        assert!(!k.is_usable(Utc::now()));
    }

    #[test]
    fn rotate_overlaps_previous() {
        let mut keys = vec![sample("ick_live_old000", "oldhash")];
        let rot = rotate_api_keys(
            &mut keys,
            Some("ick_live_old000"),
            Duration::days(7),
            Some("new app key"),
            Duration::days(90),
        )
        .unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys[0].is_usable(Utc::now()));
        assert!(keys[1].is_usable(Utc::now()));
        assert_eq!(
            keys[1].replaces_key_id.as_deref(),
            Some("ick_live_old000")
        );
        assert!(rot.secret.starts_with(ApiKeyConfig::LIVE_PREFIX));
        // After grace, old expires.
        let after_grace = Utc::now() + Duration::days(8);
        assert!(!keys[0].is_usable(after_grace));
        assert!(keys[1].is_usable(after_grace));
    }

    #[test]
    fn expand_full() {
        let mut k = sample("ick_live_cccc", "cc");
        k.permissions = vec![Permission::Full];
        k.expand_full_permissions();
        assert!(!k.permissions.contains(&Permission::Full));
        assert!(k.permissions.contains(&Permission::Read));
        assert!(k.permissions.contains(&Permission::Write));
    }
}
