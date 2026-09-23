//! Key lifecycle metadata and crash-safe on-disk writes.

use crate::IronCryptError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Lifecycle state for a key version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyState {
    Pending,
    Active,
    DecryptOnly,
    Retired,
    Revoked,
    Destroyed,
}

impl KeyState {
    pub fn can_encrypt(self) -> bool {
        matches!(self, KeyState::Active)
    }

    pub fn can_decrypt(self) -> bool {
        matches!(self, KeyState::Active | KeyState::DecryptOnly)
    }
}

/// Metadata for one version of a logical key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersionMeta {
    pub key_version: String,
    pub state: KeyState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<DateTime<Utc>>,
}

/// On-disk keyring: stable `key_id` plus versioned material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringManifest {
    pub key_id: String,
    pub versions: Vec<KeyVersionMeta>,
    pub active_version: String,
}

impl KeyringManifest {
    pub fn new(key_id: impl Into<String>, active_version: impl Into<String>, algorithm: &str) -> Self {
        let active_version = active_version.into();
        Self {
            key_id: key_id.into(),
            active_version: active_version.clone(),
            versions: vec![KeyVersionMeta {
                key_version: active_version,
                state: KeyState::Active,
                algorithm: Some(algorithm.to_string()),
                provider: Some("local".into()),
                activated_at: Some(Utc::now()),
                expires_at: None,
                rotated_at: None,
            }],
        }
    }

    pub fn version(&self, version: &str) -> Option<&KeyVersionMeta> {
        self.versions.iter().find(|v| v.key_version == version)
    }

    pub fn ensure_can_encrypt(&self, version: &str) -> Result<(), IronCryptError> {
        match self.version(version) {
            Some(meta) if meta.state.can_encrypt() => Ok(()),
            Some(meta) => Err(IronCryptError::ConfigurationError(format!(
                "key version '{version}' state {:?} cannot encrypt",
                meta.state
            ))),
            None => Err(IronCryptError::ConfigurationError(format!(
                "unknown key version '{version}' in keyring"
            ))),
        }
    }

    pub fn ensure_can_decrypt(&self, version: &str) -> Result<(), IronCryptError> {
        match self.version(version) {
            Some(meta) if meta.state.can_decrypt() => Ok(()),
            Some(meta) => Err(IronCryptError::ConfigurationError(format!(
                "key version '{version}' state {:?} cannot decrypt",
                meta.state
            ))),
            None => Err(IronCryptError::ConfigurationError(format!(
                "unknown key version '{version}' in keyring"
            ))),
        }
    }

    /// Promote `new_version` to Active and demote previous active to DecryptOnly.
    pub fn rotate_to(&mut self, new_version: &str, algorithm: &str) -> Result<(), IronCryptError> {
        if self.versions.iter().any(|v| v.key_version == new_version) {
            return Err(IronCryptError::ConfigurationError(format!(
                "key version '{new_version}' already exists in keyring"
            )));
        }
        let now = Utc::now();
        for v in &mut self.versions {
            if v.key_version == self.active_version && v.state == KeyState::Active {
                v.state = KeyState::DecryptOnly;
                v.rotated_at = Some(now);
            }
        }
        self.versions.push(KeyVersionMeta {
            key_version: new_version.to_string(),
            state: KeyState::Active,
            algorithm: Some(algorithm.to_string()),
            provider: Some("local".into()),
            activated_at: Some(now),
            expires_at: None,
            rotated_at: None,
        });
        self.active_version = new_version.to_string();
        Ok(())
    }

    /// True when the active version is past `expires_at` (rotation due).
    pub fn active_needs_rotation(&self, now: DateTime<Utc>) -> bool {
        self.version(&self.active_version)
            .and_then(|v| v.expires_at)
            .map(|exp| exp <= now)
            .unwrap_or(false)
    }

    /// Suggest next version label (`vN` → `vN+1`, else `{active}-rotated`).
    pub fn suggest_next_version(&self) -> String {
        let active = &self.active_version;
        if let Some(rest) = active.strip_prefix('v') {
            if let Ok(n) = rest.parse::<u64>() {
                return format!("v{}", n + 1);
            }
        }
        format!("{active}-rotated")
    }

    /// Human-readable rotation status for operators / CLI.
    pub fn rotation_report(&self, now: DateTime<Utc>, policy: &RotationPolicy) -> RotationReport {
        let due = self.active_needs_rotation(now)
            || policy
                .max_age_days
                .map(|days| {
                    self.version(&self.active_version)
                        .and_then(|v| v.activated_at)
                        .map(|act| now >= act + chrono::Duration::days(days as i64))
                        .unwrap_or(false)
                })
                .unwrap_or(false);
        RotationReport {
            key_id: self.key_id.clone(),
            active_version: self.active_version.clone(),
            rotation_due: due,
            suggested_next_version: if due {
                Some(self.suggest_next_version())
            } else {
                None
            },
            expires_at: self
                .version(&self.active_version)
                .and_then(|v| v.expires_at),
        }
    }
}

/// Optional policy for when active keys should be rotated.
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Rotate when active key age exceeds this many days (from `activated_at`).
    pub max_age_days: Option<u32>,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_age_days: Some(90),
        }
    }
}

/// Result of evaluating keyring rotation state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationReport {
    pub key_id: String,
    pub active_version: String,
    pub rotation_due: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_next_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Path to the keyring sidecar next to PEM material.
pub fn keyring_path(key_directory: &str) -> PathBuf {
    Path::new(key_directory).join("keyring.json")
}

pub fn load_keyring(key_directory: &str) -> Result<Option<KeyringManifest>, IronCryptError> {
    let path = keyring_path(key_directory);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&path)?;
    let manifest: KeyringManifest = serde_json::from_str(&data)
        .map_err(|e| IronCryptError::ConfigurationError(format!("invalid keyring.json: {e}")))?;
    Ok(Some(manifest))
}

pub fn save_keyring(key_directory: &str, manifest: &KeyringManifest) -> Result<(), IronCryptError> {
    let path = keyring_path(key_directory);
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| IronCryptError::ConfigurationError(e.to_string()))?;
    atomic_write(&path, json.as_bytes())
}

/// Write `data` via temp file + fsync + rename (crash-safe on POSIX).
///
/// Hardening:
/// - refuses to overwrite a destination that is a symlink;
/// - creates the temp file with `create_new` only (no truncate-reuse);
/// - sets Unix mode `0600` on the temp file and final path.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), IronCryptError> {
    if path_is_symlink(path) {
        return Err(IronCryptError::KeySavingError(format!(
            "refusing to write through symlink: {}",
            path.display()
        )));
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    // Drop a stale temp from a prior crash of this same pid (unlikely but tidy).
    let _ = fs::remove_file(&tmp);

    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| {
            IronCryptError::KeySavingError(format!(
                "failed to create temp file {}: {e}",
                tmp.display()
            ))
        })?;
        f.write_all(data)?;
        f.sync_all()?;
    }

    // Race: destination may have become a symlink after our first check.
    if path_is_symlink(path) {
        let _ = fs::remove_file(&tmp);
        return Err(IronCryptError::KeySavingError(format!(
            "refusing to write through symlink: {}",
            path.display()
        )));
    }

    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    // Best-effort directory fsync (may be unsupported on some FS).
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn path_is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rotate_demotes_previous_active() {
        let mut m = KeyringManifest::new("kid-1", "v1", "ecc-p256");
        m.rotate_to("v2", "ecc-p256").unwrap();
        assert_eq!(m.active_version, "v2");
        assert_eq!(m.version("v1").unwrap().state, KeyState::DecryptOnly);
        assert_eq!(m.version("v2").unwrap().state, KeyState::Active);
        assert!(m.ensure_can_encrypt("v2").is_ok());
        assert!(m.ensure_can_encrypt("v1").is_err());
        assert!(m.ensure_can_decrypt("v1").is_ok());
    }

    #[test]
    fn atomic_write_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("x.json");
        atomic_write(&path, b"{\"ok\":true}").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"ok\":true}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_refuses_symlink_destination() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.json");
        fs::write(&real, b"victim").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = atomic_write(&link, b"pwned").unwrap_err();
        assert!(
            matches!(err, IronCryptError::KeySavingError(_)),
            "{err:?}"
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "victim");
    }
}
