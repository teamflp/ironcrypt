use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::info;

use crate::config::{AuditConfig, AuditSigningMode};
use crate::key_lifecycle::atomic_write;
use crate::signing::{sign_hash_with_any_key, verify_signature_with_any_key};
use crate::{load_any_private_key, IronCryptError, PrivateKey, PublicKey};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Fields allowed in SIEM / external log exports (no secret names, no raw errors).
pub const SIEM_ALLOWLIST_KEYS: &[&str] = &[
    "timestamp",
    "operation",
    "outcome",
    "key_type",
    "key_size",
    "key_version",
    "recipient_key_versions",
    "symmetric_algorithm",
    "signature_algorithm",
    "signer_key_version",
    "request_id",
    "principal_id",
    "tenant_id",
    "duration_ms",
    "prev_event_hash",
    "event_hash",
    "error_category",
];

/// Genesis previous-hash for the first event in a chain.
pub const AUDIT_CHAIN_GENESIS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

static LAST_EVENT_HASH: Mutex<Option<String>> = Mutex::new(None);

/// Sanitize an error for audit / operator logs.
///
/// Strips high-entropy blobs and common secret markers so plaintext, keys,
/// tokens, passphrases, PAN/CVV/PIN, or large ciphertext never land in logs.
/// Prefer stable, short categories over raw `Display` chains from providers.
pub fn sanitize_error_message(err: &dyn Display) -> String {
    let raw = err.to_string();
    sanitize_error_str(&raw)
}

/// Sanitize a free-form error string (same rules as [`sanitize_error_message`]).
pub fn sanitize_error_str(raw: &str) -> String {
    const MAX_LEN: usize = 240;
    let mut out = String::with_capacity(raw.len().min(MAX_LEN));
    let mut hex_run = 0usize;
    let mut b64ish_run = 0usize;

    for ch in raw.chars() {
        if out.len() >= MAX_LEN {
            out.push('…');
            break;
        }
        let is_hex = ch.is_ascii_hexdigit();
        let is_b64 =
            ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' || ch == '-';

        if is_hex {
            hex_run += 1;
            b64ish_run = 0;
            if hex_run > 16 {
                if !out.ends_with("[redacted]") {
                    // Trim the partial hex already written beyond the keep window.
                    let keep = out.len().saturating_sub(hex_run.min(out.len()));
                    out.truncate(keep);
                    out.push_str("[redacted]");
                }
                continue;
            }
        } else {
            hex_run = 0;
        }

        if is_b64 && !is_hex {
            b64ish_run += 1;
            if b64ish_run > 24 {
                if !out.ends_with("[redacted]") {
                    let keep = out.len().saturating_sub(b64ish_run.min(out.len()));
                    out.truncate(keep);
                    out.push_str("[redacted]");
                }
                continue;
            }
        } else if !is_hex {
            b64ish_run = 0;
        }

        out.push(ch);
    }

    // Keyword scrub (case-insensitive) for leftover secret-shaped tokens.
    let lower = out.to_ascii_lowercase();
    for needle in [
        "-----begin",
        "private key",
        "passphrase",
        "password=",
        "authorization:",
        "x-password",
        "api_key",
        "apikey",
        "bearer ",
        "cvv",
        "pan=",
    ] {
        if lower.contains(needle) {
            return "operation failed (details redacted)".to_string();
        }
    }

    if out.is_empty() {
        "operation failed".to_string()
    } else {
        out
    }
}

/// Mask a secret / vault path name for logs (never emit the raw name).
///
/// Returns a stable, non-reversible label: `sec:<len>:<sha256[:8]>`.
pub fn sanitize_secret_name(name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ironcrypt-secret-name-v1|");
    hasher.update(name.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("sec:{}:{}", name.len().min(256), &digest[..8])
}

/// Collapse a sanitized error into a coarse category for SIEM (no detail leak).
pub fn error_category(sanitized_error: &str) -> &'static str {
    let lower = sanitized_error.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("unavailable") {
        "provider_unavailable"
    } else if lower.contains("auth") || lower.contains("forbidden") || lower.contains("unauthorized")
    {
        "auth"
    } else if lower.contains("decrypt") || lower.contains("ciphertext") || lower.contains("aad") {
        "crypto"
    } else if lower.contains("config") {
        "config"
    } else if lower.contains("redacted") || lower.contains("operation failed") {
        "redacted"
    } else {
        "other"
    }
}

/// Project an [`AuditEvent`] to a SIEM-safe JSON object (allowlisted keys only).
///
/// `error_message` is never exported; only [`error_category`] when present.
pub fn audit_event_to_siem(event: &AuditEvent) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Ok(serde_json::Value::Object(full)) = serde_json::to_value(event) {
        for key in SIEM_ALLOWLIST_KEYS {
            if *key == "error_category" {
                continue;
            }
            if let Some(v) = full.get(*key) {
                if !v.is_null() {
                    map.insert((*key).to_string(), v.clone());
                }
            }
        }
    }
    if let Some(ref err) = event.error_message {
        map.insert(
            "error_category".into(),
            serde_json::Value::String(error_category(err).into()),
        );
    }
    serde_json::Value::Object(map)
}

/// Re-export JSONL audit lines as SIEM-safe JSONL (one object per line).
pub fn export_audit_jsonl_for_siem(path: &Path) -> Result<String, IronCryptError> {
    let file = fs::File::open(path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("open {}: {e}", path.display()))
    })?;
    let reader = BufReader::new(file);
    let mut out = String::new();
    for (lineno, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            IronCryptError::ConfigurationError(format!("read line {}: {e}", lineno + 1))
        })?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            IronCryptError::ConfigurationError(format!("parse line {}: {e}", lineno + 1))
        })?;
        let event_val = extract_event_object(&value).unwrap_or(value);
        let event: AuditEvent = serde_json::from_value(event_val).map_err(|e| {
            IronCryptError::ConfigurationError(format!("deserialize line {}: {e}", lineno + 1))
        })?;
        let siem = audit_event_to_siem(&event);
        out.push_str(&serde_json::to_string(&siem).unwrap_or_default());
        out.push('\n');
    }
    Ok(out)
}

/// Delete rolling `audit.log*` segments older than `retention_days`.
///
/// Returns the number of files removed. No-op when `retention_days == 0`.
/// Never deletes the currently open day's file if mtime is within the window.
pub fn purge_expired_audit_segments(
    directory: &Path,
    retention_days: u32,
) -> Result<usize, IronCryptError> {
    if retention_days == 0 {
        return Ok(0);
    }
    let cutoff = std::time::SystemTime::now()
        - std::time::Duration::from_secs(u64::from(retention_days) * 86_400);
    let entries = fs::read_dir(directory).map_err(|e| {
        IronCryptError::ConfigurationError(format!(
            "read audit directory {}: {e}",
            directory.display()
        ))
    })?;
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if !(name.starts_with("audit.log") || name.ends_with(".jsonl")) {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match meta.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if modified < cutoff {
            match fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(e) => {
                    tracing::warn!(
                        "failed to purge audit segment {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }
    }
    Ok(removed)
}

/// HMAC-SHA256 attest a file → `{path}.hmac` (hex digest).
pub fn sign_audit_file_hmac(log_path: &Path, key: &[u8]) -> Result<PathBuf, IronCryptError> {
    let content = fs::read(log_path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("read {}: {e}", log_path.display()))
    })?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        IronCryptError::KeyDerivationError("invalid audit HMAC key".into())
    })?;
    mac.update(&content);
    let tag = hex::encode(mac.finalize().into_bytes());
    let sig_path = PathBuf::from(format!("{}.hmac", log_path.display()));
    atomic_write(&sig_path, tag.as_bytes())?;
    Ok(sig_path)
}

/// Verify `{path}.hmac` against file bytes.
pub fn verify_audit_file_hmac(log_path: &Path, key: &[u8]) -> Result<(), IronCryptError> {
    let content = fs::read(log_path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("read {}: {e}", log_path.display()))
    })?;
    let sig_path = PathBuf::from(format!("{}.hmac", log_path.display()));
    let expected = fs::read_to_string(&sig_path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("read {}: {e}", sig_path.display()))
    })?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        IronCryptError::KeyDerivationError("invalid audit HMAC key".into())
    })?;
    mac.update(&content);
    let got = hex::encode(mac.finalize().into_bytes());
    use subtle::ConstantTimeEq;
    if !bool::from(got.as_bytes().ct_eq(expected.trim().as_bytes())) {
        return Err(IronCryptError::SignatureVerificationFailed(
            "audit HMAC mismatch".into(),
        ));
    }
    Ok(())
}

fn load_hmac_key_from_env(env_name: &str) -> Result<Zeroizing<Vec<u8>>, IronCryptError> {
    let raw = std::env::var(env_name).map_err(|_| {
        IronCryptError::ConfigurationError(format!(
            "audit signing_mode=hmac-env requires env {env_name}"
        ))
    })?;
    if raw.is_empty() {
        return Err(IronCryptError::ConfigurationError(format!(
            "{env_name} is empty"
        )));
    }
    Ok(Zeroizing::new(raw.into_bytes()))
}

/// Sign/attest according to [`AuditConfig`] (PEM lab / HMAC env / deferred provider).
pub fn sign_audit_from_config(config: &AuditConfig) -> Result<Vec<PathBuf>, IronCryptError> {
    match config.effective_signing_mode() {
        AuditSigningMode::None => Ok(Vec::new()),
        AuditSigningMode::Pem => {
            let path = config.signing_key_path.as_ref().ok_or_else(|| {
                IronCryptError::ConfigurationError(
                    "signing_mode=pem requires signing_key_path".into(),
                )
            })?;
            sign_audit_configured(
                &config.log_path,
                &config.audit_directory,
                path,
                None,
            )
        }
        AuditSigningMode::HmacEnv => {
            let key = load_hmac_key_from_env(config.hmac_env_name())?;
            sign_audit_targets_hmac(
                &config.log_path,
                &config.audit_directory,
                key.as_ref(),
            )
        }
        AuditSigningMode::Provider => Err(IronCryptError::UnsupportedOperation(
            "audit signing_mode=provider requires async IronCrypt::sign_audit_log \
             (CryptoProvider.encrypt of the file digest)"
                .into(),
        )),
    }
}

fn sign_audit_targets_hmac(
    log_path: &str,
    audit_directory: &str,
    key: &[u8],
) -> Result<Vec<PathBuf>, IronCryptError> {
    let targets = audit_sign_targets(log_path, audit_directory)?;
    let mut signed = Vec::new();
    for path in targets {
        signed.push(sign_audit_file_hmac(&path, key)?);
    }
    Ok(signed)
}

/// List audit files to sign: a single `log_path` file, or rolling `audit.log*` under the directory.
pub fn audit_sign_targets(
    log_path: &str,
    audit_directory: &str,
) -> Result<Vec<PathBuf>, IronCryptError> {
    let single = Path::new(log_path);
    if !log_path.is_empty() && single.is_file() {
        return Ok(vec![single.to_path_buf()]);
    }
    let dir = if !audit_directory.is_empty() {
        Path::new(audit_directory)
    } else if !log_path.is_empty() {
        Path::new(log_path)
    } else {
        return Err(IronCryptError::ConfigurationError(
            "no audit log_path or audit_directory configured for signing".into(),
        ));
    };
    if !dir.is_dir() {
        return Err(IronCryptError::ConfigurationError(format!(
            "audit path {} is not a directory",
            dir.display()
        )));
    }
    let entries = fs::read_dir(dir).map_err(|e| {
        IronCryptError::ConfigurationError(format!("read {}: {e}", dir.display()))
    })?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| {
                    n.starts_with("audit.log")
                        && !n.ends_with(".hmac")
                        && !n.ends_with(".sig")
                        && !n.ends_with(".attestation")
                })
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    Ok(paths)
}

/// Attest a file digest with [`CryptoProvider::encrypt`] → `{path}.attestation` (base64).
pub async fn attest_audit_file_with_provider(
    log_path: &Path,
    provider: &dyn crate::CryptoProvider,
    key_id: &str,
) -> Result<PathBuf, IronCryptError> {
    let content = fs::read(log_path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("read {}: {e}", log_path.display()))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let digest = hasher.finalize();
    let sealed = provider
        .encrypt(key_id, &digest, Some(b"ironcrypt-audit-v1"))
        .await?;
    let out = PathBuf::from(format!("{}.attestation", log_path.display()));
    atomic_write(&out, base64_standard.encode(sealed).as_bytes())?;
    Ok(out)
}

/// Represents the outcome of a cryptographic operation.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
}

/// Represents the type of cryptographic operation performed.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    GenerateKey,
    Write,
    Read,
    Sign,
    Verify,
    Rekey,
}

/// A structured event for auditing cryptographic operations.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuditEvent {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub operation: Operation,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipient_key_versions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symmetric_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_key_version: Option<String>,
    /// Correlation id from `X-Request-Id` / generated UUID-ish hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// API key `key_id` / prefix or owner label (never the secret).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Tenant from EncryptionContext when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Wall-clock duration of the operation in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// SHA-256 hex of the previous event (or genesis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<String>,
    /// SHA-256 hex of this event's chain material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
}

impl AuditEvent {
    /// Creates a new audit event.
    pub fn new(operation: Operation) -> Self {
        Self {
            timestamp: Utc::now(),
            operation,
            outcome: Outcome::Success, // Default to success
            error_message: None,
            key_type: None,
            key_size: None,
            key_version: None,
            recipient_key_versions: Vec::new(),
            symmetric_algorithm: None,
            signature_algorithm: None,
            signer_key_version: None,
            request_id: None,
            principal_id: None,
            tenant_id: None,
            duration_ms: None,
            prev_event_hash: None,
            event_hash: None,
        }
    }

    /// Attach a sanitized failure message (never store raw provider/crypto Display).
    pub fn set_failure(&mut self, err: impl Display) {
        self.outcome = Outcome::Failure;
        self.error_message = Some(sanitize_error_message(&err));
    }

    /// Seal this event into the in-process hash chain (sets `prev_event_hash` / `event_hash`).
    pub fn seal_chain(&mut self) {
        let mut guard = LAST_EVENT_HASH.lock().unwrap_or_else(|e| e.into_inner());
        let prev = guard
            .clone()
            .unwrap_or_else(|| AUDIT_CHAIN_GENESIS.to_string());
        self.prev_event_hash.replace(prev.clone());
        self.event_hash = None;
        let material = canonical_chain_material(self);
        let hash = sha256_hex(format!("{prev}|{material}").as_bytes());
        self.event_hash = Some(hash.clone());
        *guard = Some(hash);
    }

    /// Logs the event using the `tracing` crate.
    ///
    /// This serializes the entire event struct into a JSON object, which is then
    /// logged. This works well with `tracing_subscriber::fmt().json()`.
    ///
    /// **Must not** contain plaintext, PAN/CVV/PIN, keys, tokens, passphrases,
    /// or large ciphertext — use [`sanitize_error_message`] / [`Self::set_failure`].
    pub fn log(&self) {
        let mut event = AuditEvent {
            timestamp: self.timestamp,
            operation: self.operation,
            outcome: self.outcome,
            error_message: self.error_message.clone(),
            key_type: self.key_type.clone(),
            key_size: self.key_size,
            key_version: self.key_version.clone(),
            recipient_key_versions: self.recipient_key_versions.clone(),
            symmetric_algorithm: self.symmetric_algorithm.clone(),
            signature_algorithm: self.signature_algorithm.clone(),
            signer_key_version: self.signer_key_version.clone(),
            request_id: self.request_id.clone(),
            principal_id: self.principal_id.clone(),
            tenant_id: self.tenant_id.clone(),
            duration_ms: self.duration_ms,
            prev_event_hash: self.prev_event_hash.clone(),
            event_hash: self.event_hash.clone(),
        };
        if event.event_hash.is_none() {
            event.seal_chain();
        }
        match serde_json::to_value(&event) {
            Ok(serde_json::Value::Object(map)) => {
                info!(target: "audit", event = ?map);
            }
            _ => {
                // Fallback for safety, though it shouldn't happen with this struct.
                info!(target: "audit", "Failed to serialize audit event");
            }
        }
    }
}

fn canonical_chain_material(event: &AuditEvent) -> String {
    // Hash without event_hash (still being computed); include prev.
    let clone = AuditEvent {
        timestamp: event.timestamp,
        operation: event.operation,
        outcome: event.outcome,
        error_message: event.error_message.clone(),
        key_type: event.key_type.clone(),
        key_size: event.key_size,
        key_version: event.key_version.clone(),
        recipient_key_versions: event.recipient_key_versions.clone(),
        symmetric_algorithm: event.symmetric_algorithm.clone(),
        signature_algorithm: event.signature_algorithm.clone(),
        signer_key_version: event.signer_key_version.clone(),
        request_id: event.request_id.clone(),
        principal_id: event.principal_id.clone(),
        tenant_id: event.tenant_id.clone(),
        duration_ms: event.duration_ms,
        prev_event_hash: event.prev_event_hash.clone(),
        event_hash: None,
    };
    // Stable-ish JSON (field order from Serialize derive).
    serde_json::to_string(&clone).unwrap_or_default()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Reset the in-process chain (tests / process restart semantics).
#[cfg(test)]
pub fn reset_audit_chain_for_tests() {
    if let Ok(mut g) = LAST_EVENT_HASH.lock() {
        *g = None;
    }
}

/// Verify a JSONL audit file where each line is a tracing JSON record containing
/// `event.prev_event_hash` / `event.event_hash`, **or** a bare AuditEvent object.
pub fn verify_audit_jsonl(path: &Path) -> Result<usize, IronCryptError> {
    let file = fs::File::open(path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("open audit log {}: {e}", path.display()))
    })?;
    let reader = BufReader::new(file);
    let mut prev = AUDIT_CHAIN_GENESIS.to_string();
    let mut count = 0usize;

    for (lineno, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            IronCryptError::ConfigurationError(format!("read audit line {}: {e}", lineno + 1))
        })?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            IronCryptError::ConfigurationError(format!(
                "audit JSON parse line {}: {e}",
                lineno + 1
            ))
        })?;
        let event_val = extract_event_object(&value).ok_or_else(|| {
            IronCryptError::ConfigurationError(format!(
                "audit line {} missing event object",
                lineno + 1
            ))
        })?;

        let claimed_prev = event_val
            .get("prev_event_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let claimed_hash = event_val
            .get("event_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if claimed_prev.is_empty() || claimed_hash.is_empty() {
            return Err(IronCryptError::ConfigurationError(format!(
                "audit line {} missing chain fields",
                lineno + 1
            )));
        }
        if claimed_prev != prev {
            return Err(IronCryptError::SignatureVerificationFailed(format!(
                "audit chain break at line {}: prev hash mismatch",
                lineno + 1
            )));
        }

        // Recompute via the same Serialize path used at seal time.
        let mut event: AuditEvent = serde_json::from_value(event_val).map_err(|e| {
            IronCryptError::ConfigurationError(format!(
                "audit line {} deserialize: {e}",
                lineno + 1
            ))
        })?;
        event.event_hash = None;
        event.prev_event_hash = Some(claimed_prev.clone());
        let material = canonical_chain_material(&event);
        let expected = sha256_hex(format!("{prev}|{material}").as_bytes());
        if expected != claimed_hash {
            return Err(IronCryptError::SignatureVerificationFailed(format!(
                "audit chain break at line {}: event hash mismatch",
                lineno + 1
            )));
        }
        prev = claimed_hash;
        count += 1;
    }
    Ok(count)
}

fn extract_event_object(value: &serde_json::Value) -> Option<serde_json::Value> {
    if value.get("operation").is_some() {
        return Some(value.clone());
    }
    // tracing-subscriber json: {"fields":{"event":{...}}} or nested
    if let Some(fields) = value.get("fields") {
        if let Some(ev) = fields.get("event") {
            return Some(ev.clone());
        }
    }
    value.get("event").cloned()
}

/// Sign a single audit log file → `{path}.sig` (base64 signature over SHA-256 of file bytes).
pub fn sign_audit_file(
    log_path: &Path,
    private_key: &PrivateKey,
) -> Result<PathBuf, IronCryptError> {
    let content = fs::read(log_path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("read {}: {e}", log_path.display()))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hasher.finalize();
    let signature = sign_hash_with_any_key(private_key, &hash)?;
    let sig_path = PathBuf::from(format!("{}.sig", log_path.display()));
    atomic_write(&sig_path, base64_standard.encode(signature).as_bytes())?;
    Ok(sig_path)
}

/// Verify `{log_path}.sig` against the file contents.
pub fn verify_audit_file_signature(
    log_path: &Path,
    public_key: &PublicKey,
) -> Result<(), IronCryptError> {
    let content = fs::read(log_path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("read {}: {e}", log_path.display()))
    })?;
    let sig_path = PathBuf::from(format!("{}.sig", log_path.display()));
    let sig_b64 = fs::read_to_string(&sig_path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("read {}: {e}", sig_path.display()))
    })?;
    let signature = base64_standard.decode(sig_b64.trim()).map_err(|e| {
        IronCryptError::ConfigurationError(format!("decode audit signature: {e}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hasher.finalize();
    verify_signature_with_any_key(public_key, &hash, &signature)
}

/// Sign every rolling segment under `directory` matching `audit.log*`.
///
/// Returns the list of `.sig` paths written. Skips files that already end in `.sig`.
pub fn sign_audit_rolling_directory(
    directory: &Path,
    private_key: &PrivateKey,
) -> Result<Vec<PathBuf>, IronCryptError> {
    let mut out = Vec::new();
    let entries = fs::read_dir(directory).map_err(|e| {
        IronCryptError::ConfigurationError(format!(
            "read audit directory {}: {e}",
            directory.display()
        ))
    })?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("audit.log") && !n.ends_with(".sig"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    for path in paths {
        out.push(sign_audit_file(&path, private_key)?);
    }
    Ok(out)
}

/// High-level helper: sign configured audit path or rolling directory.
pub fn sign_audit_configured(
    log_path: &str,
    audit_directory: &str,
    signing_key_path: &str,
    passphrase: Option<&str>,
) -> Result<Vec<PathBuf>, IronCryptError> {
    let private_key = load_any_private_key(signing_key_path, passphrase)?;
    let mut signed = Vec::new();

    let single = Path::new(log_path);
    if !log_path.is_empty() && single.is_file() {
        signed.push(sign_audit_file(single, &private_key)?);
        return Ok(signed);
    }

    let dir = if !audit_directory.is_empty() {
        Path::new(audit_directory)
    } else if !log_path.is_empty() {
        Path::new(log_path)
    } else {
        return Err(IronCryptError::ConfigurationError(
            "no audit log_path or audit_directory configured for signing".into(),
        ));
    };

    if dir.is_dir() {
        return sign_audit_rolling_directory(dir, &private_key);
    }

    Err(IronCryptError::ConfigurationError(format!(
        "audit path {} is neither a file nor a rolling directory",
        dir.display()
    )))
}

/// Append a sealed AuditEvent as one JSONL line (append-only file).
pub fn append_audit_jsonl(path: &Path, event: &mut AuditEvent) -> Result<(), IronCryptError> {
    event.seal_chain();
    let line = serde_json::to_string(event)
        .map_err(|e| IronCryptError::ConfigurationError(e.to_string()))?;
    let mut opts = fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        IronCryptError::ConfigurationError(format!("append audit {}: {e}", path.display()))
    })?;
    writeln!(f, "{line}").map_err(|e| {
        IronCryptError::ConfigurationError(format!("write audit {}: {e}", path.display()))
    })?;
    f.sync_all().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_long_hex_and_pem_markers() {
        let s = sanitize_error_str(
            "decrypt failed key=0123456789abcdef0123456789abcdef deadbeef",
        );
        assert!(s.contains("[redacted]"), "{s}");
        assert!(!s.contains("0123456789abcdef0123456789abcdef"));

        let pem = sanitize_error_str("-----BEGIN PRIVATE KEY-----\nMIIE...");
        assert_eq!(pem, "operation failed (details redacted)");
    }

    #[test]
    fn sanitize_secret_name_is_stable_and_opaque() {
        let a = sanitize_secret_name("db/prod/stripe_api_key");
        let b = sanitize_secret_name("db/prod/stripe_api_key");
        assert_eq!(a, b);
        assert!(!a.contains("stripe"));
        assert!(a.starts_with("sec:"));
        let other = sanitize_secret_name("other");
        assert_ne!(a, other);
    }

    #[test]
    fn siem_export_strips_error_message() {
        let mut ev = AuditEvent::new(Operation::Read);
        ev.set_failure("decrypt failed key=0123456789abcdef0123456789abcdef");
        let siem = audit_event_to_siem(&ev);
        let obj = siem.as_object().unwrap();
        assert!(obj.get("error_message").is_none());
        assert!(obj.get("error_category").is_some());
        assert!(!serde_json::to_string(&siem).unwrap().contains("0123456789"));
    }

    #[test]
    fn hmac_audit_sign_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        fs::write(&path, b"line1\nline2\n").unwrap();
        let key = b"audit-hmac-test-key-32bytes!!!!!!";
        sign_audit_file_hmac(&path, key).unwrap();
        verify_audit_file_hmac(&path, key).unwrap();
        assert!(verify_audit_file_hmac(&path, b"wrong-key-wrong-key-wrong-key!!").is_err());
    }

    #[test]
    fn purge_respects_retention_zero() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("audit.log.2020-01-01"), b"x").unwrap();
        assert_eq!(purge_expired_audit_segments(dir.path(), 0).unwrap(), 0);
        assert!(dir.path().join("audit.log.2020-01-01").exists());
    }

    #[test]
    fn jsonl_hash_chain_roundtrip() {
        reset_audit_chain_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        for _ in 0..3 {
            let mut ev = AuditEvent::new(Operation::Write);
            ev.key_version = Some("v1".into());
            append_audit_jsonl(&path, &mut ev).unwrap();
        }
        assert_eq!(verify_audit_jsonl(&path).unwrap(), 3);

        // Tamper
        let mut raw = fs::read_to_string(&path).unwrap();
        raw.push_str("{\"operation\":\"write\",\"outcome\":\"success\",\"prev_event_hash\":\"dead\",\"event_hash\":\"beef\"}\n");
        fs::write(&path, raw).unwrap();
        assert!(verify_audit_jsonl(&path).is_err());
    }
}
