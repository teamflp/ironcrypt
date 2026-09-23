//! Pluggable API-key catalogs for `ironcryptd`.
//!
//! Production deployments should prefer injecting the catalog from a sealed
//! secret store / IAM pipeline rather than a world-readable `keys.json` on disk.
//! The file backend remains the default for local/dev; the env backend accepts
//! a JSON blob via `IRONCRYPT_API_KEYS_JSON` (e.g. mounted from Vault Agent /
//! Kubernetes secret).

use crate::auth::{expand_full_permissions, ApiKeyConfig};
use crate::IronCryptError;
use std::path::{Path, PathBuf};

/// Where the daemon loads API-key hashes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyBackend {
    /// JSON array file (`--api-keys-file` / `IRONCRYPT_API_KEYS_FILE`).
    File,
    /// JSON array in `IRONCRYPT_API_KEYS_JSON` (no file on disk).
    Env,
}

impl ApiKeyBackend {
    pub fn parse(s: &str) -> Result<Self, IronCryptError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "file" | "json" | "keys.json" => Ok(Self::File),
            "env" | "environment" | "json-env" => Ok(Self::Env),
            other => Err(IronCryptError::ConfigurationError(format!(
                "unknown API key backend '{other}' (expected file|env)"
            ))),
        }
    }
}

/// Load + normalize a catalog of API key hashes.
pub trait ApiKeyStore: Send + Sync {
    fn load(&self) -> Result<Vec<ApiKeyConfig>, IronCryptError>;
}

/// File-backed catalog (`keys.json`).
#[derive(Debug, Clone)]
pub struct FileApiKeyStore {
    path: PathBuf,
}

impl FileApiKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ApiKeyStore for FileApiKeyStore {
    fn load(&self) -> Result<Vec<ApiKeyConfig>, IronCryptError> {
        let raw = std::fs::read_to_string(&self.path).map_err(|e| {
            IronCryptError::ConfigurationError(format!(
                "read API keys file {}: {e}",
                self.path.display()
            ))
        })?;
        parse_api_keys_json(&raw)
    }
}

/// Environment-backed catalog (`IRONCRYPT_API_KEYS_JSON`).
#[derive(Debug, Clone, Default)]
pub struct EnvApiKeyStore {
    env_var: String,
}

impl EnvApiKeyStore {
    pub const DEFAULT_VAR: &'static str = "IRONCRYPT_API_KEYS_JSON";

    pub fn new() -> Self {
        Self {
            env_var: Self::DEFAULT_VAR.to_string(),
        }
    }

    pub fn from_var(name: impl Into<String>) -> Self {
        Self {
            env_var: name.into(),
        }
    }
}

impl ApiKeyStore for EnvApiKeyStore {
    fn load(&self) -> Result<Vec<ApiKeyConfig>, IronCryptError> {
        let raw = std::env::var(&self.env_var).map_err(|_| {
            IronCryptError::ConfigurationError(format!(
                "API key backend=env requires ${} to be set to a JSON array",
                self.env_var
            ))
        })?;
        parse_api_keys_json(&raw)
    }
}

/// Parse a JSON array of [`ApiKeyConfig`] and expand `Full` permissions.
pub fn parse_api_keys_json(raw: &str) -> Result<Vec<ApiKeyConfig>, IronCryptError> {
    let mut keys: Vec<ApiKeyConfig> = serde_json::from_str(raw).map_err(|e| {
        IronCryptError::ConfigurationError(format!("parse API keys JSON: {e}"))
    })?;
    if keys.is_empty() {
        return Err(IronCryptError::ConfigurationError(
            "API keys catalog is empty".into(),
        ));
    }
    expand_full_permissions(&mut keys);
    Ok(keys)
}

/// Build the configured store.
pub fn build_api_key_store(
    backend: ApiKeyBackend,
    file_path: &str,
) -> Result<Box<dyn ApiKeyStore>, IronCryptError> {
    match backend {
        ApiKeyBackend::File => Ok(Box::new(FileApiKeyStore::new(file_path))),
        ApiKeyBackend::Env => Ok(Box::new(EnvApiKeyStore::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_expands_full() {
        let json = r#"[{
            "description":"t",
            "keyHash":"abc",
            "permissions":["full"]
        }]"#;
        let keys = parse_api_keys_json(json).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].permissions.contains(&crate::auth::Permission::Read));
        assert!(!keys[0]
            .permissions
            .contains(&crate::auth::Permission::Full));
    }

    #[test]
    fn backend_parse() {
        assert_eq!(ApiKeyBackend::parse("file").unwrap(), ApiKeyBackend::File);
        assert_eq!(ApiKeyBackend::parse("ENV").unwrap(), ApiKeyBackend::Env);
        assert!(ApiKeyBackend::parse("redis").is_err());
    }
}
