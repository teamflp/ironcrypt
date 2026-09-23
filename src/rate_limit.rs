//! Rate limiting for `ironcryptd` (local memory + optional Redis).
//!
//! Local limiting is a **second line** of defence. Prefer a gateway / WAF for
//! cluster-wide quotas; enable Redis when several daemon replicas share traffic.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::IronCryptError;

/// Async rate-limit backend used by the daemon middleware.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Returns `true` when the request may proceed.
    async fn check(&self, bucket_key: &str) -> bool;
}

/// Stable bucket material: hash of Authorization (or `_`) + method + path + optional IP.
pub fn bucket_key(auth_header: Option<&str>, method: &str, path: &str, peer_ip: Option<&str>) -> String {
    let identity = match auth_header {
        Some(auth) if !auth.is_empty() => {
            let mut hasher = Sha256::new();
            hasher.update(auth.as_bytes());
            hex::encode(hasher.finalize())
        }
        _ => "_".to_string(),
    };
    let mut key = format!("{identity}:{method}:{path}");
    if let Some(ip) = peer_ip {
        key.push(':');
        key.push_str(ip);
    }
    key
}

/// In-process fixed 1s window with burst (legacy daemon behaviour).
#[derive(Debug)]
pub struct MemoryRateLimiter {
    burst: u64,
    enabled: bool,
    max_keys: usize,
    state: Mutex<HashMap<String, (Instant, u64)>>,
}

impl MemoryRateLimiter {
    pub fn new(per_sec: u32, burst: u32) -> Self {
        if per_sec == 0 {
            return Self {
                burst: 0,
                enabled: false,
                max_keys: 10_000,
                state: Mutex::new(HashMap::new()),
            };
        }
        Self {
            burst: burst.max(1) as u64,
            enabled: true,
            max_keys: 10_000,
            state: Mutex::new(HashMap::new()),
        }
    }

    fn check_sync(&self, identity: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() >= self.max_keys && !guard.contains_key(identity) {
            if let Some(k) = guard.keys().next().cloned() {
                guard.remove(&k);
            }
        }
        let entry = guard
            .entry(identity.to_string())
            .or_insert_with(|| (Instant::now(), 0));
        let now = Instant::now();
        if now.duration_since(entry.0) >= Duration::from_secs(1) {
            entry.0 = now;
            entry.1 = 0;
        }
        if entry.1 >= self.burst {
            return false;
        }
        entry.1 += 1;
        true
    }
}

#[async_trait]
impl RateLimiter for MemoryRateLimiter {
    async fn check(&self, bucket_key: &str) -> bool {
        self.check_sync(bucket_key)
    }
}

/// Redis fixed-window limiter (`INCR` + `EXPIRE` on first hit).
///
/// Requires Cargo feature `redis-rate-limit`. Key prefix: `ironcrypt:rl:`.
#[cfg(feature = "redis-rate-limit")]
pub struct RedisRateLimiter {
    client: redis::Client,
    burst: u64,
    enabled: bool,
    key_prefix: String,
}

#[cfg(feature = "redis-rate-limit")]
impl RedisRateLimiter {
    pub fn connect(redis_url: &str, per_sec: u32, burst: u32) -> Result<Self, IronCryptError> {
        if per_sec == 0 {
            return Ok(Self {
                client: redis::Client::open("redis://127.0.0.1/").map_err(|e| {
                    IronCryptError::ConfigurationError(format!("redis: {e}"))
                })?,
                burst: 0,
                enabled: false,
                key_prefix: "ironcrypt:rl:".into(),
            });
        }
        let client = redis::Client::open(redis_url).map_err(|e| {
            IronCryptError::ConfigurationError(format!("redis url: {e}"))
        })?;
        // Fail fast on bad URL / unreachable broker at startup.
        let mut con = client.get_connection().map_err(|e| {
            IronCryptError::ConfigurationError(format!("redis connect: {e}"))
        })?;
        let _: String = redis::cmd("PING")
            .query(&mut con)
            .map_err(|e| IronCryptError::ConfigurationError(format!("redis PING: {e}")))?;
        Ok(Self {
            client,
            burst: burst.max(1) as u64,
            enabled: true,
            key_prefix: "ironcrypt:rl:".into(),
        })
    }
}

#[cfg(feature = "redis-rate-limit")]
#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn check(&self, bucket_key: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let client = self.client.clone();
        let redis_key = format!("{}{}", self.key_prefix, bucket_key);
        let burst = self.burst;
        // redis crate sync connection off the async runtime.
        match tokio::task::spawn_blocking(move || -> Result<bool, IronCryptError> {
            let mut con = client.get_connection().map_err(|e| {
                IronCryptError::ProviderError(format!("redis: {e}"))
            })?;
            let count: u64 = redis::cmd("INCR")
                .arg(&redis_key)
                .query(&mut con)
                .map_err(|e| IronCryptError::ProviderError(format!("redis INCR: {e}")))?;
            if count == 1 {
                let _: bool = redis::cmd("EXPIRE")
                    .arg(&redis_key)
                    .arg(1u64)
                    .query(&mut con)
                    .map_err(|e| IronCryptError::ProviderError(format!("redis EXPIRE: {e}")))?;
            }
            Ok(count <= burst)
        })
        .await
        {
            Ok(Ok(allowed)) => allowed,
            Ok(Err(e)) => {
                tracing::error!("redis rate limit error (fail-closed): {e}");
                false
            }
            Err(e) => {
                tracing::error!("redis rate limit join error (fail-closed): {e}");
                false
            }
        }
    }
}

/// Build the daemon rate limiter from CLI flags.
pub fn build_rate_limiter(
    backend: &str,
    redis_url: Option<&str>,
    per_sec: u32,
    burst: u32,
) -> Result<std::sync::Arc<dyn RateLimiter>, IronCryptError> {
    match backend.trim().to_ascii_lowercase().as_str() {
        "" | "memory" | "local" => Ok(std::sync::Arc::new(MemoryRateLimiter::new(per_sec, burst))),
        "redis" => {
            #[cfg(feature = "redis-rate-limit")]
            {
                let url = redis_url
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        IronCryptError::ConfigurationError(
                            "rate-limit-backend=redis requires --redis-url / IRONCRYPT_REDIS_URL"
                                .into(),
                        )
                    })?;
                Ok(std::sync::Arc::new(RedisRateLimiter::connect(
                    url, per_sec, burst,
                )?))
            }
            #[cfg(not(feature = "redis-rate-limit"))]
            {
                let _ = redis_url;
                let _ = per_sec;
                let _ = burst;
                Err(IronCryptError::ConfigurationError(
                    "rate-limit-backend=redis requires Cargo feature `redis-rate-limit`".into(),
                ))
            }
        }
        other => Err(IronCryptError::ConfigurationError(format!(
            "unknown rate-limit-backend '{other}' (expected memory | redis)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_bursts_then_blocks() {
        let lim = MemoryRateLimiter::new(10, 2);
        assert!(lim.check("k").await);
        assert!(lim.check("k").await);
        assert!(!lim.check("k").await);
    }

    #[test]
    fn bucket_key_hashes_auth() {
        let a = bucket_key(Some("Bearer secret"), "POST", "/write", Some("1.2.3.4"));
        let b = bucket_key(Some("Bearer secret"), "POST", "/write", Some("1.2.3.4"));
        assert_eq!(a, b);
        assert!(!a.contains("secret"));
    }
}
