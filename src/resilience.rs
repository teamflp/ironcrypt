//! Timeouts, circuit breaker, and controlled retry for remote crypto backends.

use crate::IronCryptError;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default wall-clock budget for a single HTTP crypto request (daemon).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Default budget for one KMS/HSM/Vault round-trip.
pub const DEFAULT_PROVIDER_TIMEOUT: Duration = Duration::from_secs(15);

/// Default max attempts for [`with_retry`] (1 = no retry).
pub const DEFAULT_PROVIDER_MAX_ATTEMPTS: u32 = 3;

/// Simple consecutive-failure circuit breaker.
#[derive(Debug)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    cool_down: Duration,
    consecutive_failures: AtomicU32,
    open_until: Mutex<Option<Instant>>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, cool_down: Duration) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            cool_down,
            consecutive_failures: AtomicU32::new(0),
            open_until: Mutex::new(None),
        }
    }

    /// Returns an error if the circuit is open.
    pub fn guard(&self) -> Result<(), IronCryptError> {
        if self.is_open() {
            return Err(IronCryptError::ProviderError(
                "crypto provider circuit open (cooling down after failures)".into(),
            ));
        }
        Ok(())
    }

    /// Whether the circuit is currently open (cooling down).
    pub fn is_open(&self) -> bool {
        let guard = self.open_until.lock().unwrap_or_else(|e| e.into_inner());
        match *guard {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        if let Ok(mut g) = self.open_until.lock() {
            *g = None;
        }
    }

    pub fn record_failure(&self) {
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.failure_threshold {
            if let Ok(mut g) = self.open_until.lock() {
                *g = Some(Instant::now() + self.cool_down);
            }
        }
    }
}

/// How many distinct quarantined principals open the process-wide circuit.
/// One API key must not be able to take the provider down for everyone else.
const GLOBAL_QUARANTINE_PRINCIPALS: usize = 2;

const MAX_TRACKED_PRINCIPALS: usize = 4_096;

#[derive(Debug)]
struct PrincipalState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

/// Per-principal provider quarantine, with a global circuit that opens only
/// when several distinct principals are already quarantined.
#[derive(Debug)]
pub struct PrincipalQuarantine {
    failure_threshold: u32,
    cool_down: Duration,
    inner: Mutex<std::collections::HashMap<String, PrincipalState>>,
}

impl PrincipalQuarantine {
    pub fn new(failure_threshold: u32, cool_down: Duration) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            cool_down,
            inner: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, PrincipalState>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn expire(map: &mut std::collections::HashMap<String, PrincipalState>) {
        let now = Instant::now();
        map.retain(|_, st| match st.open_until {
            Some(until) if now >= until && st.consecutive_failures == 0 => false,
            Some(until) if now >= until => {
                st.open_until = None;
                st.consecutive_failures = 0;
                true
            }
            _ => true,
        });
    }

    fn quarantined_count(map: &std::collections::HashMap<String, PrincipalState>) -> usize {
        let now = Instant::now();
        map.values()
            .filter(|st| st.open_until.is_some_and(|until| now < until))
            .count()
    }

    /// Error when this principal is quarantined, or when enough distinct
    /// principals are quarantined that the shared provider is treated as down.
    pub fn guard(&self, principal: &str) -> Result<(), IronCryptError> {
        let mut map = self.lock();
        Self::expire(&mut map);
        if Self::quarantined_count(&map) >= GLOBAL_QUARANTINE_PRINCIPALS {
            return Err(IronCryptError::ProviderError(
                "crypto provider circuit open (cooling down after failures)".into(),
            ));
        }
        if let Some(st) = map.get(principal) {
            if st.open_until.is_some_and(|until| Instant::now() < until) {
                return Err(IronCryptError::ProviderError(
                    "crypto provider quarantined this principal (cooling down)".into(),
                ));
            }
        }
        Ok(())
    }

    /// Global circuit only. A single quarantined principal does not flip this.
    pub fn is_open(&self) -> bool {
        let mut map = self.lock();
        Self::expire(&mut map);
        Self::quarantined_count(&map) >= GLOBAL_QUARANTINE_PRINCIPALS
    }

    pub fn record_success(&self, principal: &str) {
        let mut map = self.lock();
        if let Some(st) = map.get_mut(principal) {
            st.consecutive_failures = 0;
            st.open_until = None;
        }
    }

    /// Count a provider-side failure against one principal.
    pub fn record_failure(&self, principal: &str) {
        let mut map = self.lock();
        if map.len() >= MAX_TRACKED_PRINCIPALS && !map.contains_key(principal) {
            Self::expire(&mut map);
            if map.len() >= MAX_TRACKED_PRINCIPALS {
                map.clear();
            }
        }
        let st = map.entry(principal.to_string()).or_insert(PrincipalState {
            consecutive_failures: 0,
            open_until: None,
        });
        st.consecutive_failures = st.consecutive_failures.saturating_add(1);
        if st.consecutive_failures >= self.failure_threshold {
            st.open_until = Some(Instant::now() + self.cool_down);
        }
    }
}

/// Bounded retry policy for transient provider failures (not auth / config errors).
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_PROVIDER_MAX_ATTEMPTS,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(2),
        }
    }
}

impl RetryPolicy {
    /// Whether an error is worth retrying (timeouts / transient provider faults).
    pub fn is_retryable(err: &IronCryptError) -> bool {
        match err {
            IronCryptError::ProviderError(msg) => {
                let m = msg.to_ascii_lowercase();
                if m.contains("circuit open") {
                    return false;
                }
                m.contains("timed out")
                    || m.contains("timeout")
                    || m.contains("unavailable")
                    || m.contains("temporarily")
                    || m.contains("connection")
                    || m.contains("reset")
                    || m.contains("503")
                    || m.contains("429")
                    || m.contains("http 5")
            }
            _ => false,
        }
    }
}

/// Run `fut` with a wall-clock timeout, mapping expiry to [`IronCryptError::ProviderError`].
pub async fn with_timeout<T, E, F>(
    budget: Duration,
    fut: F,
) -> Result<T, IronCryptError>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: Into<IronCryptError>,
{
    match tokio::time::timeout(budget, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(IronCryptError::ProviderError(format!(
            "operation timed out after {}s",
            budget.as_secs()
        ))),
    }
}

/// Retry `op` with exponential backoff for retryable [`IronCryptError::ProviderError`]s.
pub async fn with_retry<T, F, Fut>(policy: &RetryPolicy, mut op: F) -> Result<T, IronCryptError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, IronCryptError>>,
{
    let attempts = policy.max_attempts.max(1);
    let mut backoff = policy.initial_backoff;
    let mut last_err = None;
    for attempt in 1..=attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                let retry = attempt < attempts && RetryPolicy::is_retryable(&e);
                last_err = Some(e);
                if !retry {
                    break;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(policy.max_backoff);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        IronCryptError::ProviderError("retry exhausted without error".into())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn opens_after_threshold() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));
        assert!(cb.guard().is_ok());
        cb.record_failure();
        assert!(cb.guard().is_ok());
        cb.record_failure();
        assert!(cb.guard().is_err());
        cb.record_success();
        assert!(cb.guard().is_ok());
    }

    #[tokio::test]
    async fn retries_transient_then_succeeds() {
        let n = AtomicU32::new(0);
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        };
        let out = with_retry(&policy, || async {
            let i = n.fetch_add(1, Ordering::SeqCst);
            if i < 2 {
                Err(IronCryptError::ProviderError("connection reset".into()))
            } else {
                Ok(42u8)
            }
        })
        .await
        .unwrap();
        assert_eq!(out, 42);
        assert_eq!(n.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn does_not_retry_circuit_open() {
        let n = AtomicU32::new(0);
        let policy = RetryPolicy {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        };
        let err = with_retry(&policy, || async {
            n.fetch_add(1, Ordering::SeqCst);
            Err::<u8, _>(IronCryptError::ProviderError(
                "crypto provider circuit open (cooling down after failures)".into(),
            ))
        })
        .await
        .unwrap_err();
        assert!(matches!(err, IronCryptError::ProviderError(_)));
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn one_principal_cannot_open_the_global_circuit() {
        let q = PrincipalQuarantine::new(2, Duration::from_secs(60));
        assert!(q.guard("key-a").is_ok());
        q.record_failure("key-a");
        q.record_failure("key-a");
        assert!(q.guard("key-a").is_err());
        assert!(q.guard("key-b").is_ok());
        assert!(!q.is_open());
        q.record_failure("key-b");
        q.record_failure("key-b");
        assert!(q.is_open());
        assert!(q.guard("key-c").is_err());
        q.record_success("key-a");
        assert!(!q.is_open());
        assert!(q.guard("key-c").is_ok());
    }
}
