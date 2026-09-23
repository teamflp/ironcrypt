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
}
