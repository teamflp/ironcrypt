//! Simulated HSM/KMS mid-operation failures (retry + circuit).

use async_trait::async_trait;
use ironcrypt::crypto_provider::{CryptoProvider, WrappedKey};
use ironcrypt::resilience::{with_retry, CircuitBreaker, RetryPolicy};
use ironcrypt::IronCryptError;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Provider that fails the first `fail_first` wrap attempts, then succeeds.
struct FlakyProvider {
    fail_first: u32,
    calls: AtomicU32,
    die_after_ok: bool,
    unwrap_calls: AtomicU32,
}

#[async_trait]
impl CryptoProvider for FlakyProvider {
    fn name(&self) -> &'static str {
        "flaky-test"
    }

    fn private_material_exportable(&self) -> bool {
        false
    }

    async fn wrap_key(
        &self,
        key_id: &str,
        plaintext_key: &[u8],
    ) -> Result<WrappedKey, IronCryptError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.fail_first {
            return Err(IronCryptError::ProviderError(
                "simulated KMS timeout mid-wrap".into(),
            ));
        }
        Ok(WrappedKey {
            key_id: key_id.to_string(),
            ciphertext: plaintext_key.to_vec(),
        })
    }

    async fn unwrap_key(
        &self,
        _key_id: &str,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        let n = self.unwrap_calls.fetch_add(1, Ordering::SeqCst);
        if self.die_after_ok && n == 0 {
            // First unwrap dies mid-op after a successful wrap elsewhere.
            return Err(IronCryptError::ProviderError(
                "simulated HSM session dropped mid-unwrap".into(),
            ));
        }
        Ok(wrapped.to_vec())
    }

    async fn encrypt(
        &self,
        _key_id: &str,
        plaintext: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        Ok(plaintext.to_vec())
    }

    async fn decrypt(
        &self,
        _key_id: &str,
        ciphertext: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        Ok(ciphertext.to_vec())
    }
}

#[tokio::test]
async fn wrap_retries_through_transient_kms_failures() {
    let provider = Arc::new(FlakyProvider {
        fail_first: 2,
        calls: AtomicU32::new(0),
        die_after_ok: false,
        unwrap_calls: AtomicU32::new(0),
    });
    let policy = RetryPolicy {
        max_attempts: 4,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
    };
    let p = provider.clone();
    let wrapped = with_retry(&policy, || {
        let p = p.clone();
        async move { p.wrap_key("kid", &[1u8; 32]).await }
    })
    .await
    .expect("should succeed after retries");
    assert_eq!(wrapped.ciphertext, vec![1u8; 32]);
    assert!(provider.calls.load(Ordering::SeqCst) >= 3);
}

#[tokio::test]
async fn unwrap_mid_op_failure_opens_circuit() {
    let provider = Arc::new(FlakyProvider {
        fail_first: 0,
        calls: AtomicU32::new(0),
        die_after_ok: true,
        unwrap_calls: AtomicU32::new(0),
    });
    let cb = CircuitBreaker::new(1, Duration::from_secs(60));
    let wrapped = provider.wrap_key("kid", &[9u8; 32]).await.unwrap();

    cb.guard().unwrap();
    let err = provider
        .unwrap_key(&wrapped.key_id, &wrapped.ciphertext)
        .await
        .unwrap_err();
    assert!(matches!(err, IronCryptError::ProviderError(_)));
    cb.record_failure();
    assert!(cb.is_open());
    assert!(cb.guard().is_err());
}

#[tokio::test]
async fn non_retryable_config_error_not_retried() {
    let n = AtomicU32::new(0);
    let policy = RetryPolicy {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
    };
    let err = with_retry(&policy, || async {
        n.fetch_add(1, Ordering::SeqCst);
        Err::<(), _>(IronCryptError::ConfigurationError("bad key id".into()))
    })
    .await
    .unwrap_err();
    assert!(matches!(err, IronCryptError::ConfigurationError(_)));
    assert_eq!(n.load(Ordering::SeqCst), 1);
}
