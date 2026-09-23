//! High-availability wrapper: try providers in order until one succeeds.
//!
//! Standby backends must be able to unwrap / decrypt ciphertexts produced by
//! the primary (multi-region KMS, replicated HSM partition, or identical key
//! material). Failover does **not** re-encrypt under a different key.

use async_trait::async_trait;
use std::sync::Arc;

use crate::crypto_provider::{CryptoProvider, WrappedKey};
use crate::IronCryptError;

/// Ordered failover pool over one or more [`CryptoProvider`] backends.
pub struct HaCryptoProvider {
    providers: Vec<Arc<dyn CryptoProvider>>,
}

impl HaCryptoProvider {
    /// At least one provider is required.
    pub fn new(providers: Vec<Arc<dyn CryptoProvider>>) -> Result<Self, IronCryptError> {
        if providers.is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "HaCryptoProvider requires at least one backend".into(),
            ));
        }
        Ok(Self { providers })
    }

    /// Number of backends in the pool.
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    async fn try_each<'a, T, F, Fut>(&'a self, op_name: &str, mut op: F) -> Result<T, IronCryptError>
    where
        F: FnMut(&'a dyn CryptoProvider) -> Fut,
        Fut: std::future::Future<Output = Result<T, IronCryptError>>,
    {
        let mut last_err: Option<IronCryptError> = None;
        for (i, p) in self.providers.iter().enumerate() {
            match op(p.as_ref()).await {
                Ok(v) => {
                    if i > 0 {
                        tracing::warn!(
                            backend = p.name(),
                            index = i,
                            "{op_name}: succeeded on failover backend"
                        );
                    }
                    return Ok(v);
                }
                Err(e) => {
                    tracing::warn!(
                        backend = p.name(),
                        index = i,
                        error = %e,
                        "{op_name}: backend failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            IronCryptError::ProviderError(format!("ha: all backends failed for {op_name}"))
        }))
    }
}

#[async_trait]
impl CryptoProvider for HaCryptoProvider {
    fn name(&self) -> &'static str {
        "ha"
    }

    fn private_material_exportable(&self) -> bool {
        self.providers
            .iter()
            .any(|p| p.private_material_exportable())
    }

    async fn wrap_key(
        &self,
        key_id: &str,
        plaintext_key: &[u8],
    ) -> Result<WrappedKey, IronCryptError> {
        self.try_each("wrap_key", |p| p.wrap_key(key_id, plaintext_key))
            .await
    }

    async fn unwrap_key(
        &self,
        key_id: &str,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        self.try_each("unwrap_key", |p| p.unwrap_key(key_id, wrapped))
            .await
    }

    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        self.try_each("encrypt", |p| p.encrypt(key_id, plaintext, aad))
            .await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        self.try_each("decrypt", |p| p.decrypt(key_id, ciphertext, aad))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::local::LocalKeyProvider;
    use crate::ecc_utils;
    use crate::keys::{PrivateKey, PublicKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Flaky {
        fail_first: AtomicUsize,
        inner: LocalKeyProvider,
    }

    #[async_trait]
    impl CryptoProvider for Flaky {
        fn name(&self) -> &'static str {
            "flaky"
        }
        fn private_material_exportable(&self) -> bool {
            true
        }
        async fn wrap_key(
            &self,
            key_id: &str,
            plaintext_key: &[u8],
        ) -> Result<WrappedKey, IronCryptError> {
            if self.fail_first.fetch_sub(1, Ordering::SeqCst) > 0 {
                return Err(IronCryptError::ProviderError("flaky".into()));
            }
            self.inner.wrap_key(key_id, plaintext_key).await
        }
        async fn unwrap_key(
            &self,
            key_id: &str,
            wrapped: &[u8],
        ) -> Result<Vec<u8>, IronCryptError> {
            self.inner.unwrap_key(key_id, wrapped).await
        }
        async fn encrypt(
            &self,
            key_id: &str,
            plaintext: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, IronCryptError> {
            self.inner.encrypt(key_id, plaintext, aad).await
        }
        async fn decrypt(
            &self,
            key_id: &str,
            ciphertext: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, IronCryptError> {
            self.inner.decrypt(key_id, ciphertext, aad).await
        }
    }

    fn local_pair(id: &str) -> LocalKeyProvider {
        let (sk, pk) = ecc_utils::generate_ecc_keys().unwrap();
        LocalKeyProvider::new(id, PublicKey::Ecc(pk), PrivateKey::Ecc(sk)).unwrap()
    }

    #[tokio::test]
    async fn failover_to_second_backend() {
        let primary = Flaky {
            fail_first: AtomicUsize::new(1),
            inner: local_pair("k1"),
        };
        // Same key material needed for unwrap — use a healthy second with its own key
        // only for wrap success path (wrap returns from whichever succeeds).
        let standby = local_pair("k1");
        // Flaky wraps with inner k1; standby also k1 but different ECC key → wrap ok on
        // either. For this test we only assert wrap succeeds via failover.
        let ha = HaCryptoProvider::new(vec![Arc::new(primary), Arc::new(standby)]).unwrap();
        // standby has key_id k1 — wrap on failover after primary fails once.
        // Wait: Flaky fail_first=1 means first wrap fails, second call on same Flaky would
        // succeed — but HA moves to standby. Standby LocalKeyProvider has key_id k1.
        let wrapped = ha.wrap_key("k1", b"0123456789abcdef0123456789abcdef").await;
        assert!(wrapped.is_ok(), "{wrapped:?}");
    }

    #[tokio::test]
    async fn rejects_empty_pool() {
        assert!(HaCryptoProvider::new(vec![]).is_err());
    }
}
