//! In-device PKCS#11 [`CryptoProvider`] backed by the maintained `cryptoki` crate.
//!
//! Private/secret key material never leaves the HSM. Operations use
//! `CKM_AES_CBC_PAD` on a token AES secret key identified by label.
//!
//! PIN resolution order: `HsmCryptoConfig.pin` → env `IRONCRYPT_HSM_PIN`.
//! Prefer injecting the PIN via the environment (never commit it to TOML).
//!
//! Sessions are pooled (`max_sessions`, default 4) so concurrent wrap/unwrap
//! can proceed without opening a fresh login for every call.

use async_trait::async_trait;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use rand::{rngs::OsRng, RngCore};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use crate::{
    config::HsmCryptoConfig,
    crypto_provider::{CryptoProvider, WrappedKey},
    IronCryptError,
};

const AES_IV_LEN: usize = 16;
const DEFAULT_MAX_SESSIONS: usize = 4;
const MAX_SESSIONS_CAP: usize = 32;

/// PKCS#11 HSM provider — encrypt/decrypt/wrap inside the module.
pub struct HsmProvider {
    pkcs11: Pkcs11,
    slot: cryptoki::slot::Slot,
    pin: AuthPin,
    default_key_label: String,
    pool: SessionPool,
}

struct SessionPool {
    available: Mutex<VecDeque<Session>>,
    cond: Condvar,
    created: AtomicUsize,
    max: usize,
}

impl SessionPool {
    fn new(max: usize) -> Self {
        Self {
            available: Mutex::new(VecDeque::new()),
            cond: Condvar::new(),
            created: AtomicUsize::new(0),
            max: max.clamp(1, MAX_SESSIONS_CAP),
        }
    }

    fn checkout<F>(&self, create: F) -> Result<Session, IronCryptError>
    where
        F: FnOnce() -> Result<Session, IronCryptError>,
    {
        let mut guard = self
            .available
            .lock()
            .map_err(|_| IronCryptError::ProviderError("hsm session pool poisoned".into()))?;
        loop {
            if let Some(session) = guard.pop_front() {
                return Ok(session);
            }
            let created = self.created.load(Ordering::SeqCst);
            if created < self.max {
                // Reserve a slot before dropping the lock to create.
                self.created.fetch_add(1, Ordering::SeqCst);
                drop(guard);
                match create() {
                    Ok(s) => return Ok(s),
                    Err(e) => {
                        self.created.fetch_sub(1, Ordering::SeqCst);
                        return Err(e);
                    }
                }
            }
            let (g, timeout) = self
                .cond
                .wait_timeout(guard, Duration::from_secs(30))
                .map_err(|_| IronCryptError::ProviderError("hsm session pool poisoned".into()))?;
            guard = g;
            if timeout.timed_out() && guard.is_empty() {
                return Err(IronCryptError::ProviderError(
                    "hsm: timed out waiting for a free PKCS#11 session".into(),
                ));
            }
        }
    }

    fn checkin(&self, session: Session) {
        let mut guard = self
            .available
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.push_back(session);
        self.cond.notify_one();
    }
}

impl Drop for HsmProvider {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.pool.available.lock() {
            while let Some(session) = guard.pop_front() {
                let _ = session.logout();
                // Session Drop closes the handle.
                drop(session);
            }
        }
    }
}

impl HsmProvider {
    /// Initialize the PKCS#11 module, locate the token by label, and prepare login.
    pub fn new(config: &HsmCryptoConfig) -> Result<Self, IronCryptError> {
        if config.module_path.trim().is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "HsmCryptoConfig.module_path must be set".into(),
            ));
        }
        if config.default_key_label.trim().is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "HsmCryptoConfig.default_key_label must be set".into(),
            ));
        }

        let pin_str = config
            .pin
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("IRONCRYPT_HSM_PIN").ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                IronCryptError::ConfigurationError(
                    "HSM PIN missing: set HsmCryptoConfig.pin or IRONCRYPT_HSM_PIN".into(),
                )
            })?;

        let pkcs11 = Pkcs11::new(&config.module_path).map_err(map_ck)?;
        // Ignore already-initialized (SoftHSM / multi-provider same process).
        match pkcs11.initialize(CInitializeArgs::OsThreads) {
            Ok(()) => {}
            Err(e) => {
                let msg = e.to_string();
                if !msg.contains("CRYPTOKI_ALREADY_INITIALIZED")
                    && !msg.contains("CKR_CRYPTOKI_ALREADY_INITIALIZED")
                {
                    return Err(map_ck(e));
                }
            }
        }

        let max_sessions = if config.max_sessions == 0 {
            DEFAULT_MAX_SESSIONS
        } else {
            config.max_sessions as usize
        };

        let slot = find_slot_by_label(&pkcs11, &config.token_label)?;
        Ok(Self {
            pkcs11,
            slot,
            pin: AuthPin::new(pin_str.into()),
            default_key_label: config.default_key_label.clone(),
            pool: SessionPool::new(max_sessions),
        })
    }

    fn resolve_label<'a>(&'a self, key_id: &'a str) -> &'a str {
        if key_id.is_empty() {
            self.default_key_label.as_str()
        } else {
            key_id
        }
    }

    fn open_logged_in_session(&self) -> Result<Session, IronCryptError> {
        let session = self
            .pkcs11
            .open_rw_session(self.slot)
            .map_err(map_ck)?;
        session
            .login(UserType::User, Some(&self.pin))
            .map_err(map_ck)?;
        Ok(session)
    }

    fn with_session<F, T>(&self, f: F) -> Result<T, IronCryptError>
    where
        F: FnOnce(&Session) -> Result<T, IronCryptError>,
    {
        let session = self.pool.checkout(|| self.open_logged_in_session())?;
        let result = f(&session);
        self.pool.checkin(session);
        result
    }

    fn find_aes_key(session: &Session, label: &str) -> Result<ObjectHandle, IronCryptError> {
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let found = session.find_objects(&template).map_err(map_ck)?;
        found.into_iter().next().ok_or_else(|| {
            IronCryptError::ProviderError(format!(
                "hsm: no AES secret key with label '{label}' (CKO_SECRET_KEY / CKK_AES)"
            ))
        })
    }

    fn encrypt_aes(
        session: &Session,
        key: ObjectHandle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        let mut iv = [0u8; AES_IV_LEN];
        OsRng.fill_bytes(&mut iv);
        let mechanism = Mechanism::AesCbcPad(iv);
        let ciphertext = session.encrypt(&mechanism, key, plaintext).map_err(map_ck)?;
        let mut out = Vec::with_capacity(AES_IV_LEN + ciphertext.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decrypt_aes(
        session: &Session,
        key: ObjectHandle,
        blob: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        if blob.len() <= AES_IV_LEN {
            return Err(IronCryptError::DecryptionError(
                "hsm ciphertext too short (missing IV)".into(),
            ));
        }
        let mut iv = [0u8; AES_IV_LEN];
        iv.copy_from_slice(&blob[..AES_IV_LEN]);
        let ct = &blob[AES_IV_LEN..];
        let mechanism = Mechanism::AesCbcPad(iv);
        session.decrypt(&mechanism, key, ct).map_err(map_ck)
    }
}

fn find_slot_by_label(
    pkcs11: &Pkcs11,
    token_label: &str,
) -> Result<cryptoki::slot::Slot, IronCryptError> {
    let slots = pkcs11.get_slots_with_token().map_err(map_ck)?;
    for slot in slots {
        if let Ok(info) = pkcs11.get_token_info(slot) {
            let label = info.label().trim();
            if label == token_label {
                return Ok(slot);
            }
        }
    }
    Err(IronCryptError::ConfigurationError(format!(
        "hsm: no token with label '{token_label}'"
    )))
}

fn map_ck(err: impl std::fmt::Display) -> IronCryptError {
    IronCryptError::ProviderError(format!("hsm/pkcs11: {err}"))
}

#[async_trait]
impl CryptoProvider for HsmProvider {
    fn name(&self) -> &'static str {
        "hsm"
    }

    fn private_material_exportable(&self) -> bool {
        false
    }

    async fn wrap_key(
        &self,
        key_id: &str,
        plaintext_key: &[u8],
    ) -> Result<WrappedKey, IronCryptError> {
        let label = self.resolve_label(key_id).to_string();
        let ciphertext = self.with_session(|session| {
            let key = Self::find_aes_key(session, &label)?;
            Self::encrypt_aes(session, key, plaintext_key)
        })?;
        Ok(WrappedKey {
            key_id: label,
            ciphertext,
        })
    }

    async fn unwrap_key(
        &self,
        key_id: &str,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        let label = self.resolve_label(key_id).to_string();
        self.with_session(|session| {
            let key = Self::find_aes_key(session, &label)?;
            Self::decrypt_aes(session, key, wrapped)
        })
    }

    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        if aad.map(|a| !a.is_empty()).unwrap_or(false) {
            return Err(IronCryptError::UnsupportedOperation(
                "hsm provider: AAD is not supported with AES-CBC-PAD; use aws-kms/vault-transit \
                 for AAD binding, or omit aad"
                    .into(),
            ));
        }
        let label = self.resolve_label(key_id).to_string();
        self.with_session(|session| {
            let key = Self::find_aes_key(session, &label)?;
            Self::encrypt_aes(session, key, plaintext)
        })
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        if aad.map(|a| !a.is_empty()).unwrap_or(false) {
            return Err(IronCryptError::UnsupportedOperation(
                "hsm provider: AAD is not supported with AES-CBC-PAD".into(),
            ));
        }
        let label = self.resolve_label(key_id).to_string();
        self.with_session(|session| {
            let key = Self::find_aes_key(session, &label)?;
            Self::decrypt_aes(session, key, ciphertext)
        })
    }
}
