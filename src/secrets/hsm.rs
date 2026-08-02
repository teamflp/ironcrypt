#[cfg(feature = "hsm")]
mod hsm_impl {
    use crate::config::HsmConfig;
    use async_trait::async_trait;
    use pkcs11::Ctx;
    use pkcs11::types::{
        CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER, CK_ATTRIBUTE, CKA_CLASS, CKO_PRIVATE_KEY,
        CKA_LABEL, CK_LONG,
    };
    use std::error::Error;
    use std::fmt;
    use super::super::SecretStore;

    /// Custom error type for HSM operations to wrap errors from the `pkcs11` crate.
    #[derive(Debug)]
    struct HsmError(String);

    impl fmt::Display for HsmError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Error for HsmError {}

    /// Helper to convert pkcs11 errors into our custom boxed error.
    fn to_hsm_error<T: fmt::Display>(e: T) -> Box<dyn Error + Send + Sync> {
        Box::new(HsmError(e.to_string()))
    }

    /// A struct for interacting with a Hardware Security Module (HSM) via PKCS#11.
    pub struct HsmSecretStore {
        config: HsmConfig,
        /// `Ctx::new` requires a `'static` path. Leaked once here (not per call) so
        /// repeated `get_secret` calls don't leak memory on every request.
        module_path: &'static str,
    }

    impl HsmSecretStore {
        /// Creates a new HsmSecretStore.
        pub fn new(config: HsmConfig) -> Self {
            let module_path: &'static str =
                Box::leak(config.module_path.clone().into_boxed_str());
            Self { config, module_path }
        }
    }

    #[async_trait]
    impl SecretStore for HsmSecretStore {
        /// Retrieves a secret (key handle) from the HSM.
        ///
        /// This implementation connects to the HSM, finds the key object by its label,
        /// and returns its handle as a string. The connection is closed afterwards.
        async fn get_secret(&self, key_label: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
            let mut ctx = Ctx::new(self.module_path).map_err(to_hsm_error)?;

            // initialize requires a mutable reference to ctx.
            ctx.initialize(None).map_err(to_hsm_error)?;

            let slot = ctx
                .get_slot_list(true)
                .map_err(to_hsm_error)?
                .into_iter()
                .find(|s| {
                    if let Ok(info) = ctx.get_token_info(*s) {
                        let label = std::str::from_utf8(&info.label).unwrap_or("").trim();
                        label == self.config.token_label
                    } else {
                        false
                    }
                })
                .ok_or_else(|| HsmError(format!("No token with label '{}' found", self.config.token_label)))?;

            let session_handle = ctx
                .open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
                .map_err(to_hsm_error)?;

            ctx.login(session_handle, CKU_USER, Some(&self.config.pin))
                .map_err(to_hsm_error)?;

            let key_class = CKO_PRIVATE_KEY as CK_LONG;
            let template = vec![
                CK_ATTRIBUTE::new(CKA_CLASS).with_ck_long(&key_class),
                CK_ATTRIBUTE::new(CKA_LABEL).with_string(&key_label.to_string()),
            ];

            ctx.find_objects_init(session_handle, &template)
                .map_err(to_hsm_error)?;
            let objects = ctx.find_objects(session_handle, 1).map_err(to_hsm_error)?;
            ctx.find_objects_final(session_handle)
                .map_err(to_hsm_error)?;

            ctx.logout(session_handle).map_err(to_hsm_error)?;
            ctx.close_session(session_handle).map_err(to_hsm_error)?;

            let object_handle = objects.first().ok_or_else(|| {
                HsmError(format!("Key with label '{}' not found in HSM", key_label))
            })?;

            Ok(object_handle.to_string())
        }

        /// Stores a secret in the HSM.
        ///
        /// Not supported: PKCS#11 HSMs generate and hold keys internally rather than
        /// accepting arbitrary raw values, so there is no safe way to implement this
        /// the way cloud KMS/Vault backends do. Provision keys directly on the HSM
        /// with your vendor's PKCS#11 tooling instead.
        async fn set_secret(&self, _key: &str, _value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
            Err(to_hsm_error(
                "HSM set_secret is not supported: provision keys directly on the HSM via PKCS#11 tooling.",
            ))
        }
    }
}

#[cfg(feature = "hsm")]
pub use hsm_impl::*;
