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
    }

    impl HsmSecretStore {
        /// Creates a new HsmSecretStore.
        pub fn new(config: HsmConfig) -> Self {
            Self { config }
        }
    }

    #[async_trait]
    impl SecretStore for HsmSecretStore {
        /// Retrieves a secret (key handle) from the HSM.
        ///
        /// This implementation connects to the HSM, finds the key object by its label,
        /// and returns its handle as a string. The connection is closed afterwards.
        async fn get_secret(&self, key_label: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
            // Ctx::new requires a 'static path. We can achieve this by leaking a cloned string.
            // This is an accepted pattern for loading dynamic libraries that must live for the
            // duration of the program.
            let static_path: &'static str = Box::leak(self.config.module_path.clone().into_boxed_str());
            let mut ctx = Ctx::new(static_path).map_err(to_hsm_error)?;

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

            let object_handle = objects.get(0).ok_or_else(|| {
                HsmError(format!("Key with label '{}' not found in HSM", key_label))
            })?;

            Ok(object_handle.to_string())
        }

        /// Stores a secret (generates a key pair) in the HSM.
        async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
            unimplemented!("HSM set_secret is not yet implemented. Key: {}, Value: {}", key, value);
        }
    }
}

#[cfg(feature = "hsm")]
pub use hsm_impl::*;
