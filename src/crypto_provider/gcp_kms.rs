//! Google Cloud KMS [`CryptoProvider`] (encrypt / decrypt via REST).
//!
//! Uses Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS` or
//! metadata server). Private keys never leave Cloud KMS.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    config::GcpKmsConfig,
    crypto_provider::{CryptoProvider, WrappedKey},
    IronCryptError,
};

/// GCP Cloud KMS backend.
pub struct GcpKmsProvider {
    default_key_name: String,
    http: reqwest::Client,
    token: Arc<Mutex<CachedToken>>,
    sa_path: Option<PathBuf>,
}

struct CachedToken {
    access_token: String,
    expires_at: std::time::Instant,
}

impl GcpKmsProvider {
    pub async fn new(config: &GcpKmsConfig) -> Result<Self, IronCryptError> {
        if config.default_key_name.trim().is_empty() {
            return Err(IronCryptError::ConfigurationError(
                "GcpKmsConfig.default_key_name must be a full CryptoKey resource name \
                 (projects/.../locations/.../keyRings/.../cryptoKeys/...)"
                    .into(),
            ));
        }
        let sa_path = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS").map(PathBuf::from);
        Ok(Self {
            default_key_name: config.default_key_name.clone(),
            http: reqwest::Client::new(),
            token: Arc::new(Mutex::new(CachedToken {
                access_token: String::new(),
                expires_at: std::time::Instant::now(),
            })),
            sa_path,
        })
    }

    fn resolve_key<'a>(&'a self, key_id: &'a str) -> &'a str {
        if key_id.trim().is_empty() {
            self.default_key_name.as_str()
        } else {
            key_id
        }
    }

    async fn bearer(&self) -> Result<String, IronCryptError> {
        {
            let guard = self.token.lock().await;
            if !guard.access_token.is_empty()
                && guard.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(60)
            {
                return Ok(guard.access_token.clone());
            }
        }
        let (access_token, expires_in) = self.fetch_access_token().await?;
        let mut guard = self.token.lock().await;
        guard.access_token = access_token.clone();
        guard.expires_at =
            std::time::Instant::now() + std::time::Duration::from_secs(expires_in.saturating_sub(30));
        Ok(access_token)
    }

    async fn fetch_access_token(&self) -> Result<(String, u64), IronCryptError> {
        if let Ok(tok) = std::env::var("IRONCRYPT_GCP_ACCESS_TOKEN") {
            if !tok.trim().is_empty() {
                return Ok((tok, 3600));
            }
        }
        #[cfg(feature = "rsa-algo")]
        if let Some(path) = &self.sa_path {
            return self.token_from_service_account(path).await;
        }
        #[cfg(not(feature = "rsa-algo"))]
        if self.sa_path.is_some() {
            return Err(IronCryptError::ConfigurationError(
                "gcp-kms: service-account JSON JWT requires feature `rsa-algo`; \
                 under Payment set IRONCRYPT_GCP_ACCESS_TOKEN or use GCE/GKE metadata"
                    .into(),
            ));
        }
        // GCE / GKE metadata server
        let url =
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
        let resp = self
            .http
            .get(url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| {
                IronCryptError::ConfigurationError(format!(
                    "gcp-kms: set IRONCRYPT_GCP_ACCESS_TOKEN or GOOGLE_APPLICATION_CREDENTIALS \
                     (with rsa-algo) or run on GCP (metadata: {e})"
                ))
            })?;
        if !resp.status().is_success() {
            return Err(IronCryptError::ConfigurationError(
                "gcp-kms: metadata token request failed".into(),
            ));
        }
        let body: MetadataToken = resp
            .json()
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("gcp-kms metadata json: {e}")))?;
        Ok((body.access_token, body.expires_in))
    }

    #[cfg(feature = "rsa-algo")]
    async fn token_from_service_account(
        &self,
        path: &PathBuf,
    ) -> Result<(String, u64), IronCryptError> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            IronCryptError::ConfigurationError(format!(
                "gcp-kms: read GOOGLE_APPLICATION_CREDENTIALS: {e}"
            ))
        })?;
        let sa: ServiceAccountFile = serde_json::from_str(&raw).map_err(|e| {
            IronCryptError::ConfigurationError(format!("gcp-kms: parse SA JSON: {e}"))
        })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let claim = serde_json::json!({
            "iss": sa.client_email,
            "scope": "https://www.googleapis.com/auth/cloudkms",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        });
        let assertion = sign_jwt(&sa.private_key, &claim)?;
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ];
        let resp = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&form)
            .send()
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("gcp-kms token http: {e}")))?;
        if !resp.status().is_success() {
            let t = resp.text().await.unwrap_or_default();
            return Err(IronCryptError::ProviderError(format!(
                "gcp-kms token exchange failed: {t}"
            )));
        }
        let body: OauthToken = resp
            .json()
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("gcp-kms token json: {e}")))?;
        Ok((body.access_token, body.expires_in.unwrap_or(3600)))
    }

    async fn encrypt_raw(
        &self,
        key_name: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:encrypt",
            key_name
        );
        let mut body = EncryptBody {
            plaintext: B64.encode(plaintext),
            additional_authenticated_data: None,
        };
        if let Some(aad) = aad.filter(|a| !a.is_empty()) {
            body.additional_authenticated_data = Some(B64.encode(aad));
        }
        let token = self.bearer().await?;
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("gcp-kms encrypt http: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(IronCryptError::ProviderError(format!(
                "gcp-kms encrypt: HTTP {status}: {text}"
            )));
        }
        let parsed: EncryptResponse = resp
            .json()
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("gcp-kms encrypt json: {e}")))?;
        B64.decode(parsed.ciphertext.as_bytes())
            .map_err(|e| IronCryptError::ProviderError(format!("gcp-kms ciphertext b64: {e}")))
    }

    async fn decrypt_raw(
        &self,
        key_name: &str,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:decrypt",
            key_name
        );
        let mut body = DecryptBody {
            ciphertext: B64.encode(ciphertext),
            additional_authenticated_data: None,
        };
        if let Some(aad) = aad.filter(|a| !a.is_empty()) {
            body.additional_authenticated_data = Some(B64.encode(aad));
        }
        let token = self.bearer().await?;
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("gcp-kms decrypt http: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(IronCryptError::ProviderError(format!(
                "gcp-kms decrypt: HTTP {status}: {text}"
            )));
        }
        let parsed: DecryptResponse = resp
            .json()
            .await
            .map_err(|e| IronCryptError::ProviderError(format!("gcp-kms decrypt json: {e}")))?;
        B64.decode(parsed.plaintext.as_bytes())
            .map_err(|e| IronCryptError::ProviderError(format!("gcp-kms plaintext b64: {e}")))
    }
}

#[cfg(feature = "rsa-algo")]
fn sign_jwt(pem_pkcs8: &str, claims: &serde_json::Value) -> Result<String, IronCryptError> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use sha2::Sha256;

    let header = B64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    // JWT uses base64url without padding.
    let header = header
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");
    let payload = B64
        .encode(claims.to_string().as_bytes())
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");
    let signing_input = format!("{header}.{payload}");

    let key = RsaPrivateKey::from_pkcs8_pem(pem_pkcs8).map_err(|e| {
        IronCryptError::ConfigurationError(format!("gcp-kms SA private key: {e}"))
    })?;
    let signing_key = SigningKey::<Sha256>::new_unprefixed(key);
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = B64
        .encode(sig.to_bytes())
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");
    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(feature = "rsa-algo")]
#[derive(Deserialize)]
struct ServiceAccountFile {
    client_email: String,
    private_key: String,
}

#[cfg(feature = "rsa-algo")]
#[derive(Deserialize)]
struct OauthToken {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct MetadataToken {
    access_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct EncryptBody {
    plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_authenticated_data: Option<String>,
}

#[derive(Deserialize)]
struct EncryptResponse {
    ciphertext: String,
}

#[derive(Serialize)]
struct DecryptBody {
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_authenticated_data: Option<String>,
}

#[derive(Deserialize)]
struct DecryptResponse {
    plaintext: String,
}

#[async_trait]
impl CryptoProvider for GcpKmsProvider {
    fn name(&self) -> &'static str {
        "gcp-kms"
    }

    fn private_material_exportable(&self) -> bool {
        false
    }

    async fn wrap_key(
        &self,
        key_id: &str,
        plaintext_key: &[u8],
    ) -> Result<WrappedKey, IronCryptError> {
        let kid = self.resolve_key(key_id);
        let ciphertext = self.encrypt_raw(kid, plaintext_key, None).await?;
        Ok(WrappedKey {
            key_id: kid.to_string(),
            ciphertext,
        })
    }

    async fn unwrap_key(
        &self,
        key_id: &str,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, IronCryptError> {
        let kid = self.resolve_key(key_id);
        self.decrypt_raw(kid, wrapped, None).await
    }

    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let kid = self.resolve_key(key_id);
        self.encrypt_raw(kid, plaintext, aad).await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, IronCryptError> {
        let kid = self.resolve_key(key_id);
        self.decrypt_raw(kid, ciphertext, aad).await
    }
}
