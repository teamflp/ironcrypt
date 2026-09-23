use axum::{
    body::{Body, Bytes},
    error_handling::HandleErrorLayer,
    extract::{connect_info::ConnectInfo, DefaultBodyLimit, Extension, Path, State},
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    BoxError, Json, Router,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::Parser;
use elliptic_curve::subtle::ConstantTimeEq;
use futures::TryStreamExt;
use hmac::{Hmac, Mac};
use ironcrypt::{
    audit::{sanitize_error_message, sanitize_secret_name, AuditEvent, Operation, Outcome},
    auth::{ApiKeyConfig, AuthenticatedPrincipal, Permission},
    config::IronCryptConfig,
    context::EncryptionContext,
    crypto_provider::{self, CryptoProvider},
    decrypt_stream, encrypt_stream_with_context,
    encrypt::{
        decrypt_stream_with_dek, encrypt_stream_with_dek, find_recipient, RecipientInfo,
        StreamHeader,
    },
    keys::{PrivateKey, PublicKey},
    limits::{
        DEFAULT_CIRCUIT_COOLDOWN_SECS, DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
        DEFAULT_CRYPTO_CONCURRENCY, DEFAULT_HTTP_BODY_LIMIT, DEFAULT_PROVIDER_TIMEOUT_SECS,
        DEFAULT_REQUEST_TIMEOUT_SECS, MAX_STREAM_HEADER_SIZE,
    },
    load_any_private_key, load_any_public_key,
    payment::PaymentSecurityProfile,
    rate_limit::{self, RateLimiter},
    resilience::{
        with_retry, with_timeout, CircuitBreaker, RetryPolicy, DEFAULT_PROVIDER_MAX_ATTEMPTS,
    },
    secrets::SecretStore,
    Argon2Config, IronCryptError,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime},
};
use tokio::io::{AsyncRead, AsyncReadExt, duplex};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::io::{ReaderStream, StreamReader, SyncIoBridge};
use tower::{timeout::TimeoutLayer, ServiceBuilder};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::{DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{
    filter::{self, LevelFilter},
    prelude::*,
    util::SubscriberInitExt,
    Layer,
};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// Hot-reloadable TLS acceptor (SIGHUP / mtime poll).
#[derive(Clone)]
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
    acceptor: Arc<RwLock<tokio_rustls::TlsAcceptor>>,
    last_ok: Arc<Mutex<Option<SystemTime>>>,
    last_err: Arc<Mutex<Option<String>>>,
}

impl TlsMaterial {
    fn load(
        cert: PathBuf,
        key: PathBuf,
        client_ca: Option<PathBuf>,
    ) -> Result<Self, String> {
        let cfg = load_rustls_server_config(&cert, &key, client_ca.as_deref())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        Ok(Self {
            cert,
            key,
            client_ca,
            acceptor: Arc::new(RwLock::new(acceptor)),
            last_ok: Arc::new(Mutex::new(Some(SystemTime::now()))),
            last_err: Arc::new(Mutex::new(None)),
        })
    }

    fn reload(&self) -> Result<(), String> {
        match load_rustls_server_config(&self.cert, &self.key, self.client_ca.as_deref()) {
            Ok(cfg) => {
                let next = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
                *self.acceptor.write().unwrap_or_else(|e| e.into_inner()) = next;
                *self.last_ok.lock().unwrap_or_else(|e| e.into_inner()) = Some(SystemTime::now());
                *self.last_err.lock().unwrap_or_else(|e| e.into_inner()) = None;
                tracing::info!(
                    "TLS material reloaded from {} / {}",
                    self.cert.display(),
                    self.key.display()
                );
                Ok(())
            }
            Err(e) => {
                *self.last_err.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.clone());
                tracing::error!("TLS reload failed: {e}");
                Err(e)
            }
        }
    }

    fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        self.acceptor
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Shared application state.
#[derive(Clone)]
struct AppState {
    /// Local keys — absent in CryptoProvider-only mode.
    public_key: Option<Arc<PublicKey>>,
    private_key: Option<Arc<PrivateKey>>,
    /// Remote / HSM provider for DEK wrap (preferred when set).
    crypto_provider: Option<Arc<dyn CryptoProvider>>,
    key_version: String,
    config: Arc<IronCryptConfig>,
    api_keys: Arc<RwLock<Vec<ApiKeyConfig>>>,
    /// Source used for SIGHUP / mtime reload of the catalog.
    api_key_store: Arc<dyn ironcrypt::ApiKeyStore>,
    /// When file-backed, path used for mtime polling.
    api_keys_path: Option<PathBuf>,
    secret_stores: Arc<HashMap<String, Arc<dyn SecretStore + Send + Sync>>>,
    rate_limiter: Arc<dyn RateLimiter>,
    /// Bounds concurrent `spawn_blocking` crypto work.
    crypto_sem: Arc<Semaphore>,
    /// Opens after consecutive CryptoProvider failures.
    provider_circuit: Arc<CircuitBreaker>,
    /// Wall-clock budget for one KMS/HSM/Vault wrap/unwrap.
    provider_timeout: Duration,
    /// Controlled retry for transient provider faults.
    provider_retry: RetryPolicy,
    /// Bounded by `DefaultBodyLimit`; retained for future stream byte accounting.
    #[allow(dead_code)]
    max_body_bytes: usize,
    /// Present when serving HTTPS (shared with admin `/tls` status).
    tls: Option<TlsMaterial>,
}

/// Command-line arguments for the daemon.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 3000)]
    port: u16,

    /// Host to listen on (default: loopback)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Directory where keys are stored
    #[arg(short = 'd', long, default_value = "keys")]
    key_directory: String,

    /// Key version to use (e.g., "v1")
    #[arg(short = 'v', long)]
    key_version: String,

    /// Passphrase for the private key (prefer IRONCRYPT_PASSPHRASE_FILE over argv).
    #[arg(
        long,
        env = "IRONCRYPT_PASSPHRASE",
        help = "Private key passphrase. Prefer IRONCRYPT_PASSPHRASE_FILE in Payment (avoid argv)."
    )]
    passphrase: Option<String>,

    /// Path to the JSON file containing API key configurations (backend=file).
    #[arg(long, env = "IRONCRYPT_API_KEYS_FILE", default_value = "keys.json")]
    api_keys_file: String,

    /// API key catalog backend: `file` (keys.json) or `env` (`IRONCRYPT_API_KEYS_JSON`).
    #[arg(long, env = "IRONCRYPT_API_KEYS_BACKEND", default_value = "file")]
    api_keys_backend: String,

    /// Poll API keys file mtime every N seconds (`0` = SIGHUP only). Ignored for `env`.
    #[arg(long, env = "IRONCRYPT_API_KEYS_RELOAD_POLL_SECS", default_value_t = 0)]
    api_keys_reload_poll_secs: u64,

    /// Path to the TOML configuration file.
    #[arg(long, env = "IRONCRYPT_CONFIG_FILE")]
    config: String,

    /// Comma-separated list of allowed CORS origins. Empty = CORS disabled (fail-closed).
    #[arg(long, env = "IRONCRYPT_CORS_ORIGINS", default_value = "")]
    cors_origins: String,

    /// Max requests per second (global). Set 0 to disable.
    #[arg(long, env = "IRONCRYPT_RATE_LIMIT_PER_SEC", default_value_t = 20)]
    rate_limit_per_sec: u32,

    /// Burst size for the rate limiter (requests allowed per 1s window).
    #[arg(long, env = "IRONCRYPT_RATE_LIMIT_BURST", default_value_t = 40)]
    rate_limit_burst: u32,

    /// Rate-limit backend: `memory` (default) or `redis` (feature `redis-rate-limit`).
    #[arg(long, env = "IRONCRYPT_RATE_LIMIT_BACKEND", default_value = "memory")]
    rate_limit_backend: String,

    /// Redis URL when `--rate-limit-backend redis` (e.g. `redis://127.0.0.1:6379/`).
    #[arg(long, env = "IRONCRYPT_REDIS_URL")]
    redis_url: Option<String>,

    /// Optional TLS certificate PEM path. When set with --tls-key, the daemon
    /// serves HTTPS in-process via rustls.
    #[arg(long, env = "IRONCRYPT_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Optional TLS private key PEM path (must be paired with --tls-cert).
    #[arg(long, env = "IRONCRYPT_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Optional path to a PEM bundle of trusted client CAs. When set with TLS,
    /// enables mTLS (client certificate required).
    #[arg(long, env = "IRONCRYPT_TLS_CLIENT_CA")]
    tls_client_ca: Option<PathBuf>,

    /// Maximum request body size in bytes (default 16 MiB).
    #[arg(long, env = "IRONCRYPT_MAX_BODY_BYTES", default_value_t = DEFAULT_HTTP_BODY_LIMIT)]
    max_body_bytes: usize,

    /// Max concurrent crypto operations (`spawn_blocking` slots).
    #[arg(
        long,
        env = "IRONCRYPT_MAX_CRYPTO_CONCURRENCY",
        default_value_t = DEFAULT_CRYPTO_CONCURRENCY
    )]
    max_crypto_concurrency: usize,

    /// Wall-clock timeout for each HTTP request (seconds).
    #[arg(
        long,
        env = "IRONCRYPT_REQUEST_TIMEOUT_SECS",
        default_value_t = DEFAULT_REQUEST_TIMEOUT_SECS
    )]
    request_timeout_secs: u64,

    /// Timeout for a single CryptoProvider wrap/unwrap (seconds).
    #[arg(
        long,
        env = "IRONCRYPT_PROVIDER_TIMEOUT_SECS",
        default_value_t = DEFAULT_PROVIDER_TIMEOUT_SECS
    )]
    provider_timeout_secs: u64,

    /// Consecutive CryptoProvider failures before the circuit opens.
    #[arg(
        long,
        env = "IRONCRYPT_CIRCUIT_FAILURE_THRESHOLD",
        default_value_t = DEFAULT_CIRCUIT_FAILURE_THRESHOLD
    )]
    circuit_failure_threshold: u32,

    /// Circuit cool-down when open (seconds).
    #[arg(
        long,
        env = "IRONCRYPT_CIRCUIT_COOLDOWN_SECS",
        default_value_t = DEFAULT_CIRCUIT_COOLDOWN_SECS
    )]
    circuit_cooldown_secs: u64,

    /// Max attempts for a CryptoProvider wrap/unwrap (transient faults only).
    #[arg(
        long,
        env = "IRONCRYPT_PROVIDER_MAX_ATTEMPTS",
        default_value_t = DEFAULT_PROVIDER_MAX_ATTEMPTS
    )]
    provider_max_attempts: u32,

    /// Explicitly allow plain HTTP when TLS is not configured. Forbidden when
    /// the `payment` feature is enabled (except loopback lab binds are still
    /// rejected under Payment — TLS is mandatory).
    #[arg(long, env = "IRONCRYPT_ALLOW_INSECURE_HTTP", default_value_t = false)]
    allow_insecure_http: bool,

    /// Admin listener port (`0` = disabled). Serves `/health`, `/ready`, `/tls`
    /// without API-key auth. Bind to loopback only in production.
    #[arg(long, env = "IRONCRYPT_ADMIN_PORT", default_value_t = 0)]
    admin_port: u16,

    /// Admin listener host (default loopback).
    #[arg(long, env = "IRONCRYPT_ADMIN_HOST", default_value = "127.0.0.1")]
    admin_host: String,

    /// Poll TLS PEM mtime every N seconds (`0` = SIGHUP only). Complements
    /// certificate rotation without process restart.
    #[arg(long, env = "IRONCRYPT_TLS_RELOAD_POLL_SECS", default_value_t = 0)]
    tls_reload_poll_secs: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    ironcrypt::metrics::init_metrics();

    let tls_mode = match (&args.tls_cert, &args.tls_key) {
        (Some(_), Some(_)) => true,
        (None, None) => false,
        _ => {
            eprintln!("Both --tls-cert and --tls-key must be provided together.");
            return;
        }
    };

    if PaymentSecurityProfile::require_tls() && !tls_mode {
        eprintln!(
            "Payment profile requires TLS. Provide --tls-cert and --tls-key \
             (plain HTTP is forbidden when built with `--features payment`)."
        );
        return;
    }

    if !tls_mode
        && !args.allow_insecure_http
        && args.host != "127.0.0.1"
        && args.host != "localhost"
        && args.host != "::1"
    {
        eprintln!(
            "Refusing to bind plain HTTP on non-loopback host '{}' without TLS. \
             Provide --tls-cert/--tls-key, bind to 127.0.0.1, or pass \
             --allow-insecure-http for lab use only.",
            args.host
        );
        return;
    }

    let mut config = match IronCryptConfig::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load config file at {}: {}", args.config, e);
            return;
        }
    };

    if PaymentSecurityProfile::is_enabled() {
        if let Err(e) = PaymentSecurityProfile::enforce(&mut config) {
            eprintln!("Payment security profile rejected configuration: {e}");
            return;
        }
    }

    let stdout_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(io::stdout)
        .with_filter(LevelFilter::INFO)
        .with_filter(filter::filter_fn(|metadata| metadata.target() != "audit"));

    let mut _guard = None;
    let audit_layer = if let Some(audit_config) = &config.audit {
        if audit_config.retention_days > 0 {
            match ironcrypt::purge_expired_audit_segments(
                std::path::Path::new(audit_config.rolling_directory()),
                audit_config.retention_days,
            ) {
                Ok(n) if n > 0 => tracing::info!("Purged {n} expired audit segment(s)"),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    "audit retention purge failed: {}",
                    sanitize_error_message(&e)
                ),
            }
        }
        let file_appender =
            tracing_appender::rolling::daily(audit_config.rolling_directory(), "audit.log");
        let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);
        _guard = Some(guard);

        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(non_blocking_writer)
            .with_filter(LevelFilter::INFO)
            .with_filter(filter::filter_fn(|metadata| metadata.target() == "audit"));

        Some(Box::new(layer) as Box<dyn Layer<_> + Send + Sync>)
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(audit_layer)
        .init();

    let backend = match ironcrypt::ApiKeyBackend::parse(&args.api_keys_backend) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };
    let api_key_store: Arc<dyn ironcrypt::ApiKeyStore> =
        match ironcrypt::build_api_key_store(backend, &args.api_keys_file) {
            Ok(s) => Arc::from(s),
            Err(e) => {
                eprintln!("API key store: {e}");
                return;
            }
        };
    let api_keys = match api_key_store.load() {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("Failed to load API keys: {e}");
            return;
        }
    };
    let api_keys_path = match backend {
        ironcrypt::ApiKeyBackend::File => Some(PathBuf::from(&args.api_keys_file)),
        ironcrypt::ApiKeyBackend::Env => None,
    };
    tracing::info!(
        "loaded {} API key(s) via backend={:?}",
        api_keys.len(),
        args.api_keys_backend
    );

    let public_key_path = format!("{}/public_key_{}.pem", args.key_directory, args.key_version);
    let private_key_path = format!("{}/private_key_{}.pem", args.key_directory, args.key_version);

    if let Ok(Some(manifest)) = ironcrypt::key_lifecycle::load_keyring(&args.key_directory) {
        let report = manifest.rotation_report(
            chrono::Utc::now(),
            &ironcrypt::key_lifecycle::RotationPolicy::default(),
        );
        if report.rotation_due {
            tracing::warn!(
                key_id = %report.key_id,
                active = %report.active_version,
                suggested = ?report.suggested_next_version,
                "keyring rotation due — run `ironcrypt keyring-status` / rotate-key"
            );
        } else {
            tracing::info!(
                key_id = %report.key_id,
                active = %report.active_version,
                "keyring OK (rotation not due)"
            );
        }
    }

    let crypto_provider = if let Some(cp_cfg) = &config.crypto_provider {
        match crypto_provider::build_from_config(cp_cfg).await {
            Ok(p) => {
                tracing::info!("CryptoProvider '{}' ready for DEK wrap", p.name());
                Some(Arc::from(p))
            }
            Err(e) => {
                eprintln!("Failed to initialize crypto_provider: {e}");
                return;
            }
        }
    } else {
        None
    };

    let (public_key, private_key) = if crypto_provider.is_some() {
        if PaymentSecurityProfile::is_enabled() {
            let pem_hint = std::path::Path::new(&private_key_path);
            if pem_hint.exists() {
                tracing::warn!(
                    "Payment + CryptoProvider: local private key file {} is present but unused — \
                     do not mount PEM key directories on Payment instances",
                    private_key_path
                );
            }
        }
        (None, None)
    } else {
        let public_key = match load_any_public_key(&public_key_path) {
            Ok(key) => {
                if let Err(e) = PaymentSecurityProfile::ensure_ecc_public(&key) {
                    eprintln!("{e}");
                    return;
                }
                Arc::new(key)
            }
            Err(e) => {
                eprintln!("Failed to load public key from {}: {}", public_key_path, e);
                return;
            }
        };
        let passphrase = match ironcrypt::resolve_passphrase(args.passphrase.clone()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to resolve passphrase: {e}");
                return;
            }
        };
        let private_key = match load_any_private_key(
            &private_key_path,
            ironcrypt::passphrase_as_str(&passphrase),
        ) {
            Ok(key) => {
                if let Err(e) = PaymentSecurityProfile::ensure_ecc_private(&key) {
                    eprintln!("{e}");
                    return;
                }
                Arc::new(key)
            }
            Err(e) => {
                eprintln!("Failed to load private key from {}: {}", private_key_path, e);
                return;
            }
        };
        (Some(public_key), Some(private_key))
    };

    // `mut` is only exercised when at least one cloud/HSM secrets feature is enabled.
    #[allow(unused_mut)]
    let mut secret_stores: HashMap<String, Arc<dyn SecretStore + Send + Sync>> = HashMap::new();
    #[cfg(any(feature = "aws", feature = "azure", feature = "vault", feature = "gcp"))]
    if let Some(secrets_config) = &config.secrets {
        #[cfg(feature = "aws")]
        if let Some(aws_config) = &secrets_config.aws {
            match ironcrypt::secrets::aws::AwsStore::new(aws_config).await {
                Ok(store) => {
                    secret_stores.insert("aws".to_string(), Arc::new(store));
                    tracing::info!("Initialized AWS Secrets Manager store.");
                }
                Err(e) => tracing::error!("Failed to initialize AWS store: {}", e),
            }
        }

        #[cfg(feature = "azure")]
        if let Some(azure_config) = &secrets_config.azure {
            match ironcrypt::secrets::azure::AzureStore::new(azure_config).await {
                Ok(store) => {
                    secret_stores.insert("azure".to_string(), Arc::new(store));
                    tracing::info!("Initialized Azure Key Vault store.");
                }
                Err(e) => tracing::error!("Failed to initialize Azure store: {}", e),
            }
        }

        #[cfg(feature = "vault")]
        if let Some(vault_config) = &secrets_config.vault {
            match ironcrypt::secrets::vault::VaultStore::new(vault_config, &vault_config.mount) {
                Ok(store) => {
                    secret_stores.insert("vault".to_string(), Arc::new(store));
                    tracing::info!("Initialized HashiCorp Vault store.");
                }
                Err(e) => tracing::error!("Failed to initialize Vault store: {}", e),
            }
        }

        #[cfg(feature = "gcp")]
        if let Some(google_config) = &secrets_config.google {
            match ironcrypt::secrets::google::GoogleStore::new(google_config).await {
                Ok(store) => {
                    secret_stores.insert("gcp".to_string(), Arc::new(store));
                    tracing::info!("Initialized Google Secret Manager store.");
                }
                Err(e) => tracing::error!("Failed to initialize GCP store: {}", e),
            }
        }
    }

    let crypto_slots = args.max_crypto_concurrency.max(1);

    // Load TLS early so AppState / admin can report status and SIGHUP can reload.
    let tls_material = if tls_mode {
        let cert = args.tls_cert.clone().expect("tls_mode guarantees cert");
        let key = args.tls_key.clone().expect("tls_mode guarantees key");
        match TlsMaterial::load(cert, key, args.tls_client_ca.clone()) {
            Ok(m) => Some(m),
            Err(e) => {
                tracing::error!("Failed to load TLS certificate/key: {}", e);
                return;
            }
        }
    } else {
        None
    };

    let rate_limiter = match rate_limit::build_rate_limiter(
        &args.rate_limit_backend,
        args.redis_url.as_deref(),
        args.rate_limit_per_sec,
        args.rate_limit_burst,
    ) {
        Ok(rl) => {
            tracing::info!(
                backend = %args.rate_limit_backend,
                per_sec = args.rate_limit_per_sec,
                burst = args.rate_limit_burst,
                "rate limiter ready"
            );
            rl
        }
        Err(e) => {
            eprintln!("Failed to initialize rate limiter: {e}");
            return;
        }
    };

    let state = AppState {
        public_key,
        private_key,
        crypto_provider,
        key_version: args.key_version.clone(),
        config: Arc::new(config),
        api_keys: Arc::new(RwLock::new(api_keys)),
        api_key_store,
        api_keys_path,
        secret_stores: Arc::new(secret_stores),
        rate_limiter,
        crypto_sem: Arc::new(Semaphore::new(crypto_slots)),
        provider_circuit: Arc::new(CircuitBreaker::new(
            args.circuit_failure_threshold,
            Duration::from_secs(args.circuit_cooldown_secs.max(1)),
        )),
        provider_timeout: Duration::from_secs(args.provider_timeout_secs.max(1)),
        provider_retry: RetryPolicy {
            max_attempts: args.provider_max_attempts.max(1),
            ..RetryPolicy::default()
        },
        max_body_bytes: args.max_body_bytes,
        tls: tls_material.clone(),
    };

    let cors_layer = build_cors_layer(&args.cors_origins);
    let request_timeout = Duration::from_secs(args.request_timeout_secs.max(1));

    // Crypto listener: /write, /read (+ optional secret routes).
    let mut app = Router::new()
        .route("/write", post(write_handler))
        .route("/read", post(read_handler))
        // Use-secret: HMAC over body with vault secret — never returns the secret.
        .route(
            "/service/:service_name/secret/:secret_key/hmac",
            post(hmac_secret_handler),
        );

    if PaymentSecurityProfile::allow_plaintext_secret_http() {
        app = app.route(
            "/service/:service_name/secret/:secret_key",
            get(get_secret_handler).post(set_secret_handler),
        );
    } else {
        tracing::warn!(
            "Payment profile: plaintext secret HTTP GET/POST disabled; \
             use POST .../hmac (use-secret) instead of exporting secrets"
        );
    }

    let app = app
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state.clone())
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|err: BoxError| async move {
                    if err.is::<tower::timeout::error::Elapsed>() {
                        StatusCode::REQUEST_TIMEOUT
                    } else {
                        tracing::error!("unhandled middleware error: {err}");
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                }))
                .layer(TimeoutLayer::new(request_timeout)),
        )
        .layer(TraceLayer::new_for_http()
            .make_span_with(|req: &Request<_>| {
                // Never put Authorization / X-Password into span fields.
                let request_id = req
                    .headers()
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-");
                tracing::info_span!(
                    "http",
                    method = %req.method(),
                    path = %req.uri().path(),
                    request_id = %request_id,
                )
            })
            .on_response(DefaultOnResponse::new().level(Level::INFO))
            .on_failure(DefaultOnFailure::new().level(Level::WARN)))
        .layer(cors_layer)
        .layer(DefaultBodyLimit::max(args.max_body_bytes));

    let host_addr: std::net::IpAddr = match args.host.parse() {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!("Invalid host address provided '{}': {}", args.host, e);
            return;
        }
    };

    let addr = SocketAddr::new(host_addr, args.port);
    tracing::info!(
        "crypto listener on {} ({})",
        addr,
        if tls_mode { "HTTPS" } else { "HTTP" }
    );

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to address {}: {}", addr, e);
            return;
        }
    };

    // Admin listener (optional): health / ready / tls — no API key.
    if args.admin_port != 0 {
        if PaymentSecurityProfile::is_enabled()
            && args.admin_host != "127.0.0.1"
            && args.admin_host != "localhost"
            && args.admin_host != "::1"
        {
            tracing::error!(
                "Payment profile: admin listener must bind loopback \
                 (got host '{}')",
                args.admin_host
            );
            return;
        }
        let admin_ip: std::net::IpAddr = match args.admin_host.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("Invalid admin host '{}': {}", args.admin_host, e);
                return;
            }
        };
        let admin_addr = SocketAddr::new(admin_ip, args.admin_port);
        match TcpListener::bind(&admin_addr).await {
            Ok(admin_listener) => {
                tracing::info!("admin listener on {} (HTTP, no auth)", admin_addr);
                let admin_state = state.clone();
                tokio::spawn(async move {
                    let admin_app = Router::new()
                        .route("/health", get(admin_health))
                        .route("/ready", get(admin_ready))
                        .route("/tls", get(admin_tls_status))
                        .with_state(admin_state);
                    if let Err(e) = axum::serve(admin_listener, admin_app).await {
                        tracing::error!("admin listener error: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::error!("Failed to bind admin listener {}: {}", admin_addr, e);
                return;
            }
        }
    }

    if let Some(ref tls) = tls_material {
        spawn_tls_reload_watchers(tls.clone(), args.tls_reload_poll_secs);
        spawn_api_keys_reload_watchers(state.clone(), args.api_keys_reload_poll_secs);
        if let Err(e) = serve_https(listener, app, tls.clone()).await {
            tracing::error!("HTTPS server error: {}", e);
        }
    } else {
        spawn_api_keys_reload_watchers(state.clone(), args.api_keys_reload_poll_secs);
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("HTTP server error: {}", e);
        }
    }
}

fn spawn_api_keys_reload_watchers(state: AppState, poll_secs: u64) {
    #[cfg(unix)]
    {
        let state_sighup = state.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut hangup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("API keys SIGHUP watcher unavailable: {e}");
                    return;
                }
            };
            while hangup.recv().await.is_some() {
                tracing::info!("SIGHUP received — reloading API keys catalog");
                reload_api_keys(&state_sighup);
            }
        });
    }

    if poll_secs > 0 {
        if let Some(path) = state.api_keys_path.clone() {
            let state_poll = state;
            tokio::spawn(async move {
                let mut last_mtime = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                let interval = Duration::from_secs(poll_secs.max(1));
                loop {
                    tokio::time::sleep(interval).await;
                    let mtime = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .unwrap_or(last_mtime);
                    if mtime > last_mtime {
                        tracing::info!("API keys file mtime changed — reloading");
                        reload_api_keys(&state_poll);
                        last_mtime = mtime;
                    }
                }
            });
        }
    }
}

fn reload_api_keys(state: &AppState) {
    match state.api_key_store.load() {
        Ok(keys) => {
            let n = keys.len();
            *state
                .api_keys
                .write()
                .unwrap_or_else(|e| e.into_inner()) = keys;
            tracing::info!("API keys catalog reloaded ({n} key(s))");
        }
        Err(e) => tracing::error!("API keys reload failed: {e}"),
    }
}

fn load_rustls_server_config(
    cert_path: &FsPath,
    key_path: &FsPath,
    client_ca_path: Option<&FsPath>,
) -> Result<rustls::ServerConfig, String> {
    use rustls::server::WebPkiClientVerifier;
    use rustls::{version, SupportedProtocolVersion};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use std::sync::Arc as StdArc;

    // TLS 1.2+ only (reject TLS 1.0 / 1.1).
    static TLS_VERSIONS: &[&SupportedProtocolVersion] = &[&version::TLS13, &version::TLS12];

    let certs: Vec<_> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("open/parse cert {}: {e}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs: {e}"))?;
    if certs.is_empty() {
        return Err("no certificates found in PEM file".into());
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("open/parse key {}: {e}", key_path.display()))?;

    let builder = rustls::ServerConfig::builder_with_protocol_versions(TLS_VERSIONS);
    let mut config = if let Some(ca_path) = client_ca_path {
        let mut roots = rustls::RootCertStore::empty();
        let ca_certs: Vec<_> = CertificateDer::pem_file_iter(ca_path)
            .map_err(|e| format!("open/parse client CA {}: {e}", ca_path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse client CAs: {e}"))?;
        for ca in ca_certs {
            roots
                .add(ca)
                .map_err(|e| format!("add client CA: {e}"))?;
        }
        if roots.is_empty() {
            return Err("no client CA certificates found in PEM file".into());
        }
        let verifier = WebPkiClientVerifier::builder(StdArc::new(roots))
            .build()
            .map_err(|e| format!("client verifier: {e}"))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| format!("rustls config (mTLS): {e}"))?
    } else {
        if PaymentSecurityProfile::require_tls() {
            return Err(
                "Payment profile requires mTLS: pass --tls-client-ca with a trusted client CA bundle"
                    .into(),
            );
        }
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("rustls config: {e}"))?
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn spawn_tls_reload_watchers(tls: TlsMaterial, poll_secs: u64) {
    #[cfg(unix)]
    {
        let tls_sighup = tls.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut hangup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("TLS SIGHUP watcher unavailable: {e}");
                    return;
                }
            };
            while hangup.recv().await.is_some() {
                tracing::info!("SIGHUP received — reloading TLS material");
                let _ = tls_sighup.reload();
            }
        });
    }
    #[cfg(not(unix))]
    {
        tracing::info!("TLS SIGHUP reload is Unix-only; use --tls-reload-poll-secs on this platform");
    }

    if poll_secs > 0 {
        let tls_poll = tls;
        tokio::spawn(async move {
            let mut last_mtime = latest_tls_mtime(&tls_poll);
            let interval = Duration::from_secs(poll_secs.max(1));
            loop {
                tokio::time::sleep(interval).await;
                let mtime = latest_tls_mtime(&tls_poll);
                if mtime > last_mtime {
                    tracing::info!("TLS PEM mtime changed — reloading");
                    if tls_poll.reload().is_ok() {
                        last_mtime = mtime;
                    }
                }
            }
        });
    }
}

fn latest_tls_mtime(tls: &TlsMaterial) -> SystemTime {
    let mut latest = SystemTime::UNIX_EPOCH;
    for p in [&tls.cert, &tls.key].into_iter().chain(tls.client_ca.iter()) {
        if let Ok(meta) = std::fs::metadata(p) {
            if let Ok(m) = meta.modified() {
                if m > latest {
                    latest = m;
                }
            }
        }
    }
    latest
}

async fn serve_https(
    listener: TcpListener,
    app: Router,
    tls: TlsMaterial,
) -> Result<(), std::io::Error> {
    use hyper::body::Incoming;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as HyperConnBuilder;
    use tower::Service;

    loop {
        let (tcp_stream, peer) = listener.accept().await?;
        let acceptor = tls.acceptor();
        let tower_service = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("TLS handshake failed: {}", e);
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let hyper_service =
                hyper::service::service_fn(move |mut req: axum::http::Request<Incoming>| {
                    req.extensions_mut().insert(ConnectInfo(peer));
                    let mut svc = tower_service.clone();
                    async move { svc.call(req).await }
                });

            if let Err(e) = HyperConnBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await
            {
                tracing::warn!("HTTPS connection error: {}", e);
            }
        });
    }
}

fn build_cors_layer(origins: &str) -> CorsLayer {
    let trimmed = origins.trim();
    if trimmed.is_empty() {
        return CorsLayer::new();
    }

    let list: Vec<HeaderValue> = trimmed
        .split(',')
        .filter_map(|o| {
            let o = o.trim();
            if o.is_empty() {
                None
            } else {
                HeaderValue::from_str(o).ok()
            }
        })
        .collect();

    if list.is_empty() {
        return CorsLayer::new();
    }

    let mut allow_headers = vec![header::AUTHORIZATION, header::CONTENT_TYPE];
    if PaymentSecurityProfile::allow_x_password_header() {
        allow_headers.push(header::HeaderName::from_static("x-password"));
    }

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(list))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(allow_headers)
        .max_age(Duration::from_secs(600))
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string());
    let key = rate_limit::bucket_key(
        auth,
        req.method().as_str(),
        req.uri().path(),
        peer.as_deref(),
    );
    if state.rate_limiter.check(&key).await {
        Ok(next.run(req).await)
    } else {
        tracing::warn!("Rate limit exceeded");
        let mut res = Response::new(Body::empty());
        *res.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        res.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        Err(res)
    }
}

async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_string();
    let is_service_route = path.starts_with("/service/");

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => h[7..].to_string(),
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    // Prefer `ick_live_…` string secrets; fall back to legacy base64-raw keys.
    let hash_input: Vec<u8> = if token.starts_with(ApiKeyConfig::LIVE_PREFIX) {
        token.into_bytes()
    } else {
        match base64::engine::general_purpose::STANDARD.decode(&token) {
            Ok(bytes) => bytes,
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    };

    let mut hasher = Sha512::new();
    hasher.update(&hash_input);
    let received_hash_bytes = hasher.finalize();
    let now = chrono::Utc::now();

    let matched = {
        let keys = state.api_keys.read().unwrap_or_else(|e| e.into_inner());
        let mut found: Option<(usize, AuthenticatedPrincipal, Vec<Permission>)> = None;
        for (idx, key_config) in keys.iter().enumerate() {
            if !key_config.is_usable(now) {
                continue;
            }
            if let Ok(expected_hash_bytes) = hex::decode(&key_config.key_hash) {
                if received_hash_bytes
                    .as_slice()
                    .ct_eq(&expected_hash_bytes)
                    .unwrap_u8()
                    == 1
                {
                    if is_service_route {
                        let path_parts: Vec<&str> = path.split('/').collect();
                        if path_parts.len() < 3 || path_parts[1] != "service" {
                            return Err(StatusCode::BAD_REQUEST);
                        }
                        let service_name = path_parts[2];

                        let authorized_for_service = match &key_config.allowed_services {
                            // Explicit allow-list. `"*"` grants all backends.
                            // Missing or empty `[]` is fail-closed (deny).
                            Some(services) if !services.is_empty() => {
                                services.iter().any(|s| s == "*")
                                    || services
                                        .iter()
                                        .any(|s| s.eq_ignore_ascii_case(service_name))
                            }
                            _ => false,
                        };

                        if !authorized_for_service {
                            return Err(StatusCode::FORBIDDEN);
                        }
                    }

                    found = Some((
                        idx,
                        AuthenticatedPrincipal {
                            key_id: key_config.key_id.clone(),
                            owner: key_config.owner.clone(),
                            permissions: key_config.permissions.clone(),
                        },
                        key_config.permissions.clone(),
                    ));
                    break;
                }
            }
        }
        found
    };

    let Some((idx, principal, permissions)) = matched else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Best-effort in-memory last_used_at (not persisted to disk).
    if let Ok(mut keys) = state.api_keys.write() {
        if let Some(k) = keys.get_mut(idx) {
            k.last_used_at = Some(now);
        }
    }

    req.extensions_mut().insert(Arc::new(principal));
    req.extensions_mut().insert(Arc::new(permissions));
    Ok(next.run(req).await)
}

fn map_crypto_error(err: &IronCryptError) -> StatusCode {
    match err {
        IronCryptError::PasswordVerificationError
        | IronCryptError::PasswordStrengthError(_)
        | IronCryptError::InvalidPassword
        | IronCryptError::DecryptionError(_)
        | IronCryptError::SignatureVerificationFailed(_)
        | IronCryptError::ConfigurationError(_) => StatusCode::BAD_REQUEST,
        IronCryptError::ProviderError(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn body_stream_reader(
    req: Request<Body>,
) -> StreamReader<impl futures::Stream<Item = Result<bytes::Bytes, io::Error>> + Send, bytes::Bytes>
{
    let stream = req.into_body().into_data_stream().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, e.to_string())
    });
    StreamReader::new(stream)
}

fn streaming_response<R>(reader: R) -> Response
where
    R: AsyncRead + Send + Unpin + 'static,
{
    Response::new(Body::from_stream(ReaderStream::new(reader)))
}

async fn acquire_crypto_permit(
    state: &AppState,
) -> Result<OwnedSemaphorePermit, StatusCode> {
    state
        .crypto_sem
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// Wrap/unwrap via CryptoProvider with circuit breaker + timeout + controlled retry.
async fn provider_wrap(
    state: &AppState,
    provider: &Arc<dyn CryptoProvider>,
    key_id: &str,
    dek: &[u8],
) -> Result<ironcrypt::WrappedKey, StatusCode> {
    state.provider_circuit.guard().map_err(|e| {
        tracing::warn!("provider circuit open: {}", sanitize_error_message(&e));
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    let key_id = key_id.to_string();
    let dek = zeroize::Zeroizing::new(dek.to_vec());
    let provider = provider.clone();
    let timeout = state.provider_timeout;
    let started = Instant::now();
    let name = provider.name();
    match with_retry(&state.provider_retry, || {
        let provider = provider.clone();
        let key_id = key_id.clone();
        let dek = dek.clone();
        async move { with_timeout(timeout, provider.wrap_key(&key_id, &dek)).await }
    })
    .await
    {
        Ok(wrapped) => {
            state.provider_circuit.record_success();
            ironcrypt::metrics::provider_op_finish(name, "wrap", started, true);
            Ok(wrapped)
        }
        Err(e) => {
            state.provider_circuit.record_failure();
            ironcrypt::metrics::provider_op_finish(name, "wrap", started, false);
            tracing::error!("DEK wrap failed: {}", sanitize_error_message(&e));
            Err(map_crypto_error(&e))
        }
    }
}

async fn provider_unwrap(
    state: &AppState,
    provider: &Arc<dyn CryptoProvider>,
    key_id: &str,
    wrapped: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, StatusCode> {
    state.provider_circuit.guard().map_err(|e| {
        tracing::warn!("provider circuit open: {}", sanitize_error_message(&e));
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    let key_id = key_id.to_string();
    let wrapped = wrapped.to_vec();
    let provider = provider.clone();
    let timeout = state.provider_timeout;
    let started = Instant::now();
    let name = provider.name();
    match with_retry(&state.provider_retry, || {
        let provider = provider.clone();
        let key_id = key_id.clone();
        let wrapped = wrapped.clone();
        async move { with_timeout(timeout, provider.unwrap_key(&key_id, &wrapped)).await }
    })
    .await
    {
        Ok(dek) => {
            state.provider_circuit.record_success();
            ironcrypt::metrics::provider_op_finish(name, "unwrap", started, true);
            Ok(zeroize::Zeroizing::new(dek))
        }
        Err(e) => {
            state.provider_circuit.record_failure();
            ironcrypt::metrics::provider_op_finish(name, "unwrap", started, false);
            tracing::error!("DEK unwrap failed: {}", sanitize_error_message(&e));
            Err(map_crypto_error(&e))
        }
    }
}

/// Read IronCrypt stream header from an async source (bounded).
async fn read_stream_header_async<R: AsyncRead + Unpin>(
    source: &mut R,
) -> Result<StreamHeader, IronCryptError> {
    let mut len_buf = [0u8; 8];
    source.read_exact(&mut len_buf).await?;
    let header_len = u64::from_be_bytes(len_buf);
    if header_len == 0 || header_len as u128 > MAX_STREAM_HEADER_SIZE as u128 {
        return Err(IronCryptError::DecryptionError(format!(
            "stream header length {header_len} exceeds MAX_STREAM_HEADER_SIZE ({MAX_STREAM_HEADER_SIZE})"
        )));
    }
    let mut header_bytes = vec![0u8; header_len as usize];
    source.read_exact(&mut header_bytes).await?;
    let header: StreamHeader = serde_json::from_slice(&header_bytes)?;
    Ok(header)
}

async fn get_secret_handler(
    State(state): State<AppState>,
    Path((service_name, secret_key)): Path<(String, String)>,
    permissions: Extension<Arc<Vec<Permission>>>,
) -> Result<String, StatusCode> {
    if !permissions.contains(&Permission::Read) {
        return Err(StatusCode::FORBIDDEN);
    }

    let secret_store = state.secret_stores.get(&service_name).ok_or_else(|| {
        tracing::warn!("Requested service not found: {}", service_name);
        StatusCode::NOT_FOUND
    })?;

    match secret_store.get_secret(&secret_key).await {
        Ok(secret) => Ok(secret),
        Err(e) => {
            tracing::error!(
                "Failed to get secret '{}' from service '{}': {}",
                sanitize_secret_name(&secret_key),
                service_name,
                sanitize_error_message(&e)
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn set_secret_handler(
    State(state): State<AppState>,
    Path((service_name, secret_key)): Path<(String, String)>,
    permissions: Extension<Arc<Vec<Permission>>>,
    body: String,
) -> Result<StatusCode, StatusCode> {
    if !permissions.contains(&Permission::Write) {
        return Err(StatusCode::FORBIDDEN);
    }

    let secret_store = state.secret_stores.get(&service_name).ok_or_else(|| {
        tracing::warn!("Requested service not found: {}", service_name);
        StatusCode::NOT_FOUND
    })?;

    match secret_store.set_secret(&secret_key, &body).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            tracing::error!(
                "Failed to set secret '{}' in service '{}': {}",
                sanitize_secret_name(&secret_key),
                service_name,
                sanitize_error_message(&e)
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Use-secret: HMAC-SHA256(body) with the store secret as key — never returns the secret.
async fn hmac_secret_handler(
    State(state): State<AppState>,
    Path((service_name, secret_key)): Path<(String, String)>,
    permissions: Extension<Arc<Vec<Permission>>>,
    body: Bytes,
) -> Result<Json<HmacResponse>, StatusCode> {
    if !permissions.contains(&Permission::Read) {
        return Err(StatusCode::FORBIDDEN);
    }

    let secret_store = state.secret_stores.get(&service_name).ok_or_else(|| {
        tracing::warn!("Requested service not found: {}", service_name);
        StatusCode::NOT_FOUND
    })?;

    let mut secret = match secret_store.get_secret(&secret_key).await {
        Ok(s) => Zeroizing::new(s),
        Err(e) => {
            tracing::error!(
                "Failed to get secret '{}' from service '{}' for HMAC: {}",
                sanitize_secret_name(&secret_key),
                service_name,
                sanitize_error_message(&e)
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| {
        tracing::error!("HMAC key rejected (empty or invalid length)");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    mac.update(&body);
    let tag = mac.finalize().into_bytes();
    secret.zeroize();

    Ok(Json(HmacResponse {
        algorithm: "HMAC-SHA256",
        digest_hex: hex::encode(tag),
    }))
}

#[derive(Serialize)]
struct HmacResponse {
    algorithm: &'static str,
    digest_hex: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    provider_circuit_open: bool,
    crypto_provider: bool,
}

#[derive(Serialize)]
struct TlsStatusResponse {
    enabled: bool,
    last_reload_unix: Option<u64>,
    last_error: Option<String>,
    cert: Option<String>,
}

async fn admin_health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn admin_ready(State(state): State<AppState>) -> Result<Json<ReadyResponse>, StatusCode> {
    // Liveness is `/health` (process up). Readiness: circuit closed + a crypto
    // backend configured (provider or local PEM). Never include error strings /
    // key ids / backend addresses here.
    let open = state.provider_circuit.is_open();
    if open {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let has_crypto = state.crypto_provider.is_some()
        || (state.public_key.is_some() && state.private_key.is_some());
    if !has_crypto {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(ReadyResponse {
        status: "ready",
        provider_circuit_open: false,
        crypto_provider: state.crypto_provider.is_some(),
    }))
}

async fn admin_tls_status(State(state): State<AppState>) -> Json<TlsStatusResponse> {
    match &state.tls {
        None => Json(TlsStatusResponse {
            enabled: false,
            last_reload_unix: None,
            last_error: None,
            cert: None,
        }),
        Some(tls) => {
            let last_ok = tls
                .last_ok
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            let last_error = tls
                .last_err
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            Json(TlsStatusResponse {
                enabled: true,
                last_reload_unix: last_ok,
                last_error,
                cert: Some(tls.cert.display().to_string()),
            })
        }
    }
}

/// Extract optional stream password; rejected under Payment.
fn extract_password_header(req: &Request<Body>) -> Result<String, StatusCode> {
    let header = req.headers().get("X-Password");
    if header.is_some() && !PaymentSecurityProfile::allow_x_password_header() {
        tracing::warn!("X-Password header rejected under Payment profile");
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(header
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string())
}

/// EncryptionContext from `X-IronCrypt-Tenant-Id` / `Purpose` / `Record-Id`.
/// Mandatory under Payment.
fn extract_encryption_context(
    req: &Request<Body>,
) -> Result<Option<EncryptionContext>, StatusCode> {
    let tenant = req
        .headers()
        .get("x-ironcrypt-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let purpose = req
        .headers()
        .get("x-ironcrypt-purpose")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let record = req
        .headers()
        .get("x-ironcrypt-record-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();

    if tenant.is_empty() && purpose.is_empty() && record.is_empty() {
        if PaymentSecurityProfile::require_encryption_context() {
            tracing::warn!("Payment requires X-IronCrypt-Tenant-Id / Purpose / Record-Id");
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok(None);
    }
    let ctx = EncryptionContext::new(tenant, purpose, record);
    if let Err(e) = ctx.validate() {
        tracing::warn!("invalid EncryptionContext headers: {e}");
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Some(ctx))
}

async fn write_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    let permissions = req
        .extensions()
        .get::<Arc<Vec<Permission>>>()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .clone();
    if !permissions.contains(&Permission::Write) {
        return Err(StatusCode::FORBIDDEN);
    }

    let principal_label = req
        .extensions()
        .get::<Arc<AuthenticatedPrincipal>>()
        .and_then(|p| p.audit_label());
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let started = Instant::now();

    let mut password = extract_password_header(&req)?;
    let hash_password = !password.is_empty();
    let enc_context = extract_encryption_context(&req)?;

    let async_in = body_stream_reader(req);
    let (async_out_writer, async_out_reader) = duplex(64 * 1024);
    let response = streaming_response(async_out_reader);

    let key_version = state.key_version.clone();
    let config = state.config.clone();
    let permit = acquire_crypto_permit(&state).await?;

    if let Some(provider) = state.crypto_provider.clone() {
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);
        let wrapped = match provider_wrap(&state, &provider, &key_version, &dek).await {
            Ok(w) => w,
            Err(e) => {
                dek.zeroize();
                return Err(e);
            }
        };
        let recipient = RecipientInfo::Provider {
            key_version: key_version.clone(),
            provider: provider.name().to_string(),
            key_id: wrapped.key_id,
            encrypted_symmetric_key: B64.encode(&wrapped.ciphertext),
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut audit_event = AuditEvent::new(Operation::Write);
            audit_event.key_version = Some(key_version.clone());
            audit_event.symmetric_algorithm = Some(config.symmetric_algorithm.to_string());
            audit_event.request_id = request_id.clone();
            audit_event.principal_id = principal_label.clone();
            if let Some(ref ctx) = enc_context {
                audit_event.tenant_id = Some(ctx.tenant_id.clone());
            }
            let argon_cfg = Argon2Config {
                memory_cost: config.argon2_memory_cost,
                time_cost: config.argon2_time_cost,
                parallelism: config.argon2_parallelism,
            };
            let mut source = SyncIoBridge::new(async_in);
            let mut destination = SyncIoBridge::new(async_out_writer);
            let mut dek = dek;
            let result = encrypt_stream_with_dek(
                &mut source,
                &mut destination,
                &mut password,
                &mut dek,
                vec![recipient],
                None,
                &config.password_criteria,
                argon_cfg,
                hash_password,
                config.symmetric_algorithm,
                enc_context.as_ref(),
            );
            dek.zeroize();
            let _ = destination.shutdown();
            audit_event.duration_ms = Some(started.elapsed().as_millis() as u64);
            match &result {
                Ok(_) => audit_event.outcome = Outcome::Success,
                Err(e) => {
                    audit_event.set_failure(e);
                    tracing::error!(
                        "Encryption failed: {}",
                        sanitize_error_message(e)
                    );
                }
            }
            audit_event.log();
            result
        });
    } else {
        let public_key = state
            .public_key
            .clone()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut audit_event = AuditEvent::new(Operation::Write);
            audit_event.key_version = Some(key_version.clone());
            audit_event.symmetric_algorithm = Some(config.symmetric_algorithm.to_string());
            audit_event.request_id = request_id;
            audit_event.principal_id = principal_label;
            if let Some(ref ctx) = enc_context {
                audit_event.tenant_id = Some(ctx.tenant_id.clone());
            }
            let argon_cfg = Argon2Config {
                memory_cost: config.argon2_memory_cost,
                time_cost: config.argon2_time_cost,
                parallelism: config.argon2_parallelism,
            };
            let mut source = SyncIoBridge::new(async_in);
            let mut destination = SyncIoBridge::new(async_out_writer);
            let recipients = vec![(&*public_key, key_version.as_str())];
            let result = encrypt_stream_with_context(
                &mut source,
                &mut destination,
                &mut password,
                recipients,
                None,
                &config.password_criteria,
                argon_cfg,
                hash_password,
                config.symmetric_algorithm,
                enc_context.as_ref(),
            );
            let _ = destination.shutdown();
            audit_event.duration_ms = Some(started.elapsed().as_millis() as u64);
            match &result {
                Ok(_) => audit_event.outcome = Outcome::Success,
                Err(e) => {
                    audit_event.set_failure(e);
                    tracing::error!(
                        "Encryption failed: {}",
                        sanitize_error_message(e)
                    );
                }
            }
            audit_event.log();
            result
        });
    }

    Ok(response)
}

async fn read_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    let permissions = req
        .extensions()
        .get::<Arc<Vec<Permission>>>()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .clone();
    if !permissions.contains(&Permission::Read) {
        return Err(StatusCode::FORBIDDEN);
    }

    let principal_label = req
        .extensions()
        .get::<Arc<AuthenticatedPrincipal>>()
        .and_then(|p| p.audit_label());
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let started = Instant::now();

    let password = extract_password_header(&req)?;

    let mut async_in = body_stream_reader(req);
    let key_version = state.key_version.clone();
    let (async_out_writer, async_out_reader) = duplex(64 * 1024);
    let response = streaming_response(async_out_reader);
    let permit = acquire_crypto_permit(&state).await?;

    if let Some(provider) = state.crypto_provider.clone() {
        let header = read_stream_header_async(&mut async_in)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Header parse failed: {}",
                    sanitize_error_message(&e)
                );
                map_crypto_error(&e)
            })?;
        let recipient = find_recipient(&header, &key_version).ok_or_else(|| {
            tracing::error!("No recipient for key_version {}", key_version);
            StatusCode::BAD_REQUEST
        })?;
        let (key_id, wrapped_b64) = match recipient {
            RecipientInfo::Provider {
                key_id,
                encrypted_symmetric_key,
                provider: prov,
                ..
            } => {
                if prov != provider.name() {
                    tracing::error!("Provider mismatch: {} vs {}", prov, provider.name());
                    return Err(StatusCode::BAD_REQUEST);
                }
                (key_id.clone(), encrypted_symmetric_key.clone())
            }
            _ => {
                tracing::error!("Expected Provider recipient for CryptoProvider mode");
                return Err(StatusCode::BAD_REQUEST);
            }
        };
        let wrapped = B64
            .decode(wrapped_b64.as_bytes())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut dek = provider_unwrap(&state, &provider, &key_id, &wrapped).await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut audit_event = AuditEvent::new(Operation::Read);
            audit_event.key_version = Some(key_version);
            audit_event.request_id = request_id.clone();
            audit_event.principal_id = principal_label.clone();
            let mut source = SyncIoBridge::new(async_in);
            let mut destination = SyncIoBridge::new(async_out_writer);
            let result = decrypt_stream_with_dek(
                &mut source,
                &mut destination,
                header,
                &mut dek,
                &password,
                None,
            );
            dek.zeroize();
            let _ = destination.shutdown();
            audit_event.duration_ms = Some(started.elapsed().as_millis() as u64);
            match &result {
                Ok(_) => audit_event.outcome = Outcome::Success,
                Err(e) => {
                    audit_event.set_failure(e);
                    tracing::error!(
                        "Decryption failed: {}",
                        sanitize_error_message(e)
                    );
                }
            }
            audit_event.log();
            result
        });
    } else {
        let private_key = state
            .private_key
            .clone()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut audit_event = AuditEvent::new(Operation::Read);
            audit_event.key_version = Some(key_version.clone());
            audit_event.request_id = request_id;
            audit_event.principal_id = principal_label;
            let mut source = SyncIoBridge::new(async_in);
            let mut destination = SyncIoBridge::new(async_out_writer);
            let result = decrypt_stream(
                &mut source,
                &mut destination,
                &private_key,
                &key_version,
                &password,
                None,
            );
            let _ = destination.shutdown();
            audit_event.duration_ms = Some(started.elapsed().as_millis() as u64);
            match &result {
                Ok(_) => audit_event.outcome = Outcome::Success,
                Err(e) => {
                    audit_event.set_failure(e);
                    tracing::error!(
                        "Decryption failed: {}",
                        sanitize_error_message(e)
                    );
                }
            }
            audit_event.log();
            result
        });
    }

    Ok(response)
}
