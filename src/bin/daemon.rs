use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Extension, Path, State},
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use base64::Engine;
use clap::Parser;
use elliptic_curve::subtle::ConstantTimeEq;
use futures::StreamExt;
use ironcrypt::{
    audit::{AuditEvent, Operation, Outcome},
    auth::{ApiKeyConfig, Permission},
    config::IronCryptConfig,
    decrypt_stream, encrypt_stream,
    keys::{PrivateKey, PublicKey},
    load_any_private_key, load_any_public_key,
    secrets::SecretStore,
    Argon2Config, IronCryptError,
};
use sha2::{Digest, Sha512};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::net::TcpListener;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{
    filter::{self, LevelFilter},
    prelude::*,
    util::SubscriberInitExt,
    Layer,
};

/// Simple token-bucket style global rate limiter.
#[derive(Debug)]
struct SimpleRateLimiter {
    /// Max requests allowed per 1s window.
    burst: u64,
    state: Mutex<(Instant, u64)>,
    /// When false, rate limiting is disabled.
    enabled: bool,
}

impl SimpleRateLimiter {
    fn new(per_sec: u32, burst: u32) -> Self {
        if per_sec == 0 {
            return Self {
                burst: 0,
                state: Mutex::new((Instant::now(), 0)),
                enabled: false,
            };
        }
        Self {
            burst: burst.max(1) as u64,
            state: Mutex::new((Instant::now(), 0)),
            enabled: true,
        }
    }

    fn check(&self) -> bool {
        if !self.enabled {
            return true;
        }
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if now.duration_since(guard.0) >= Duration::from_secs(1) {
            guard.0 = now;
            guard.1 = 0;
        }
        if guard.1 >= self.burst {
            return false;
        }
        guard.1 += 1;
        true
    }
}

/// Shared application state.
#[derive(Clone)]
struct AppState {
    public_key: Arc<PublicKey>,
    private_key: Arc<PrivateKey>,
    key_version: String,
    config: Arc<IronCryptConfig>,
    api_keys: Arc<Vec<ApiKeyConfig>>,
    secret_stores: Arc<HashMap<String, Arc<dyn SecretStore + Send + Sync>>>,
    rate_limiter: Arc<SimpleRateLimiter>,
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

    /// Passphrase for the private key
    #[arg(long)]
    passphrase: Option<String>,

    /// Path to the JSON file containing API key configurations.
    #[arg(long, env = "IRONCRYPT_API_KEYS_FILE")]
    api_keys_file: String,

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

    /// Optional TLS certificate PEM path. When set with --tls-key, the daemon
    /// serves HTTPS in-process via rustls.
    #[arg(long, env = "IRONCRYPT_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Optional TLS private key PEM path (must be paired with --tls-cert).
    #[arg(long, env = "IRONCRYPT_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Explicitly allow plain HTTP when TLS is not configured (default). Kept for
    /// clarity in deployments that document insecure lab mode.
    #[arg(long, env = "IRONCRYPT_ALLOW_INSECURE_HTTP", default_value_t = false)]
    allow_insecure_http: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let tls_mode = match (&args.tls_cert, &args.tls_key) {
        (Some(_), Some(_)) => true,
        (None, None) => false,
        _ => {
            eprintln!("Both --tls-cert and --tls-key must be provided together.");
            return;
        }
    };

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

    let config = match IronCryptConfig::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load config file at {}: {}", args.config, e);
            return;
        }
    };

    let stdout_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(io::stdout)
        .with_filter(LevelFilter::INFO)
        .with_filter(filter::filter_fn(|metadata| metadata.target() != "audit"));

    let mut _guard = None;
    let audit_layer = if let Some(audit_config) = &config.audit {
        let file_appender =
            tracing_appender::rolling::daily(&audit_config.log_path, "audit.log");
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

    let api_keys_content = match std::fs::read_to_string(&args.api_keys_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!(
                "Failed to read API keys file at {}: {}",
                args.api_keys_file, e
            );
            return;
        }
    };

    let mut api_keys: Vec<ApiKeyConfig> = match serde_json::from_str(&api_keys_content) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("Failed to parse API keys file: {}", e);
            return;
        }
    };

    for key_config in &mut api_keys {
        if key_config.permissions.contains(&Permission::Full) {
            key_config.permissions.retain(|p| *p != Permission::Full);
            key_config.permissions.push(Permission::Read);
            key_config.permissions.push(Permission::Write);
            key_config.permissions.push(Permission::Delete);
            key_config.permissions.push(Permission::Update);
            key_config.permissions.sort();
            key_config.permissions.dedup();
        }
    }

    let public_key_path = format!("{}/public_key_{}.pem", args.key_directory, args.key_version);
    let private_key_path = format!("{}/private_key_{}.pem", args.key_directory, args.key_version);

    let public_key = match load_any_public_key(&public_key_path) {
        Ok(key) => Arc::new(key),
        Err(e) => {
            eprintln!("Failed to load public key from {}: {}", public_key_path, e);
            return;
        }
    };

    let private_key = match load_any_private_key(&private_key_path, args.passphrase.as_deref()) {
        Ok(key) => Arc::new(key),
        Err(e) => {
            eprintln!("Failed to load private key from {}: {}", private_key_path, e);
            return;
        }
    };

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

    let state = AppState {
        public_key,
        private_key,
        key_version: args.key_version.clone(),
        config: Arc::new(config),
        api_keys: Arc::new(api_keys),
        secret_stores: Arc::new(secret_stores),
        rate_limiter: Arc::new(SimpleRateLimiter::new(
            args.rate_limit_per_sec,
            args.rate_limit_burst,
        )),
    };

    let cors_layer = build_cors_layer(&args.cors_origins);

    let app = Router::new()
        .route("/write", post(write_handler))
        .route("/read", post(read_handler))
        .route(
            "/service/:service_name/secret/:secret_key",
            get(get_secret_handler).post(set_secret_handler),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer)
        .layer(DefaultBodyLimit::disable());

    let host_addr: std::net::IpAddr = match args.host.parse() {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!("Invalid host address provided '{}': {}", args.host, e);
            return;
        }
    };

    let addr = SocketAddr::new(host_addr, args.port);
    tracing::info!(
        "listening on {} ({})",
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

    if tls_mode {
        let cert = args.tls_cert.as_ref().expect("tls_mode guarantees cert");
        let key = args.tls_key.as_ref().expect("tls_mode guarantees key");
        let tls_config = match load_rustls_server_config(cert, key) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::error!("Failed to load TLS certificate/key: {}", e);
                return;
            }
        };
        if let Err(e) = serve_https(listener, app, tls_config).await {
            tracing::error!("HTTPS server error: {}", e);
        }
    } else if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        tracing::error!("HTTP server error: {}", e);
    }
}

fn load_rustls_server_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<rustls::ServerConfig, String> {
    use std::fs::File;
    use std::io::BufReader;

    let mut cert_reader = BufReader::new(
        File::open(cert_path).map_err(|e| format!("open cert {}: {e}", cert_path.display()))?,
    );
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs: {e}"))?;
    if certs.is_empty() {
        return Err("no certificates found in PEM file".into());
    }

    let mut key_reader = BufReader::new(
        File::open(key_path).map_err(|e| format!("open key {}: {e}", key_path.display()))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("parse key: {e}"))?
        .ok_or_else(|| "no private key found in PEM file".to_string())?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("rustls config: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

async fn serve_https(
    listener: TcpListener,
    app: Router,
    tls_config: rustls::ServerConfig,
) -> Result<(), std::io::Error> {
    use hyper::body::Incoming;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as HyperConnBuilder;
    use tokio_rustls::TlsAcceptor;
    use tower::Service;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    loop {
        let (tcp_stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
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
            let hyper_service = hyper::service::service_fn(move |req: axum::http::Request<Incoming>| {
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

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(list))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-password"),
        ])
        .max_age(Duration::from_secs(600))
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if state.rate_limiter.check() {
        Ok(next.run(req).await)
    } else {
        tracing::warn!("Rate limit exceeded");
        Err(StatusCode::TOO_MANY_REQUESTS)
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
    let token_b64 = match auth_header {
        Some(h) if h.starts_with("Bearer ") => h[7..].to_string(),
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    let token_bytes = match base64::engine::general_purpose::STANDARD.decode(&token_b64) {
        Ok(bytes) => bytes,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let mut hasher = Sha512::new();
    hasher.update(&token_bytes);
    let received_hash_bytes = hasher.finalize();

    for key_config in state.api_keys.iter() {
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
                        Some(services) if !services.is_empty() => services
                            .iter()
                            .any(|s| s.eq_ignore_ascii_case(service_name)),
                        _ => true,
                    };

                    if !authorized_for_service {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }

                req.extensions_mut()
                    .insert(Arc::new(key_config.permissions.clone()));
                return Ok(next.run(req).await);
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

fn map_crypto_error(err: &IronCryptError) -> StatusCode {
    match err {
        IronCryptError::PasswordVerificationError
        | IronCryptError::PasswordStrengthError(_)
        | IronCryptError::InvalidPassword
        | IronCryptError::DecryptionError(_)
        | IronCryptError::SignatureVerificationFailed(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
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
                secret_key,
                service_name,
                e
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
                secret_key,
                service_name,
                e
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn read_body(req: Request<Body>) -> Result<Vec<u8>, StatusCode> {
    let mut body_stream = req.into_body().into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = body_stream.next().await {
        let chunk = chunk.map_err(|e| {
            tracing::error!("Failed to read request body: {}", e);
            StatusCode::BAD_REQUEST
        })?;
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
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

    let mut password = req
        .headers()
        .get("X-Password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let hash_password = !password.is_empty();

    let input = read_body(req).await?;

    let public_key = state.public_key.clone();
    let key_version = state.key_version.clone();
    let config = state.config.clone();

    let crypto_result = tokio::task::spawn_blocking(move || {
        let mut audit_event = AuditEvent::new(Operation::Write);
        audit_event.key_version = Some(key_version.clone());
        audit_event.symmetric_algorithm = Some(config.symmetric_algorithm.to_string());

        let argon_cfg = Argon2Config {
            memory_cost: config.argon2_memory_cost,
            time_cost: config.argon2_time_cost,
            parallelism: config.argon2_parallelism,
        };

        let mut source = std::io::Cursor::new(input);
        let mut output = Vec::new();
        let recipients = vec![(&*public_key, key_version.as_str())];
        let result = encrypt_stream(
            &mut source,
            &mut output,
            &mut password,
            recipients,
            None,
            &config.password_criteria,
            argon_cfg,
            hash_password,
            config.symmetric_algorithm,
        );

        match &result {
            Ok(_) => audit_event.outcome = Outcome::Success,
            Err(e) => {
                audit_event.outcome = Outcome::Failure;
                audit_event.error_message = Some(e.to_string());
                tracing::error!("Encryption failed: {}", e);
            }
        }
        audit_event.log();
        result.map(|_| output)
    })
    .await
    .map_err(|e| {
        tracing::error!("Encryption task join error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match crypto_result {
        Ok(output) => Ok(Response::new(Body::from(output))),
        Err(e) => Err(map_crypto_error(&e)),
    }
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

    let password = req
        .headers()
        .get("X-Password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let input = read_body(req).await?;

    let private_key = state.private_key.clone();
    let key_version = state.key_version.clone();

    let crypto_result = tokio::task::spawn_blocking(move || {
        let mut audit_event = AuditEvent::new(Operation::Read);
        audit_event.key_version = Some(key_version.clone());

        let mut source = std::io::Cursor::new(input);
        let mut output = Vec::new();
        let result = decrypt_stream(
            &mut source,
            &mut output,
            &private_key,
            &key_version,
            &password,
            None,
        );

        match &result {
            Ok(_) => audit_event.outcome = Outcome::Success,
            Err(e) => {
                audit_event.outcome = Outcome::Failure;
                audit_event.error_message = Some(e.to_string());
                tracing::error!("Decryption failed: {}", e);
            }
        }
        audit_event.log();
        result.map(|_| output)
    })
    .await
    .map_err(|e| {
        tracing::error!("Decryption task join error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match crypto_result {
        Ok(output) => Ok(Response::new(Body::from(output))),
        Err(e) => Err(map_crypto_error(&e)),
    }
}
