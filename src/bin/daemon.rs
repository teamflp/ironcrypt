use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Extension, Path, State},
    http::{header, Request, StatusCode},
    middleware,
    response::Response,
    routing::{get, post},
    Router,
};
use clap::Parser;
use elliptic_curve::subtle::ConstantTimeEq;
use futures::StreamExt;
use ironcrypt::{
    audit::{AuditEvent, Operation, Outcome},
    auth::{ApiKeyConfig, Permission},
    config::IronCryptConfig,
    decrypt_stream, encrypt_stream,
    keys::{PrivateKey, PublicKey},
    load_private_key, load_public_key,
    secrets::{SecretStore},
    Argon2Config,
};
use sha2::{Digest, Sha512};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_util::io::{ReaderStream, SyncIoBridge};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{
    filter::{self, LevelFilter},
    prelude::*,
    util::SubscriberInitExt,
    Layer,
};

/// A struct to hold the application's shared state.
#[derive(Clone)]
struct AppState {
    public_key: Arc<PublicKey>,
    private_key: Arc<PrivateKey>,
    key_version: String,
    config: Arc<IronCryptConfig>,
    api_keys: Arc<Vec<ApiKeyConfig>>,
    secret_stores: Arc<HashMap<String, Arc<dyn SecretStore + Send + Sync>>>,
}

/// Command-line arguments for the daemon.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 3000)]
    port: u16,

    /// Host to listen on
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
}

#[tokio::main]
async fn main() {
    // Parse command-line arguments first, so we can get the config path.
    let args = Args::parse();

    // Load IronCrypt config
    let config = match IronCryptConfig::from_file(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load config file at {}: {}", args.config, e);
            return;
        }
    };

    // --- Logger setup ---
    let stdout_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(io::stdout)
        .with_filter(LevelFilter::INFO)
        .with_filter(filter::filter_fn(|metadata| metadata.target() != "audit"));

    // Keep the guard alive for the duration of the program.
    let mut _guard = None;
    let audit_layer = if let Some(audit_config) = &config.audit {
        let file_appender =
            tracing_appender::rolling::daily(&audit_config.log_path, "audit.log");
        let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);
        _guard = Some(guard); // This moves the guard into the outer scope.

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


    // Load and parse the API keys file
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

    // Expand "full" permission
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

    // Load keys
    let public_key_path = format!("{}/public_key_{}.pem", args.key_directory, args.key_version);
    let private_key_path = format!("{}/private_key_{}.pem", args.key_directory, args.key_version);

    // This assumes RSA keys for now. A more robust solution would check the key type.
    let public_key = match load_public_key(&public_key_path) {
        Ok(key) => Arc::new(PublicKey::Rsa(key)),
        Err(e) => {
            eprintln!("Failed to load public key from {}: {}", public_key_path, e);
            return;
        }
    };

    let private_key = match load_private_key(&private_key_path, args.passphrase.as_deref()) {
        Ok(key) => Arc::new(PrivateKey::Rsa(key)),
        Err(e) => {
            eprintln!("Failed to load private key from {}: {}", private_key_path, e);
            return;
        }
    };

    // Initialize secret stores based on config
    let mut secret_stores: HashMap<String, Arc<dyn SecretStore + Send + Sync>> = HashMap::new();
    if let Some(secrets_config) = &config.secrets {
        // NOTE: This logic assumes multiple secret backends can be configured and used
        // simultaneously, which is a departure from the original single-provider model.

        #[cfg(feature = "aws")]
        if let Some(aws_config) = &secrets_config.aws {
            match ironcrypt::secrets::aws::AwsStore::new(aws_config).await {
                Ok(store) => {
                    secret_stores.insert("aws".to_string(), Arc::new(store));
                    tracing::info!("Initialized AWS Secrets Manager store.");
                }
                Err(e) => {
                    tracing::error!("Failed to initialize AWS store: {}", e);
                }
            }
        }

        // TODO: Add initialization for other providers like Azure, Vault, etc.
    }

    // Create application state
    let state = AppState {
        public_key,
        private_key,
        key_version: args.key_version,
        config: Arc::new(config.clone()),
        api_keys: Arc::new(api_keys),
        secret_stores: Arc::new(secret_stores),
    };

    // Build our application router
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
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .layer(DefaultBodyLimit::disable()); // Disable default body limit for streaming

    // Run our app with hyper
    let host_addr: std::net::IpAddr = match args.host.parse() {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!("Invalid host address provided '{}': {}", args.host, e);
            return;
        }
    };

    let addr = SocketAddr::new(host_addr, args.port);
    tracing::debug!("listening on {}", addr);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to address {}: {}", addr, e);
            return;
        }
    };
    axum::serve(listener, app).await.unwrap();
}

use base64::Engine;

async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: middleware::Next,
) -> Result<Response, StatusCode> {
    let path = req.uri().path();
    let is_service_route = path.starts_with("/service/");

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let token_b64 = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    // Base64-decode the token first.
    let token_bytes = match base64::engine::general_purpose::STANDARD.decode(token_b64) {
        Ok(bytes) => bytes,
        Err(_) => {
            // If decoding fails, it's a bad token.
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Now hash the decoded bytes.
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
                // Key hash matches.

                if is_service_route {
                    let path_parts: Vec<&str> = path.split('/').collect();
                    if path_parts.len() < 3 || path_parts[1] != "service" {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    let service_name = path_parts[2];

                    let authorized_for_service = match &key_config.allowed_services {
                        Some(services) if !services.is_empty() => {
                            services.iter().any(|s| s.eq_ignore_ascii_case(service_name))
                        }
                        _ => true,
                    };

                    if !authorized_for_service {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }

                // Match found, store permissions and proceed.
                req.extensions_mut()
                    .insert(Arc::new(key_config.permissions.clone()));
                return Ok(next.run(req).await);
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Axum handler for getting a secret from a secret store.
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

/// Axum handler for setting a secret in a secret store.
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

/// Axum handler for the /write endpoint.
async fn write_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    // Authorization check
    let permissions = req
        .extensions()
        .get::<Arc<Vec<Permission>>>()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    if !permissions.contains(&Permission::Write) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Create audit event
    let mut audit_event = AuditEvent::new(Operation::Write);
    audit_event.key_version = Some(state.key_version.clone());
    audit_event.symmetric_algorithm = Some(state.config.symmetric_algorithm.to_string());

    // Get password from headers, or use an empty string
    let mut password = req
        .headers()
        .get("X-Password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let hash_password = !password.is_empty();

    // Create a pipe for the request body
    let (mut writer, reader) = tokio::io::duplex(1024 * 1024); // 1MB buffer
    let mut request_reader = SyncIoBridge::new(reader);

    // Spawn a task to stream the request body into the pipe
    let mut body_stream = req.into_body().into_data_stream();
    tokio::spawn(async move {
        while let Some(Ok(chunk)) = body_stream.next().await {
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut writer, &chunk).await {
                tracing::error!("Failed to write to pipe: {}", e);
                break;
            }
        }
    });

    // Create a pipe for the response body
    let (writer, reader) = tokio::io::duplex(1024 * 1024);
    let mut response_writer = SyncIoBridge::new(writer);
    let response_body = Body::from_stream(ReaderStream::new(reader));

    // Spawn a blocking task for the synchronous encryption
    let public_key = state.public_key.clone();
    let key_version = state.key_version.clone();
    let config = state.config.clone();
    tokio::task::spawn_blocking(move || {
        let argon_cfg = Argon2Config {
            memory_cost: config.argon2_memory_cost,
            time_cost: config.argon2_time_cost,
            parallelism: config.argon2_parallelism,
        };

        let recipients = vec![(&*public_key, key_version.as_str())];
        let result = encrypt_stream(
            &mut request_reader,
            &mut response_writer,
            &mut password,
            recipients,
            None,
            &config.password_criteria,
            argon_cfg,
            hash_password,
            config.symmetric_algorithm,
        );

        match result {
            Ok(_) => {
                audit_event.outcome = Outcome::Success;
            }
            Err(e) => {
                audit_event.outcome = Outcome::Failure;
                audit_event.error_message = Some(e.to_string());
                tracing::error!("Encryption failed: {}", e);
            }
        }
        audit_event.log();
    });

    Ok(Response::new(response_body))
}

/// Axum handler for the /read endpoint.
async fn read_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    // Authorization check
    let permissions = req
        .extensions()
        .get::<Arc<Vec<Permission>>>()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    if !permissions.contains(&Permission::Read) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Create audit event
    let mut audit_event = AuditEvent::new(Operation::Read);
    audit_event.key_version = Some(state.key_version.clone());

    // Get password from headers
    let password = req
        .headers()
        .get("X-Password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Create a pipe for the request body
    let (mut writer, reader) = tokio::io::duplex(1024 * 1024);
    let mut request_reader = SyncIoBridge::new(reader);

    // Spawn a task to stream the request body into the pipe
    let mut body_stream = req.into_body().into_data_stream();
    tokio::spawn(async move {
        while let Some(Ok(chunk)) = body_stream.next().await {
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut writer, &chunk).await {
                tracing::error!("Failed to write to pipe: {}", e);
                break;
            }
        }
    });

    // Create a pipe for the response body
    let (writer, reader) = tokio::io::duplex(1024 * 1024);
    let mut response_writer = SyncIoBridge::new(writer);
    let response_body = Body::from_stream(ReaderStream::new(reader));

    // Spawn a blocking task for the synchronous decryption
    let private_key = state.private_key.clone();
    let key_version = state.key_version.clone();
    tokio::task::spawn_blocking(move || {
        let result = decrypt_stream(
            &mut request_reader,
            &mut response_writer,
            &private_key,
            &key_version,
            &password,
            None,
        );

        match result {
            Ok(_) => {
                audit_event.outcome = Outcome::Success;
            }
            Err(e) => {
                audit_event.outcome = Outcome::Failure;
                audit_event.error_message = Some(e.to_string());
                tracing::error!("Decryption failed: {}", e);
            }
        }
        audit_event.log();
    });

    Ok(Response::new(response_body))
}
