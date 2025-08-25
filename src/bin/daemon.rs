use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::Request,
    response::Response,
    routing::post,
    Router,
};
use clap::Parser;
use futures::StreamExt;
use ironcrypt::{
    decrypt_stream, encrypt_stream, load_private_key, load_public_key, Argon2Config,
    PasswordCriteria,
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_util::io::{ReaderStream, SyncIoBridge};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// A struct to hold the application's shared state.
#[derive(Clone)]
struct AppState {
    public_key: Arc<RsaPublicKey>,
    private_key: Arc<RsaPrivateKey>,
    key_version: String,
}

/// Command-line arguments for the daemon.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 3000)]
    port: u16,

    /// Directory where keys are stored
    #[arg(short = 'd', long, default_value = "keys")]
    key_directory: String,

    /// Key version to use (e.g., "v1")
    #[arg(short = 'v', long)]
    key_version: String,

    /// Passphrase for the private key
    #[arg(long)]
    passphrase: Option<String>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse command-line arguments
    let args = Args::parse();

    // Load keys
    let public_key_path = format!("{}/public_key_{}.pem", args.key_directory, args.key_version);
    let private_key_path = format!("{}/private_key_{}.pem", args.key_directory, args.key_version);

    let public_key = match load_public_key(&public_key_path) {
        Ok(key) => Arc::new(key),
        Err(e) => {
            eprintln!("Failed to load public key from {}: {}", public_key_path, e);
            return;
        }
    };

    let private_key = match load_private_key(&private_key_path, args.passphrase.as_deref()) {
        Ok(key) => Arc::new(key),
        Err(e) => {
            eprintln!("Failed to load private key from {}: {}", private_key_path, e);
            return;
        }
    };

    // Create application state
    let state = AppState {
        public_key,
        private_key,
        key_version: args.key_version,
    };

    // Build our application router
    let app = Router::new()
        .route("/encrypt", post(encrypt_handler))
        .route("/decrypt", post(decrypt_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .layer(DefaultBodyLimit::disable()); // Disable default body limit for streaming

    // Run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    tracing::debug!("listening on {}", addr);
    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Axum handler for the /encrypt endpoint.
async fn encrypt_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Response {
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
    tokio::task::spawn_blocking(move || {
        let criteria = PasswordCriteria::default();
        let argon_cfg = Argon2Config::default();

        let recipients = vec![(&*public_key, key_version.as_str())];
        if let Err(e) = encrypt_stream(
            &mut request_reader,
            &mut response_writer,
            &mut password,
            recipients,
            &criteria,
            argon_cfg,
            hash_password,
        ) {
            tracing::error!("Encryption failed: {}", e);
        }
    });

    Response::new(response_body)
}

/// Axum handler for the /decrypt endpoint.
async fn decrypt_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Response {
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
        if let Err(e) = decrypt_stream(
            &mut request_reader,
            &mut response_writer,
            &private_key,
            &key_version,
            &password,
        ) {
            tracing::error!("Decryption failed: {}", e);
        }
    });

    Response::new(response_body)
}
