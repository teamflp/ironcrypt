use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::Request,
    response::Response,
    routing::post,
    Router,
};
use clap::{Parser, ValueEnum};
use futures::StreamExt;
use ironcrypt::{
    decrypt_stream, encrypt_stream,
    keys::{PrivateKey, PublicKey},
    load_private_key, load_public_key, Argon2Config, CryptoStandard, IronCryptConfig,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_util::io::{ReaderStream, SyncIoBridge};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// A struct to hold the application's shared state.
#[derive(Clone)]
struct AppState {
    public_key: Arc<PublicKey>,
    private_key: Arc<PrivateKey>,
    key_version: String,
    config: Arc<IronCryptConfig>,
}

/// A `clap`-compatible enum for selecting the cryptographic standard.
#[derive(ValueEnum, Clone, Debug, Copy)]
enum CliCryptoStandard {
    Nist,
    Fips140_2,
    Custom,
}

impl From<CliCryptoStandard> for CryptoStandard {
    fn from(standard: CliCryptoStandard) -> Self {
        match standard {
            CliCryptoStandard::Nist => CryptoStandard::Nist,
            CliCryptoStandard::Fips140_2 => CryptoStandard::Fips140_2,
            CliCryptoStandard::Custom => CryptoStandard::Custom,
        }
    }
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

    /// The cryptographic standard to use.
    #[arg(long, value_enum, default_value_t = CliCryptoStandard::Nist)]
    standard: CliCryptoStandard,
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

    // Create IronCrypt config
    let mut config = IronCryptConfig::default();
    config.standard = args.standard.into();

    // Apply the standard's parameters
    if let Some(params) = config.standard.get_params() {
        config.symmetric_algorithm = params.symmetric_algorithm;
        config.asymmetric_algorithm = params.asymmetric_algorithm;
        config.rsa_key_size = params.rsa_key_size;
    }

    // Create application state
    let state = AppState {
        public_key,
        private_key,
        key_version: args.key_version,
        config: Arc::new(config),
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
    let config = state.config.clone();
    tokio::task::spawn_blocking(move || {
        let argon_cfg = Argon2Config {
            memory_cost: config.argon2_memory_cost,
            time_cost: config.argon2_time_cost,
            parallelism: config.argon2_parallelism,
        };

        let recipients = vec![(&*public_key, key_version.as_str())];
        if let Err(e) = encrypt_stream(
            &mut request_reader,
            &mut response_writer,
            &mut password,
            recipients,
            None,
            &config.password_criteria,
            argon_cfg,
            hash_password,
            config.symmetric_algorithm,
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
            None,
        ) {
            tracing::error!("Decryption failed: {}", e);
        }
    });

    Response::new(response_body)
}
