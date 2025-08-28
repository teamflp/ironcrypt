use clap::{Parser, Subcommand, ValueEnum};
#[cfg(feature = "interactive")]
use indicatif::{ProgressBar, ProgressStyle};
use ironcrypt::{
    algorithms::SymmetricAlgorithm,
    decrypt_stream, ecc_utils, encrypt_stream, generate_rsa_keys,
    keys::PublicKey,
    save_keys_to_files, Argon2Config, IronCrypt, IronCryptConfig, PasswordCriteria,
};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::File;
// use std::io::Read;  // Currently unused, commented out to avoid warning
use std::process;
#[cfg(feature = "interactive")]
use std::time::Duration;
use tar::{Archive, Builder};
use tempfile::NamedTempFile;

mod metrics;

#[derive(Parser)]
#[command(
    name = "ironcrypt",
    about = "Generation and management of RSA keys for IronCrypt."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Debug)]
enum KeyType {
    Rsa,
    Ecc,
}

#[derive(ValueEnum, Clone, Debug, Copy)]
enum CliSymmetricAlgorithm {
    Aes,
    Chacha20,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates an asymmetric key pair.
    Generate {
        #[arg(short = 'v', long)]
        version: String,

        #[arg(short = 'd', long, default_value = "keys")]
        directory: String,

        /// For RSA, the key size in bits. ECC uses a fixed curve (P-256).
        #[arg(short = 's', long, default_value_t = 2048)]
        key_size: u32,

        #[arg(long)]
        passphrase: Option<String>,

        /// The type of key to generate.
        #[arg(long, value_enum, default_value_t = KeyType::Rsa)]
        key_type: KeyType,
    },

    /// Hashes and encrypts a password (existing logic).
    Encrypt {
        #[arg(short = 'w', long)]
        password: String,
    },

    /// Decrypts an encrypted password (existing logic).
    Decrypt {
        #[arg(short = 'w', long)]
        password: String,

        #[arg(short = 'd', long, conflicts_with = "file")]
        data: Option<String>,

        #[arg(short = 'f', long, conflicts_with = "data")]
        file: Option<String>,

        /// Path to the private keys directory
        #[arg(short = 'k', long, default_value = "keys")]
        key_directory: String,

        /// Passphrase for the private key
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Encrypts a binary file (new command).
    #[command(
        about = "Encrypts a binary file (uses AES+RSA)",
        alias("encfile"),
        alias("efile"),
        alias("ef")
    )]
    EncryptFile {
        /// Path to the binary file to encrypt
        #[arg(short = 'i', long)]
        input_file: String,

        /// Path to the output file (encrypted JSON)
        #[arg(short = 'o', long)]
        output_file: String,

        /// Path to the public keys directory
        #[arg(short = 'd', long, default_value = "keys")]
        public_key_directory: String,

        /// Version of the public key to use (can be specified multiple times for multiple recipients)
        #[arg(short = 'v', long, required = true)]
        key_versions: Vec<String>,

        /// Optional password (leave empty otherwise)
        #[arg(short = 'w', long, default_value = "")]
        password: String,

        /// The symmetric algorithm to use for encryption.
        #[arg(long, value_enum, default_value_t = CliSymmetricAlgorithm::Aes)]
        sym_algo: CliSymmetricAlgorithm,

        /// Version of the private key to use for signing
        #[arg(long)]
        signing_key_version: Option<String>,

        /// Passphrase for the signing key
        #[arg(long)]
        signing_key_passphrase: Option<String>,
    },

    /// Encrypts a PII file.
    #[command(about = "Encrypts a PII file (uses AES+RSA with PII keys)")]
    EncryptPii {
        /// Path to the binary file to encrypt
        #[arg(short = 'i', long)]
        input_file: String,

        /// Path to the output file (encrypted JSON)
        #[arg(short = 'o', long)]
        output_file: String,

        /// Optional password (leave empty otherwise)
        #[arg(short = 'w', long, default_value = "")]
        password: String,
    },

    /// Encrypts a biometric file.
    #[command(about = "Encrypts a biometric file (uses AES+RSA with biometric keys)")]
    EncryptBio {
        /// Path to the binary file to encrypt
        #[arg(short = 'i', long)]
        input_file: String,

        /// Path to the output file (encrypted JSON)
        #[arg(short = 'o', long)]
        output_file: String,

        /// Optional password (leave empty otherwise)
        #[arg(short = 'w', long, default_value = "")]
        password: String,
    },

    /// Decrypts a binary file (new command).
    #[command(
        about = "Decrypts a binary file (returns a .tar, .zip, etc.)",
        alias("decfile"),
        alias("dfile"),
        alias("df")
    )]
    DecryptFile {
        /// Path to the encrypted JSON file
        #[arg(short = 'i', long)]
        input_file: String,

        /// Path to the decrypted binary file
        #[arg(short = 'o', long)]
        output_file: String,

        /// Path to the private keys directory
        #[arg(short = 'k', long, default_value = "keys")]
        private_key_directory: String,

        /// Version of the private key
        #[arg(short = 'v', long)]
        key_version: String,

        /// Optional password
        #[arg(short = 'w', long, default_value = "")]
        password: String,

        /// Passphrase for the private key
        #[arg(long)]
        passphrase: Option<String>,

        /// Version of the public key to use for signature verification
        #[arg(long)]
        verifying_key_version: Option<String>,
    },

    /// Encrypts an entire directory.
    #[command(alias("encdir"))]
    EncryptDir {
        /// Path of the directory to encrypt.
        #[arg(short = 'i', long)]
        input_dir: String,

        /// Path of the encrypted output file.
        #[arg(short = 'o', long)]
        output_file: String,

        /// Path to the public keys directory.
        #[arg(short = 'd', long, default_value = "keys")]
        public_key_directory: String,

        /// Version of the public key to use (can be specified multiple times for multiple recipients)
        #[arg(short = 'v', long, required = true)]
        key_versions: Vec<String>,

        /// Optional password (leave empty otherwise).
        #[arg(short = 'w', long, default_value = "")]
        password: String,

        /// The symmetric algorithm to use for encryption.
        #[arg(long, value_enum, default_value_t = CliSymmetricAlgorithm::Aes)]
        sym_algo: CliSymmetricAlgorithm,
    },

    /// Decrypts an entire directory.
    #[command(alias("decdir"))]
    DecryptDir {
        /// Path of the encrypted file.
        #[arg(short = 'i', long)]
        input_file: String,

        /// Path of the output directory.
        #[arg(short = 'o', long)]
        output_dir: String,

        /// Path to the private keys directory.
        #[arg(short = 'k', long, default_value = "keys")]
        private_key_directory: String,

        /// Version of the private key.
        #[arg(short = 'v', long)]
        key_version: String,

        /// Optional password.
        #[arg(short = 'w', long, default_value = "")]
        password: String,

        /// Passphrase for the private key
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Rotates an encryption key.
    #[command(alias("rk"))]
    RotateKey {
        /// The old key version.
        #[arg(long)]
        old_version: String,

        /// The new key version.
        #[arg(long)]
        new_version: String,

        /// The key directory.
        #[arg(short = 'k', long, default_value = "keys")]
        key_directory: String,

        /// The new key size (optional, default: 2048).
        #[arg(short = 's', long)]
        key_size: Option<u32>,

        /// A single file to re-encrypt.
        #[arg(short = 'f', long, conflicts_with = "directory")]
        file: Option<String>,

        /// A directory of files to re-encrypt.
        #[arg(short = 'd', long, conflicts_with = "file")]
        directory: Option<String>,

        /// Passphrase for the private keys
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Starts the transparent encryption daemon.
    #[cfg(feature = "daemon")]
    Daemon {
        /// Port to listen on
        #[arg(short, long, default_value_t = 3000)]
        port: u16,

        /// Directory where keys are stored
        #[arg(short = 'd', long, default_value = "keys")]
        key_directory: String,

        /// Key version to use (e.g., "v1")
        #[arg(short = 'v', long)]
        key_version: String,
    },
}

#[tokio::main]
async fn main() {
    metrics::init_metrics();
    let args = Cli::parse();

    // The main logic is wrapped in a closure to handle errors easily
    let result: Result<(), String> = async {
        match args.command {
            Commands::Generate {
                version,
                directory,
                key_size,
                passphrase,
                key_type,
            } => {
                let start = metrics::metrics_start();
                let result: Result<(), String> = (async {
                    if let Err(e) = std::fs::create_dir_all(&directory) {
                        return Err(format!(
                            "could not create key directory '{}': {}",
                            directory, e
                        ));
                    }
                    let private_key_path = format!("{}/private_key_{}.pem", directory, version);
                    let public_key_path = format!("{}/public_key_{}.pem", directory, version);

                    match key_type {
                        KeyType::Rsa => {
                            #[cfg(feature = "interactive")]
                            let spinner = {
                                let s = ProgressBar::new_spinner();
                                s.set_style(
                                    ProgressStyle::with_template("{spinner} {msg}")
                                        .unwrap()
                                        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
                                );
                                s.set_message("Generating RSA keys...");
                                s.enable_steady_tick(Duration::from_millis(100));
                                s
                            };
                            #[cfg(not(feature = "interactive"))]
                            println!("Generating RSA keys...");

                            let (private_key, public_key) = generate_rsa_keys(key_size)
                                .map_err(|e| format!("could not generate RSA key pair: {}", e))?;

                            #[cfg(feature = "interactive")]
                            spinner.finish_with_message("RSA keys generated.");
                            #[cfg(not(feature = "interactive"))]
                            println!("RSA keys generated.");

                            save_keys_to_files(
                                &private_key,
                                &public_key,
                                &private_key_path,
                                &public_key_path,
                                passphrase.as_deref(),
                            )
                            .map_err(|e| format!("could not save keys to files: {}", e))?;
                        }
                        KeyType::Ecc => {
                            println!("Generating ECC keys (P-256)...");
                            let (secret_key, public_key) = ecc_utils::generate_ecc_keys()
                                .map_err(|e| format!("could not generate ECC key pair: {}", e))?;

                            ecc_utils::save_keys_to_files(
                                &secret_key,
                                &public_key,
                                &private_key_path,
                                &public_key_path,
                                passphrase.as_deref(),
                            )
                            .map_err(|e| format!("could not save ECC keys to files: {}", e))?;
                        }
                    }

                    println!("Keys saved successfully.");
                    println!("Private key: {}", private_key_path);
                    println!("Public key: {}", public_key_path);
                    Ok(())
                })
                .await;
                metrics::metrics_finish("generate", 0, start, result.is_ok());
                result?;
            }
            Commands::Encrypt { password } => {
                let start = metrics::metrics_start();
                let payload_size = password.len() as u64;
                let result: Result<(), String> = (async {
                    let config = IronCryptConfig::default();
                    let crypt = IronCrypt::new(config, ironcrypt::DataType::Generic)
                        .await
                        .map_err(|e| format!("could not initialize encryption module: {}", e))?;
                    let encrypted_hash = crypt
                        .encrypt_password(&password)
                        .map_err(|e| format!("could not encrypt password: {}", e))?;
                    println!("{}", encrypted_hash);
                    Ok(())
                })
                .await;
                metrics::metrics_finish("encrypt", payload_size, start, result.is_ok());
                result?;
            }
            Commands::Decrypt {
                password,
                data,
                file,
                key_directory,
                passphrase,
            } => {
                let start = metrics::metrics_start();
                let (payload_size, result) = match (async {
                    let encrypted_data = if let Some(s) = data {
                        s
                    } else if let Some(f) = file {
                        std::fs::read_to_string(&f).map_err(|e| {
                            format!("could not read file '{}': {}", f, e)
                        })?
                    } else {
                        return Err("please provide encrypted data with --data or --file.".to_string());
                    };
                    let payload_size = encrypted_data.len() as u64;

                    let ed: ironcrypt::EncryptedData = serde_json::from_str(&encrypted_data)
                        .map_err(|e| format!("Could not parse encrypted data: {}", e))?;

                    let key_version = match &ed.recipient_info {
                        ironcrypt::RecipientInfo::Rsa { key_version, .. } => key_version.clone(),
                        ironcrypt::RecipientInfo::Ecc { key_version, .. } => key_version.clone(),
                    };

                    let mut config = IronCryptConfig::default();
                    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
                    data_type_config.insert(
                        ironcrypt::DataType::Generic,
                        ironcrypt::config::KeyManagementConfig {
                            key_directory,
                            key_version, // Use key version from file
                            passphrase,
                        },
                    );
                    config.data_type_config = Some(data_type_config);

                    let crypt = IronCrypt::new(config, ironcrypt::DataType::Generic)
                        .await
                        .map_err(|e| format!("could not initialize encryption module: {}", e))?;

                    if crypt
                        .verify_password(&encrypted_data, &password)
                        .map_err(|e| e.to_string())?
                    {
                        println!("Password correct.");
                    } else {
                        return Err("incorrect password or hash not found.".into());
                    }
                    Ok((payload_size, ()))
                })
                .await
                {
                    Ok((size, _)) => (size, Ok(())),
                    Err(e) => (0, Err(e)),
                };
                metrics::metrics_finish("decrypt", payload_size, start, result.is_ok());
                result?;
            }
            Commands::EncryptFile {
                input_file,
                output_file,
                public_key_directory,
                key_versions,
                mut password,
                sym_algo,
                signing_key_version,
                signing_key_passphrase,
            } => {
                let start = metrics::metrics_start();
                let payload_size = std::fs::metadata(&input_file).map(|m| m.len()).unwrap_or(0);
                let result: Result<(), String> = (async {
                    let mut source = File::open(&input_file)
                        .map_err(|e| format!("could not open input file '{}': {}", input_file, e))?;
                    let mut dest = File::create(&output_file).map_err(|e| {
                        format!("could not create output file '{}': {}", output_file, e)
                    })?;

                    let mut public_keys = Vec::new();
                    for v in &key_versions {
                        let public_key_path =
                            format!("{}/public_key_{}.pem", public_key_directory, v);
                        let key = ironcrypt::load_any_public_key(&public_key_path).map_err(|e| {
                            format!("could not load public key '{}': {}", public_key_path, e)
                        })?;
                        public_keys.push(key);
                    }

                    let recipients: Vec<(&PublicKey, &str)> = public_keys
                        .iter()
                        .zip(key_versions.iter().map(|s| s.as_str()))
                        .collect();

                    let signing_key_data;
                    let signing_key_version_string = signing_key_version;
                    let signing_key = if let Some(ref version) = signing_key_version_string {
                        let private_key_path =
                            format!("{}/private_key_{}.pem", public_key_directory, version);
                        signing_key_data = ironcrypt::load_any_private_key(&private_key_path, signing_key_passphrase.as_deref())
                            .map_err(|e| {
                                format!("could not load signing private key '{}': {}", private_key_path, e)
                            })?;
                        Some((&signing_key_data, version.as_str()))
                    } else {
                        None
                    };

                    let criteria = PasswordCriteria::default();
                    let argon_cfg = Argon2Config::default();

                    let hash_password = !password.is_empty();
                    let algo = match sym_algo {
                        CliSymmetricAlgorithm::Aes => SymmetricAlgorithm::Aes256Gcm,
                        CliSymmetricAlgorithm::Chacha20 => SymmetricAlgorithm::ChaCha20Poly1305,
                    };

                    encrypt_stream(
                        &mut source,
                        &mut dest,
                        &mut password,
                        recipients,
                        signing_key,
                        &criteria,
                        argon_cfg,
                        hash_password,
                        algo,
                    )
                    .map_err(|e| format!("could not encrypt file stream: {}", e))?;

                    println!("File encrypted successfully to '{}'.", output_file);
                    Ok(())
                })
                .await;
                metrics::metrics_finish("encrypt_file", payload_size, start, result.is_ok());
                result?;
            }
            Commands::EncryptPii {
                input_file,
                output_file,
                mut password,
            } => {
                let start = metrics::metrics_start();
                let payload_size = std::fs::metadata(&input_file).map(|m| m.len()).unwrap_or(0);
                let result: Result<(), String> = (async {
                    let config = IronCryptConfig::default();
                    let crypt = IronCrypt::new(config, ironcrypt::DataType::Pii)
                        .await
                        .map_err(|e| format!("could not initialize encryption module: {}", e))?;

                    let mut source = File::open(&input_file)
                        .map_err(|e| format!("could not open input file '{}': {}", input_file, e))?;
                    let mut dest = File::create(&output_file).map_err(|e| {
                        format!("could not create output file '{}': {}", output_file, e)
                    })?;

                    let public_key = crypt.public_key();
                    let key_version = crypt.key_version();
                    let recipients = vec![(public_key, key_version)];

                    let criteria = PasswordCriteria::default();
                    let argon_cfg = Argon2Config::default();

                    let hash_password = !password.is_empty();
                    encrypt_stream(
                        &mut source,
                        &mut dest,
                        &mut password,
                        recipients,
                        None,
                        &criteria,
                        argon_cfg,
                        hash_password,
                        SymmetricAlgorithm::Aes256Gcm,
                    )
                    .map_err(|e| format!("could not encrypt file stream: {}", e))?;

                    println!("File encrypted successfully to '{}'.", output_file);
                    Ok(())
                })
                .await;
                metrics::metrics_finish("encrypt_pii", payload_size, start, result.is_ok());
                result?;
            }
            Commands::EncryptBio {
                input_file,
                output_file,
                mut password,
            } => {
                let start = metrics::metrics_start();
                let payload_size = std::fs::metadata(&input_file).map(|m| m.len()).unwrap_or(0);
                let result: Result<(), String> = (async {
                    let config = IronCryptConfig::default();
                    let crypt = IronCrypt::new(config, ironcrypt::DataType::Biometric)
                        .await
                        .map_err(|e| format!("could not initialize encryption module: {}", e))?;

                    let mut source = File::open(&input_file)
                        .map_err(|e| format!("could not open input file '{}': {}", input_file, e))?;
                    let mut dest = File::create(&output_file).map_err(|e| {
                        format!("could not create output file '{}': {}", output_file, e)
                    })?;

                    let public_key = crypt.public_key();
                    let key_version = crypt.key_version();
                    let recipients = vec![(public_key, key_version)];

                    let criteria = PasswordCriteria::default();
                    let argon_cfg = Argon2Config::default();

                    let hash_password = !password.is_empty();
                    encrypt_stream(
                        &mut source,
                        &mut dest,
                        &mut password,
                        recipients,
                        None,
                        &criteria,
                        argon_cfg,
                        hash_password,
                        SymmetricAlgorithm::Aes256Gcm,
                    )
                    .map_err(|e| format!("could not encrypt file stream: {}", e))?;

                    println!("File encrypted successfully to '{}'.", output_file);
                    Ok(())
                })
                .await;
                metrics::metrics_finish("encrypt_bio", payload_size, start, result.is_ok());
                result?;
            }
            Commands::DecryptFile {
                input_file,
                output_file,
                private_key_directory,
                key_version,
                password,
                passphrase,
                verifying_key_version,
            } => {
                let start = metrics::metrics_start();
                let payload_size = std::fs::metadata(&input_file).map(|m| m.len()).unwrap_or(0);
                let result: Result<(), String> = (async {
                    let mut source = File::open(&input_file).map_err(|e| {
                        format!("could not open input file '{}': {}", input_file, e)
                    })?;
                    let mut dest = File::create(&output_file).map_err(|e| {
                        format!("could not create output file '{}': {}", output_file, e)
                    })?;

                    let private_key_path =
                        format!("{}/private_key_{}.pem", private_key_directory, key_version);
                    let private_key = ironcrypt::load_any_private_key(
                        &private_key_path,
                        passphrase.as_deref(),
                    )
                    .map_err(|e| {
                        format!("could not load private key '{}': {}", private_key_path, e)
                    })?;

                    let verifying_key_data;
                    let verifying_key = if let Some(version) = verifying_key_version {
                        let public_key_path =
                            format!("{}/public_key_{}.pem", private_key_directory, version);
                        verifying_key_data = ironcrypt::load_any_public_key(&public_key_path)
                            .map_err(|e| {
                                format!("could not load verifying public key '{}': {}", public_key_path, e)
                            })?;
                        Some(&verifying_key_data)
                    } else {
                        None
                    };

                    decrypt_stream(
                        &mut source,
                        &mut dest,
                        &private_key,
                        &key_version,
                        &password,
                        verifying_key,
                    )
                    .map_err(|e| format!("could not decrypt file stream: {}", e))?;

                    println!("File decrypted successfully to '{}'.", output_file);
                    Ok(())
                })
                .await;
                metrics::metrics_finish("decrypt_file", payload_size, start, result.is_ok());
                result?;
            }
            Commands::EncryptDir {
                input_dir,
                output_file,
                public_key_directory,
                key_versions,
                mut password,
                sym_algo,
            } => {
                let start = metrics::metrics_start();
                let closure_result: Result<(u64, ()), String> = (async {
                    let temp_tar_file = NamedTempFile::new()
                        .map_err(|e| format!("could not create temporary file: {}", e))?;
                    let tar_path = temp_tar_file.path().to_path_buf();

                    let file = File::create(&tar_path)
                        .map_err(|e| format!("could not create tar archive: {}", e))?;
                    let encoder = GzEncoder::new(file, Compression::default());
                    let mut builder = Builder::new(encoder);
                    builder.append_dir_all(".", &input_dir).map_err(|e| {
                        format!("could not archive directory '{}': {}", input_dir, e)
                    })?;
                    builder
                        .into_inner()
                        .map_err(|e| format!("could not finalize archive: {}", e))?
                        .finish()
                        .map_err(|e| format!("could not finish gzip encoding: {}", e))?;

                    let payload_size =
                        std::fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);

                    let mut source = File::open(&tar_path)
                        .map_err(|e| format!("could not open temporary archive: {}", e))?;
                    let mut dest = File::create(&output_file).map_err(|e| {
                        format!("could not create output file '{}': {}", output_file, e)
                    })?;

                    let mut public_keys = Vec::new();
                    for v in &key_versions {
                        let public_key_path =
                            format!("{}/public_key_{}.pem", public_key_directory, v);
                        let key = ironcrypt::load_any_public_key(&public_key_path).map_err(|e| {
                            format!("could not load public key '{}': {}", public_key_path, e)
                        })?;
                        public_keys.push(key);
                    }

                    let recipients: Vec<(&PublicKey, &str)> = public_keys
                        .iter()
                        .zip(key_versions.iter().map(|s| s.as_str()))
                        .collect();

                    let criteria = PasswordCriteria::default();
                    let argon_cfg = Argon2Config::default();

                    let hash_password = !password.is_empty();
                    let algo = match sym_algo {
                        CliSymmetricAlgorithm::Aes => SymmetricAlgorithm::Aes256Gcm,
                        CliSymmetricAlgorithm::Chacha20 => SymmetricAlgorithm::ChaCha20Poly1305,
                    };
                    encrypt_stream(
                        &mut source,
                        &mut dest,
                        &mut password,
                        recipients,
                        None,
                        &criteria,
                        argon_cfg,
                        hash_password,
                        algo,
                    )
                    .map_err(|e| format!("could not encrypt directory stream: {}", e))?;

                    println!("Directory encrypted successfully to '{}'.", output_file);
                    Ok((payload_size, ()))
                })
                .await;

                let (payload_size, op_result) = match closure_result {
                    Ok((size, ())) => (size, Ok(())),
                    Err(e) => (0, Err(e)),
                };

                metrics::metrics_finish("encrypt_dir", payload_size, start, op_result.is_ok());
                op_result?;
            }
            Commands::DecryptDir {
                input_file,
                output_dir,
                private_key_directory,
                key_version,
                password,
                passphrase,
            } => {
                let start = metrics::metrics_start();
                let payload_size = std::fs::metadata(&input_file).map(|m| m.len()).unwrap_or(0);
                let result: Result<(), String> = (async {
                    let temp_tar_file = NamedTempFile::new()
                        .map_err(|e| format!("could not create temporary file: {}", e))?;
                    let tar_path = temp_tar_file.path().to_path_buf();

                    let mut source = File::open(&input_file).map_err(|e| {
                        format!("could not open input file '{}': {}", input_file, e)
                    })?;
                    let mut dest = File::create(&tar_path)
                        .map_err(|e| format!("could not create temporary archive: {}", e))?;

                    let private_key_path =
                        format!("{}/private_key_{}.pem", private_key_directory, key_version);
                    let private_key = ironcrypt::load_any_private_key(
                        &private_key_path,
                        passphrase.as_deref(),
                    )
                    .map_err(|e| {
                        format!("could not load private key '{}': {}", private_key_path, e)
                    })?;

                    decrypt_stream(
                        &mut source,
                        &mut dest,
                        &private_key,
                        &key_version,
                        &password,
                        None,
                    )
                    .map_err(|e| format!("could not decrypt directory stream: {}", e))?;

                    let tar_gz = File::open(&tar_path)
                        .map_err(|e| format!("could not open decrypted archive: {}", e))?;
                    let gz_decoder = GzDecoder::new(tar_gz);
                    let mut archive = Archive::new(gz_decoder);
                    std::fs::create_dir_all(&output_dir).map_err(|e| {
                        format!("could not create output directory '{}': {}", output_dir, e)
                    })?;
                    archive.unpack(&output_dir).map_err(|e| {
                        format!("could not extract archive to '{}': {}", output_dir, e)
                    })?;

                    println!("Directory decrypted successfully to '{}'.", output_dir);
                    Ok(())
                })
                .await;
                metrics::metrics_finish("decrypt_dir", payload_size, start, result.is_ok());
                result?;
            }
            Commands::RotateKey {
                old_version,
                new_version,
                key_directory,
                key_size,
                file,
                directory,
                passphrase,
            } => {
                let start = metrics::metrics_start();
                let result: Result<(), String> = (async {
                    if directory.is_some() {
                        return Err("Key rotation for directories is not yet supported.".into());
                    }
                    let file_path = file.ok_or_else(|| {
                        "Please specify a file to rotate with --file".to_string()
                    })?;

                    // 1. Set up configs. We need an IronCrypt instance to call re_encrypt_data.
                    // The instance is configured for the *old* key, which is needed to decrypt the
                    // existing file's symmetric key.
                    let mut config = IronCryptConfig::default();
                    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
                    data_type_config.insert(
                        ironcrypt::DataType::Generic,
                        ironcrypt::config::KeyManagementConfig {
                            key_directory: key_directory.clone(),
                            key_version: old_version.clone(),
                            passphrase,
                        },
                    );
                    config.data_type_config = Some(data_type_config);

                    // 2. Generate new key if it doesn't exist.
                    let new_public_key_path =
                        format!("{}/public_key_{}.pem", key_directory, new_version);
                    if std::fs::metadata(&new_public_key_path).is_err() {
                        println!("Generating new key for version '{}'...", new_version);
                        let (private_key, public_key) =
                            generate_rsa_keys(key_size.unwrap_or(2048))
                                .map_err(|e| e.to_string())?;
                        let new_private_key_path =
                            format!("{}/private_key_{}.pem", key_directory, new_version);
                        save_keys_to_files(
                            &private_key,
                            &public_key,
                            &new_private_key_path,
                            &new_public_key_path,
                            None, // Passphrase for new key is not supported in this flow yet
                        )
                        .map_err(|e| e.to_string())?;
                    }

                    // 3. Create an IronCrypt instance configured for the old key.
                    // This instance will be used to call the re-encryption logic.
                    let crypt = IronCrypt::new(config, ironcrypt::DataType::Generic)
                        .await
                        .map_err(|e| e.to_string())?;

                    // 4. Load the new public key.
                    let new_public_key = ironcrypt::load_any_public_key(&new_public_key_path)
                        .map_err(|e| e.to_string())?;

                    // 5. Read the original encrypted file content.
                    // This is inefficient for large files but required because the current
                    // re_encrypt_data function works on in-memory data.
                    let encrypted_json =
                        std::fs::read_to_string(&file_path).map_err(|e| e.to_string())?;

                    // 6. Perform the key rotation.
                    let re_encrypted_json = crypt
                        .re_encrypt_data(&encrypted_json, &new_public_key, &new_version)
                        .map_err(|e| e.to_string())?;

                    // 7. Write the re-encrypted data back to the original file.
                    std::fs::write(&file_path, re_encrypted_json).map_err(|e| e.to_string())?;

                    println!(
                        "Key for file '{}' rotated successfully to version '{}'.",
                        file_path, new_version
                    );
                    Ok(())
                })
                .await;
                metrics::metrics_finish("rotate_key", 0, start, result.is_ok());
                result?;
            }
            #[cfg(feature = "daemon")]
            Commands::Daemon {
                port,
                key_directory,
                key_version,
            } => {
                let start = metrics::metrics_start();
                let result: Result<(), String> = (async {
                println!("Starting daemon...");
                let mut daemon_path = std::env::current_exe()
                    .map_err(|e| format!("Could not find current executable path: {}", e))?;
                daemon_path.pop();
                daemon_path.push("ironcryptd");

                let mut child = std::process::Command::new(daemon_path)
                    .arg("--port")
                    .arg(port.to_string())
                    .arg("--key-directory")
                    .arg(key_directory)
                    .arg("--key-version")
                    .arg(key_version)
                    .spawn()
                    .map_err(|e| format!("Failed to start daemon: {}", e))?;

                println!("Daemon started with PID: {}", child.id());
                child.wait().map_err(|e| format!("Daemon process failed: {}", e))?;
                    Ok(())
                })
                .await;
                metrics::metrics_finish("daemon_launch", 0, start, result.is_ok());
                result?;
            }
        }
        Ok(())
    }.await;

    if let Err(e) = result {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {

    use ironcrypt::config::{DataType, IronCryptConfig, KeyManagementConfig};
    use ironcrypt::ironcrypt::IronCrypt;
    use std::fs;
    use std::path::Path;

    #[tokio::test]
    async fn test_encrypt_and_verify() {
        let key_directory = "test_keys";

        if !Path::new(key_directory).exists() {
            fs::create_dir_all(key_directory).unwrap();
        }

        // Configuration
        let mut config = IronCryptConfig {
            rsa_key_size: 2048,
            ..Default::default()
        };
        let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
        data_type_config.insert(
            DataType::Generic,
            KeyManagementConfig {
                key_directory: key_directory.to_string(),
                key_version: "v1".to_string(),
                passphrase: None,
            },
        );
        config.data_type_config = Some(data_type_config);

        // Build IronCrypt
        // Here we use "v1" in the test, but it's just an example of usage
        let crypt = IronCrypt::new(config, ironcrypt::DataType::Generic)
            .await
            .expect("IronCrypt::new error");

        // Encrypt the password
        let password = "Str0ngP@ssw0rd!";
        let encrypted = crypt
            .encrypt_password(password)
            .expect("encrypt_password error");

        println!("Encrypted data JSON = {}", encrypted);

        // Verify
        let ok = crypt
            .verify_password(&encrypted, password)
            .expect("verify_password error");
        assert!(ok, "The password should be correct");

        // Verify a bad password
        let bad_ok = crypt
            .verify_password(&encrypted, "bad_password")
            .expect("verify_password should not fail on bad password, just return false");
        assert!(!bad_ok, "Should return false on a bad password");
    }
}
