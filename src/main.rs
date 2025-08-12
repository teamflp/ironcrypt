use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use ironcrypt::{
    generate_rsa_keys,
    save_keys_to_files,
    IronCrypt,
    IronCryptConfig,
};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::process;
use std::time::Duration;
use tar::{Archive, Builder};

#[derive(Parser)]
#[command(
    name = "ironcrypt",
    about = "Generation and management of RSA keys for IronCrypt."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Set the output format.
    #[arg(global = true, long, value_enum, default_value_t = OutputFormat::Text, env = "IRONCRYPT_FORMAT")]
    format: OutputFormat,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputFormat {
    /// Human-readable text format.
    Text,
    /// JSON format for machine-readable output.
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates an RSA key pair.
    Generate {
        /// The version of the key pair.
        #[arg(short = 'v', long, env = "IRONCRYPT_KEY_VERSION")]
        version: String,

        /// The directory where the keys will be saved.
        #[arg(short = 'd', long, default_value = "keys", env = "IRONCRYPT_KEY_DIR")]
        directory: String,

        /// The size of the RSA key in bits.
        #[arg(short = 's', long, default_value_t = 2048, env = "IRONCRYPT_KEY_SIZE")]
        key_size: u32,
    },

    /// Hashes and encrypts a password.
    Encrypt {
        /// The password to hash and encrypt.
        #[arg(short = 'w', long, env = "IRONCRYPT_PASSWORD")]
        password: String,

        /// The directory containing the public key file.
        #[arg(short = 'd', long, default_value = "keys", env = "IRONCRYPT_PUBKEY_DIR")]
        public_key_directory: String,

        /// The version of the public key to use.
        #[arg(short = 'v', long, env = "IRONCRYPT_KEY_VERSION")]
        key_version: String,
    },

    /// Decrypts and verifies a password.
    Decrypt {
        /// The password to verify.
        #[arg(short = 'w', long, env = "IRONCRYPT_PASSWORD")]
        password: String,

        /// The directory containing the private key file.
        #[arg(short = 'k', long, default_value = "keys", env = "IRONCRYPT_PRIVKEY_DIR")]
        private_key_directory: String,

        /// The version of the private key to use.
        #[arg(short = 'v', long, env = "IRONCRYPT_KEY_VERSION")]
        key_version: String,

        /// The encrypted data as a string.
        #[arg(short = 'd', long, conflicts_with = "file", env = "IRONCRYPT_DATA")]
        data: Option<String>,

        /// The path to the file containing the encrypted data.
        #[arg(short = 'f', long, conflicts_with = "data", env = "IRONCRYPT_FILE")]
        file: Option<String>,
    },

    /// Encrypts a binary file using AES+RSA.
    #[command(
        alias("encfile"),
        alias("efile"),
        alias("ef")
    )]
    EncryptFile {
        /// Path to the binary file to encrypt.
        #[arg(short = 'i', long, env = "IRONCRYPT_INPUT")]
        input_file: String,

        /// Path for the encrypted output file (JSON).
        #[arg(short = 'o', long, env = "IRONCRYPT_OUTPUT")]
        output_file: String,

        /// Directory of the public keys.
        #[arg(short = 'd', long, default_value = "keys", env = "IRONCRYPT_PUBKEY_DIR")]
        public_key_directory: String,

        /// Version of the public key to use.
        #[arg(short = 'v', long, env = "IRONCRYPT_KEY_VERSION")]
        key_version: String,

        /// Optional password (leave empty if not needed).
        #[arg(short = 'w', long, default_value = "", env = "IRONCRYPT_PASSWORD")]
        password: String,
    },

    /// Decrypts a binary file.
    #[command(
        alias("decfile"),
        alias("dfile"),
        alias("df")
    )]
    DecryptFile {
        /// Path to the encrypted JSON file.
        #[arg(short = 'i', long, env = "IRONCRYPT_INPUT")]
        input_file: String,

        /// Path for the decrypted binary file.
        #[arg(short = 'o', long, env = "IRONCRYPT_OUTPUT")]
        output_file: String,

        /// Directory of the private keys.
        #[arg(short = 'k', long, default_value = "keys", env = "IRONCRYPT_PRIVKEY_DIR")]
        private_key_directory: String,

        /// Version of the private key to use.
        #[arg(short = 'v', long, env = "IRONCRYPT_KEY_VERSION")]
        key_version: String,

        /// Optional password.
        #[arg(short = 'w', long, default_value = "", env = "IRONCRYPT_PASSWORD")]
        password: String,
    },

    /// Encrypts an entire directory.
    #[command(alias("encdir"))]
    EncryptDir {
        /// Path to the directory to encrypt.
        #[arg(short = 'i', long, env = "IRONCRYPT_INPUT")]
        input_dir: String,

        /// Path for the encrypted output file.
        #[arg(short = 'o', long, env = "IRONCRYPT_OUTPUT")]
        output_file: String,

        /// Directory of the public keys.
        #[arg(short = 'd', long, default_value = "keys", env = "IRONCRYPT_PUBKEY_DIR")]
        public_key_directory: String,

        /// Version of the public key to use.
        #[arg(short = 'v', long, env = "IRONCRYPT_KEY_VERSION")]
        key_version: String,

        /// Optional password.
        #[arg(short = 'w', long, default_value = "", env = "IRONCRYPT_PASSWORD")]
        password: String,
    },

    /// Decrypts an entire directory.
    #[command(alias("decdir"))]
    DecryptDir {
        /// Path to the encrypted file.
        #[arg(short = 'i', long, env = "IRONCRYPT_INPUT")]
        input_file: String,

        /// Path for the output directory.
        #[arg(short = 'o', long, env = "IRONCRYPT_OUTPUT")]
        output_dir: String,

        /// Directory of the private keys.
        #[arg(short = 'k', long, default_value = "keys", env = "IRONCRYPT_PRIVKEY_DIR")]
        private_key_directory: String,

        /// Version of the private key.
        #[arg(short = 'v', long, env = "IRONCRYPT_KEY_VERSION")]
        key_version: String,

        /// Optional password.
        #[arg(short = 'w', long, default_value = "", env = "IRONCRYPT_PASSWORD")]
        password: String,
    },

    /// Rotates an encryption key.
    #[command(alias("rk"))]
    RotateKey {
        /// The old key version.
        #[arg(long, env = "IRONCRYPT_OLD_KEY_VERSION")]
        old_version: String,

        /// The new key version.
        #[arg(long, env = "IRONCRYPT_NEW_KEY_VERSION")]
        new_version: String,

        /// The directory where keys are stored.
        #[arg(short='k', long, default_value = "keys", env = "IRONCRYPT_KEY_DIR")]
        key_directory: String,

        /// The size for the new key (optional, defaults to 2048).
        #[arg(short='s', long, env = "IRONCRYPT_KEY_SIZE")]
        key_size: Option<u32>,

        /// A single file to re-encrypt.
        #[arg(short='f', long, conflicts_with="directory", env = "IRONCRYPT_FILE")]
        file: Option<String>,

        /// A directory of files to re-encrypt.
        #[arg(short='d', long, conflicts_with="file", env = "IRONCRYPT_DIR")]
        directory: Option<String>,
    }
}

// Structs for JSON output
#[derive(Serialize)]
struct JsonResponse<'a> {
    status: &'a str,
    data: Option<serde_json::Value>,
}

fn main() {
    let args = Cli::parse();
    let format = args.format;

    let result = match args.command {
        Commands::Generate {
            version,
            directory,
            key_size,
        } => handle_generate(format, version, directory, key_size),
        Commands::Encrypt {
            password,
            public_key_directory,
            key_version,
        } => handle_encrypt(format, password, public_key_directory, key_version),
        Commands::Decrypt {
            password,
            private_key_directory,
            key_version,
            data,
            file,
        } => handle_decrypt(format, password, private_key_directory, key_version, data, file),
        Commands::EncryptFile {
            input_file,
            output_file,
            public_key_directory,
            key_version,
            password,
        } => handle_encrypt_file(format, input_file, output_file, public_key_directory, key_version, password),
        Commands::DecryptFile {
            input_file,
            output_file,
            private_key_directory,
            key_version,
            password,
        } => handle_decrypt_file(format, input_file, output_file, private_key_directory, key_version, password),
        Commands::EncryptDir {
            input_dir,
            output_file,
            public_key_directory,
            key_version,
            password,
        } => handle_encrypt_dir(format, input_dir, output_file, public_key_directory, key_version, password),
        Commands::DecryptDir {
            input_file,
            output_dir,
            private_key_directory,
            key_version,
            password,
        } => handle_decrypt_dir(format, input_file, output_dir, private_key_directory, key_version, password),
        Commands::RotateKey {
            old_version,
            new_version,
            key_directory,
            key_size,
            file,
            directory,
        } => handle_rotate_key(format, old_version, new_version, key_directory, key_size, file, directory),
    };

    if let Err(e) = result {
        if format == OutputFormat::Json {
            let error_response = serde_json::json!({
                "status": "error",
                "error": e.to_string(),
            });
            eprintln!("{}", serde_json::to_string(&error_response).unwrap());
        } else {
            eprintln!("Error: {}", e);
        }
        process::exit(1);
    }
}

fn handle_generate(format: OutputFormat, version: String, directory: String, key_size: u32) -> Result<(), anyhow::Error> {
    if let Err(e) = std::fs::create_dir_all(&directory) {
        return Err(anyhow::anyhow!("failed to create key directory '{}': {}", directory, e));
    }
    let private_key_path = format!("{}/private_key_{}.pem", directory, version);
    let public_key_path = format!("{}/public_key_{}.pem", directory, version);

    let (private_key, public_key) = if format == OutputFormat::Text {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::with_template("{spinner} {msg}")?
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        spinner.set_message("Generating RSA keys...");
        spinner.enable_steady_tick(Duration::from_millis(100));
        let result = generate_rsa_keys(key_size)?;
        spinner.finish_with_message("RSA keys generated.");
        result
    } else {
        generate_rsa_keys(key_size)?
    };

    save_keys_to_files(&private_key, &public_key, &private_key_path, &public_key_path)?;

    if format == OutputFormat::Json {
        let response = JsonResponse {
            status: "success",
            data: Some(serde_json::json!({
                "private_key_path": private_key_path,
                "public_key_path": public_key_path,
            })),
        };
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!("RSA keys saved successfully.");
        println!("Private Key: {private_key_path}");
        println!("Public Key: {public_key_path}");
    }
    Ok(())
}

fn handle_encrypt(format: OutputFormat, password: String, public_key_directory: String, key_version: String) -> Result<(), anyhow::Error> {
    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(&public_key_directory, &key_version, config)?;
    let encrypted_hash = crypt.encrypt_password(&password)?;

    if format == OutputFormat::Json {
        println!("{}", encrypted_hash);
    } else {
        let file_path = "encrypted_data.json";
        let mut file = File::create(file_path)?;
        file.write_all(encrypted_hash.as_bytes())?;
        println!("Password encrypted to '{file_path}'.");
    }
    Ok(())
}

fn handle_decrypt(format: OutputFormat, password: String, private_key_directory: String, key_version: String, data: Option<String>, file: Option<String>) -> Result<(), anyhow::Error> {
    let encrypted_data = if let Some(s) = data {
        s
    } else if let Some(f) = file {
        std::fs::read_to_string(&f)?
    } else {
        return Err(anyhow::anyhow!("please provide encrypted data with --data or --file."));
    };

    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(&private_key_directory, &key_version, config)?;
    let is_valid = crypt.verify_password(&encrypted_data, &password)?;

    if format == OutputFormat::Json {
        let response = JsonResponse {
            status: "success",
            data: Some(serde_json::json!({
                "password_correct": is_valid,
            })),
        };
        println!("{}", serde_json::to_string(&response)?);
    } else {
        if is_valid {
            println!("Password correct.");
        } else {
            return Err(anyhow::anyhow!("incorrect password or hash not found."));
        }
    }
    Ok(())
}

fn handle_encrypt_file(format: OutputFormat, input_file: String, output_file: String, public_key_directory: String, key_version: String, password: String) -> Result<(), anyhow::Error> {
    let file_data = std::fs::read(&input_file)?;
    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(&public_key_directory, &key_version, config)?;
    let encrypted_json = crypt.encrypt_binary_data(&file_data, &password)?;
    std::fs::write(&output_file, encrypted_json)?;

    if format == OutputFormat::Json {
        let response = JsonResponse {
            status: "success",
            data: Some(serde_json::json!({
                "input_file": input_file,
                "output_file": output_file,
            })),
        };
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!("Binary file encrypted and saved to '{output_file}'.");
    }
    Ok(())
}

fn handle_decrypt_file(format: OutputFormat, input_file: String, output_file: String, private_key_directory: String, key_version: String, password: String) -> Result<(), anyhow::Error> {
    let encrypted_json = std::fs::read_to_string(&input_file)?;
    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(&private_key_directory, &key_version, config)?;
    let plaintext_bytes = crypt.decrypt_binary_data(&encrypted_json, &password)?;
    std::fs::write(&output_file, &plaintext_bytes)?;

    if format == OutputFormat::Json {
        let response = JsonResponse {
            status: "success",
            data: Some(serde_json::json!({
                "input_file": input_file,
                "output_file": output_file,
                "bytes_written": plaintext_bytes.len(),
            })),
        };
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!("Binary file decrypted to '{output_file}'.");
    }
    Ok(())
}

fn handle_encrypt_dir(format: OutputFormat, input_dir: String, output_file: String, public_key_directory: String, key_version: String, password: String) -> Result<(), anyhow::Error> {
    let mut archive_data = Vec::new();
    {
        let encoder = GzEncoder::new(&mut archive_data, Compression::default());
        let mut builder = Builder::new(encoder);
        builder.append_dir_all(".", &input_dir)?;
        builder.into_inner()?;
    }

    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(&public_key_directory, &key_version, config)?;
    let encrypted_json = crypt.encrypt_binary_data(&archive_data, &password)?;
    std::fs::write(&output_file, encrypted_json)?;

    if format == OutputFormat::Json {
        let response = JsonResponse {
            status: "success",
            data: Some(serde_json::json!({
                "input_dir": input_dir,
                "output_file": output_file,
            })),
        };
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!("Directory encrypted and saved to '{}'.", output_file);
    }
    Ok(())
}

fn handle_decrypt_dir(format: OutputFormat, input_file: String, output_dir: String, private_key_directory: String, key_version: String, password: String) -> Result<(), anyhow::Error> {
    let encrypted_json = std::fs::read_to_string(&input_file)?;
    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(&private_key_directory, &key_version, config)?;
    let decrypted_data = crypt.decrypt_binary_data(&encrypted_json, &password)?;

    let gz_decoder = GzDecoder::new(decrypted_data.as_slice());
    let mut archive = Archive::new(gz_decoder);
    archive.unpack(&output_dir)?;

    if format == OutputFormat::Json {
        let response = JsonResponse {
            status: "success",
            data: Some(serde_json::json!({
                "input_file": input_file,
                "output_dir": output_dir,
            })),
        };
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!("Directory decrypted and extracted to '{}'.", output_dir);
    }
    Ok(())
}

fn handle_rotate_key(format: OutputFormat, old_version: String, new_version: String, key_directory: String, key_size: Option<u32>, file: Option<String>, directory: Option<String>) -> Result<(), anyhow::Error> {
    let new_key_size = key_size.unwrap_or(2048);
    let old_config = IronCryptConfig::default();
    let mut new_config = IronCryptConfig::default();
    new_config.rsa_key_size = new_key_size;

    let old_crypt = IronCrypt::new(&key_directory, &old_version, old_config)?;
    let _new_crypt = IronCrypt::new(&key_directory, &new_version, new_config)?;

    let new_public_key_path = format!("{}/public_key_{}.pem", key_directory, new_version);
    let new_public_key = ironcrypt::load_public_key(&new_public_key_path)?;

    let files_to_process = if let Some(f) = file {
        vec![f]
    } else if let Some(d) = directory {
        std::fs::read_dir(&d)?
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    let path = e.path();
                    if path.is_file() {
                        path.to_str().map(String::from)
                    } else {
                        None
                    }
                })
            })
            .collect()
    } else {
        return Err(anyhow::anyhow!("please specify a file (--file) or a directory (--directory)."));
    };

    let mut processed_files = vec![];
    for file_path in &files_to_process {
        let encrypted_json = std::fs::read_to_string(file_path)?;
        let new_json = old_crypt.re_encrypt_data(&encrypted_json, &new_public_key, &new_version)?;
        std::fs::write(file_path, new_json)?;
        processed_files.push(file_path);
    }

    if format == OutputFormat::Json {
        let response = JsonResponse {
            status: "success",
            data: Some(serde_json::json!({
                "processed_files": processed_files,
                "new_key_version": new_version,
            })),
        };
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!("\nKey rotation completed successfully for {} file(s).", processed_files.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironcrypt::config::IronCryptConfig;
    use ironcrypt::ironcrypt::IronCrypt;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_encrypt_and_verify() {
        let key_directory = "test_keys";

        if !Path::new(key_directory).exists() {
            fs::create_dir_all(key_directory).unwrap();
        }

        let mut config = IronCryptConfig::default();
        config.rsa_key_size = 2048;

        let crypt = IronCrypt::new(key_directory, "v1", config).expect("Failed to call IronCrypt::new");

        let password = "Str0ngP@ssw0rd!";
        let encrypted = crypt
            .encrypt_password(password)
            .expect("Failed to call encrypt_password");

        println!("Encrypted data JSON = {}", encrypted);

        let ok = crypt
            .verify_password(&encrypted, password)
            .expect("Failed to call verify_password");
        assert!(ok, "The password should be correct");

        let bad_ok = crypt.verify_password(&encrypted, "bad_password");
        assert!(
            bad_ok.is_err(),
            "Should fail on a bad password"
        );
    }
}
