use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use ironcrypt::{
    decrypt_stream, encrypt_stream, generate_rsa_keys, load_private_key, load_public_key,
    save_keys_to_files, Argon2Config, IronCrypt, IronCryptConfig, PasswordCriteria,
};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand;
use std::fs::File;
use std::io::{Read, Write};
use std::process;
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

#[derive(Subcommand)]
enum Commands {
    /// Generates an RSA key pair.
    Generate {
        #[arg(short = 'v', long)]
        version: String,

        #[arg(short = 'd', long, default_value = "keys")]
        directory: String,

        #[arg(short = 's', long, default_value_t = 2048)]
        key_size: u32,
    },

    /// Hashes and encrypts a password (existing logic).
    Encrypt {
        #[arg(short = 'w', long)]
        password: String,

        #[arg(short = 'd', long, default_value = "keys")]
        public_key_directory: String,

        /// Version of the public key (no default value)
        #[arg(short = 'v', long)]
        key_version: String,
    },

    /// Decrypts an encrypted password (existing logic).
    Decrypt {
        #[arg(short = 'w', long)]
        password: String,

        #[arg(short = 'k', long, default_value = "keys")]
        private_key_directory: String,

        /// Version of the private key (no default value)
        #[arg(short = 'v', long)]
        key_version: String,

        #[arg(short = 'd', long, conflicts_with = "file")]
        data: Option<String>,

        #[arg(short = 'f', long, conflicts_with = "data")]
        file: Option<String>,
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

        /// Version of the public key to use
        #[arg(short = 'v', long)]
        key_version: String,

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

        /// Version of the public key to use.
        #[arg(short = 'v', long)]
        key_version: String,

        /// Optional password (leave empty otherwise).
        #[arg(short = 'w', long, default_value = "")]
        password: String,
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
        #[arg(short='k', long, default_value = "keys")]
        key_directory: String,

        /// The new key size (optional, default: 2048).
        #[arg(short='s', long)]
        key_size: Option<u32>,

        /// A single file to re-encrypt.
        #[arg(short='f', long, conflicts_with="directory")]
        file: Option<String>,

        /// A directory of files to re-encrypt.
        #[arg(short='d', long, conflicts_with="file")]
        directory: Option<String>,
    }
}

fn main() {
    metrics::init_metrics();
    let args = Cli::parse();

    // The main logic is wrapped in a closure to handle errors easily
    let result = (|| -> Result<(), String> {
        match args.command {
            Commands::Generate {
                version,
                directory,
                key_size,
            } => {
                if let Err(e) = std::fs::create_dir_all(&directory) {
                    return Err(format!(
                        "could not create key directory '{}': {}",
                        directory, e
                    ));
                }
                let private_key_path = format!("{}/private_key_{}.pem", directory, version);
                let public_key_path = format!("{}/public_key_{}.pem", directory, version);

                let spinner = ProgressBar::new_spinner();
                spinner.set_style(
                    ProgressStyle::with_template("{spinner} {msg}")
                        .unwrap()
                        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
                );
                spinner.set_message("Generating RSA keys...");
                spinner.enable_steady_tick(Duration::from_millis(100));

                let (private_key, public_key) = generate_rsa_keys(key_size)
                    .map_err(|e| format!("could not generate RSA key pair: {}", e))?;
                spinner.finish_with_message("RSA keys generated.");

                save_keys_to_files(
                    &private_key,
                    &public_key,
                    &private_key_path,
                    &public_key_path,
                )
                .map_err(|e| format!("could not save keys to files: {}", e))?;

                println!("RSA keys saved successfully.");
                println!("Private key: {}", private_key_path);
                println!("Public key: {}", public_key_path);
            }
            Commands::Encrypt {
                password,
                public_key_directory,
                key_version,
            } => {
                let config = IronCryptConfig::default();
                let crypt = IronCrypt::new(&public_key_directory, &key_version, config)
                    .map_err(|e| format!("could not initialize encryption module: {}", e))?;
                let encrypted_hash = crypt
                    .encrypt_password(&password)
                    .map_err(|e| format!("could not encrypt password: {}", e))?;
                println!("{}", encrypted_hash);
            }
            Commands::Decrypt {
                password,
                private_key_directory,
                key_version,
                data,
                file,
            } => {
                let encrypted_data = if let Some(s) = data {
                    s
                } else if let Some(f) = file {
                    std::fs::read_to_string(&f)
                        .map_err(|e| format!("could not read file '{}': {}", f, e))?
                } else {
                    return Err("please provide encrypted data with --data or --file.".into());
                };

                let config = IronCryptConfig::default();
                let crypt = IronCrypt::new(&private_key_directory, &key_version, config)
                    .map_err(|e| format!("could not initialize encryption module: {}", e))?;

                if crypt.verify_password(&encrypted_data, &password).map_err(|e| e.to_string())? {
                    println!("Password correct.");
                } else {
                    return Err("incorrect password or hash not found.".into());
                }
            }
            Commands::EncryptFile {
                input_file,
                output_file,
                public_key_directory,
                key_version,
                mut password,
            } => {
                let mut source = File::open(&input_file)
                    .map_err(|e| format!("could not open input file '{}': {}", input_file, e))?;
                let mut dest = File::create(&output_file).map_err(|e| {
                    format!("could not create output file '{}': {}", output_file, e)
                })?;

                let public_key_path =
                    format!("{}/public_key_{}.pem", public_key_directory, key_version);
                let public_key = load_public_key(&public_key_path)
                    .map_err(|e| format!("could not load public key '{}': {}", public_key_path, e))?;

                let criteria = PasswordCriteria::default();
                let argon_cfg = Argon2Config::default();

                let hash_password = !password.is_empty();
                encrypt_stream(
                    &mut source,
                    &mut dest,
                    &mut password,
                    &public_key,
                    &criteria,
                    &key_version,
                    argon_cfg,
                    hash_password,
                )
                .map_err(|e| format!("could not encrypt file stream: {}", e))?;

                println!("File encrypted successfully to '{}'.", output_file);
            }
            Commands::DecryptFile {
                input_file,
                output_file,
                private_key_directory,
                key_version,
                password,
            } => {
                let mut source = File::open(&input_file)
                    .map_err(|e| format!("could not open input file '{}': {}", input_file, e))?;
                let mut dest = File::create(&output_file).map_err(|e| {
                    format!("could not create output file '{}': {}", output_file, e)
                })?;

                let private_key_path =
                    format!("{}/private_key_{}.pem", private_key_directory, key_version);
                let private_key = load_private_key(&private_key_path).map_err(|e| {
                    format!("could not load private key '{}': {}", private_key_path, e)
                })?;

                decrypt_stream(&mut source, &mut dest, &private_key, &password)
                    .map_err(|e| format!("could not decrypt file stream: {}", e))?;

                println!("File decrypted successfully to '{}'.", output_file);
            }
            Commands::EncryptDir {
                input_dir,
                output_file,
                public_key_directory,
                key_version,
                mut password,
            } => {
                let temp_tar_file = NamedTempFile::new()
                    .map_err(|e| format!("could not create temporary file: {}", e))?;
                let tar_path = temp_tar_file.path().to_path_buf();

                let file = File::create(&tar_path)
                    .map_err(|e| format!("could not create tar archive: {}", e))?;
                let encoder = GzEncoder::new(file, Compression::default());
                let mut builder = Builder::new(encoder);
                builder
                    .append_dir_all(".", &input_dir)
                    .map_err(|e| format!("could not archive directory '{}': {}", input_dir, e))?;
                builder
                    .into_inner()
                    .map_err(|e| format!("could not finalize archive: {}", e))?
                    .finish()
                    .map_err(|e| format!("could not finish gzip encoding: {}", e))?;

                let mut source = File::open(&tar_path)
                    .map_err(|e| format!("could not open temporary archive: {}", e))?;
                let mut dest = File::create(&output_file).map_err(|e| {
                    format!("could not create output file '{}': {}", output_file, e)
                })?;

                let public_key_path =
                    format!("{}/public_key_{}.pem", public_key_directory, key_version);
                let public_key = load_public_key(&public_key_path)
                    .map_err(|e| format!("could not load public key '{}': {}", public_key_path, e))?;

                let criteria = PasswordCriteria::default();
                let argon_cfg = Argon2Config::default();

                let hash_password = !password.is_empty();
                encrypt_stream(
                    &mut source,
                    &mut dest,
                    &mut password,
                    &public_key,
                    &criteria,
                    &key_version,
                    argon_cfg,
                    hash_password,
                )
                .map_err(|e| format!("could not encrypt directory stream: {}", e))?;

                println!("Directory encrypted successfully to '{}'.", output_file);
            }
            Commands::DecryptDir {
                input_file,
                output_dir,
                private_key_directory,
                key_version,
                password,
            } => {
                let temp_tar_file = NamedTempFile::new()
                    .map_err(|e| format!("could not create temporary file: {}", e))?;
                let tar_path = temp_tar_file.path().to_path_buf();

                let mut source = File::open(&input_file)
                    .map_err(|e| format!("could not open input file '{}': {}", input_file, e))?;
                let mut dest = File::create(&tar_path)
                    .map_err(|e| format!("could not create temporary archive: {}", e))?;

                let private_key_path =
                    format!("{}/private_key_{}.pem", private_key_directory, key_version);
                let private_key = load_private_key(&private_key_path).map_err(|e| {
                    format!("could not load private key '{}': {}", private_key_path, e)
                })?;

                decrypt_stream(&mut source, &mut dest, &private_key, &password)
                    .map_err(|e| format!("could not decrypt directory stream: {}", e))?;

                let tar_gz = File::open(&tar_path)
                    .map_err(|e| format!("could not open decrypted archive: {}", e))?;
                let gz_decoder = GzDecoder::new(tar_gz);
                let mut archive = Archive::new(gz_decoder);
                std::fs::create_dir_all(&output_dir)
                    .map_err(|e| format!("could not create output directory '{}': {}", output_dir, e))?;
                archive
                    .unpack(&output_dir)
                    .map_err(|e| format!("could not extract archive to '{}': {}", output_dir, e))?;

                println!("Directory decrypted successfully to '{}'.", output_dir);
            }
            Commands::RotateKey {
                old_version,
                new_version,
                key_directory,
                key_size,
                file,
                directory,
            } => {
                use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
                use ironcrypt::EncryptedStreamHeader;
                use base64::Engine;
                use rsa::Oaep;
                use sha2::Sha256;

                if directory.is_some() {
                    return Err("Key rotation for directories is not yet supported.".into());
                }
                let file_path = file.ok_or_else(|| {
                    "Please specify a file to rotate with --file".to_string()
                })?;

                // 1. Generate new key if it doesn't exist
                let new_key_size = key_size.unwrap_or(2048);
                let new_public_key_path =
                    format!("{}/public_key_{}.pem", key_directory, new_version);
                if std::fs::metadata(&new_public_key_path).is_err() {
                    let (private_key, public_key) = generate_rsa_keys(new_key_size).map_err(|e| e.to_string())?;
                    let new_private_key_path =
                        format!("{}/private_key_{}.pem", key_directory, new_version);
                    save_keys_to_files(
                        &private_key,
                        &public_key,
                        &new_private_key_path,
                        &new_public_key_path,
                    ).map_err(|e| e.to_string())?;
                }

                // 2. Load keys
                let old_private_key_path =
                    format!("{}/private_key_{}.pem", key_directory, old_version);
                let old_private_key = load_private_key(&old_private_key_path).map_err(|e| e.to_string())?;
                let new_public_key = load_public_key(&new_public_key_path).map_err(|e| e.to_string())?;

                // 3. Open files
                let mut source_file = File::open(&file_path).map_err(|e| e.to_string())?;
                let temp_dest_file = NamedTempFile::new().map_err(|e| e.to_string())?;

                // 4. Read old header
                let header_len = source_file.read_u64::<BigEndian>().map_err(|e| e.to_string())?;
                let mut header_bytes = vec![0; header_len as usize];
                source_file.read_exact(&mut header_bytes).map_err(|e| e.to_string())?;
                let old_header: EncryptedStreamHeader = serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;

                if old_header.key_version != old_version {
                    return Err(format!(
                        "File key version '{}' does not match expected old version '{}'",
                        old_header.key_version, old_version
                    ));
                }

                // 5. Re-encrypt symmetric key
                let sym_key_ciphertxt = base64::engine::general_purpose::STANDARD.decode(&old_header.encrypted_symmetric_key).map_err(|e| e.to_string())?;
                let sym_key_plaintxt = old_private_key.decrypt(Oaep::new::<Sha256>(), &sym_key_ciphertxt).map_err(|e| e.to_string())?;
                let new_sym_key_ciphertxt = new_public_key.encrypt(&mut rand::rngs::OsRng, Oaep::new::<Sha256>(), &sym_key_plaintxt).map_err(|e| e.to_string())?;

                // 6. Write new header and copy ciphertext
                let new_header = EncryptedStreamHeader {
                    key_version: new_version.clone(),
                    encrypted_symmetric_key: base64::engine::general_purpose::STANDARD.encode(&new_sym_key_ciphertxt),
                    nonce: old_header.nonce,
                    password_hash: old_header.password_hash,
                };
                let new_header_json = serde_json::to_string(&new_header).map_err(|e| e.to_string())?;

                {
                    let mut temp_writer = std::io::BufWriter::new(&temp_dest_file);
                    temp_writer.write_u64::<BigEndian>(new_header_json.len() as u64).map_err(|e| e.to_string())?;
                    temp_writer.write_all(new_header_json.as_bytes()).map_err(|e| e.to_string())?;
                    std::io::copy(&mut source_file, &mut temp_writer).map_err(|e| e.to_string())?;
                }

                // 7. Replace original file
                temp_dest_file.persist(&file_path).map_err(|e| e.to_string())?;

                println!("Key for file '{}' rotated successfully to version '{}'.", file_path, new_version);
            }
        }
        Ok(())
    })();

    if let Err(e) = result {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {

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

        // Configuration
        let config = IronCryptConfig {
            rsa_key_size: 2048,
            ..Default::default()
        };
        // Build IronCrypt
        // Here we use "v1" in the test, but it's just an example of usage
        let crypt = IronCrypt::new(key_directory, "v1", config).expect("IronCrypt::new error");

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
        let bad_ok = crypt.verify_password(&encrypted, "bad_password");
        assert!(
            bad_ok.is_err(),
            "Should fail on a bad password"
        );
    }
}