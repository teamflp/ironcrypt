use clap::{Parser, Subcommand};
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
use std::fs::File;
use std::io::{Read, Write};
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
    let args = Cli::parse();

    match args.command {
        // ---------------------------------------------------------------
        // 1) Generating an RSA key pair
        // ---------------------------------------------------------------
        Commands::Generate {
            version,
            directory,
            key_size,
        } => {
            if let Err(e) = std::fs::create_dir_all(&directory) {
                eprintln!("error: could not create key directory '{}': {}", directory, e);
                process::exit(1);
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

            let (private_key, public_key) = match generate_rsa_keys(key_size) {
                Ok((pk, pubk)) => (pk, pubk),
                Err(e) => {
                    spinner.finish_with_message("Error.");
                    eprintln!("error: could not generate RSA key pair: {}", e);
                    process::exit(1);
                }
            };
            spinner.finish_with_message("RSA keys generated.");

            match save_keys_to_files(&private_key, &public_key, &private_key_path, &public_key_path) {
                Ok(_) => {
                    println!("RSA keys saved successfully.");
                    println!("Private key: {private_key_path}");
                    println!("Public key: {public_key_path}");
                }
                Err(e) => {
                    eprintln!("error: could not save keys to files: {}", e);
                    process::exit(1);
                }
            }
        }

        // ---------------------------------------------------------------
        // 2) Encrypting a password
        // ---------------------------------------------------------------
        Commands::Encrypt {
            password,
            public_key_directory,
            key_version,
        } => {
            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&public_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: could not initialize encryption module: {}", e);
                    process::exit(1);
                }
            };
            match crypt.encrypt_password(&password) {
                Ok(encrypted_hash) => {
                    let file_path = "encrypted_data.json";
                    match File::create(file_path) {
                        Ok(mut file) => {
                            if let Err(e) = file.write_all(encrypted_hash.as_bytes()) {
                                eprintln!("error: could not write encrypted data to file '{}': {}", file_path, e);
                                process::exit(1);
                            } else {
                                println!("Password encrypted to '{file_path}'.");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: could not create output file '{}': {}", file_path, e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: could not encrypt password: {}", e);
                    process::exit(1);
                }
            }
        }

        // ---------------------------------------------------------------
        // 3) Decrypting/verifying a password
        // ---------------------------------------------------------------
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
                match std::fs::read_to_string(&f) {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!("error: could not read file '{}': {}", f, e);
                        process::exit(1);
                    }
                }
            } else {
                eprintln!("error: please provide encrypted data with --data or --file.");
                process::exit(1);
            };

            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&private_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: could not initialize encryption module: {}", e);
                    process::exit(1);
                }
            };

            match crypt.verify_password(&encrypted_data, &password) {
                Ok(ok) => {
                    if ok {
                        println!("Password correct.");
                    } else {
                        eprintln!("error: incorrect password or hash not found.");
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("error: could not verify password: {}", e);
                    process::exit(1);
                }
            }
        }

        // ---------------------------------------------------------------
        // 4) Encrypting a binary file
        // ---------------------------------------------------------------
        Commands::EncryptFile {
            input_file,
            output_file,
            public_key_directory,
            key_version,
            password,
        } => {
            // Read the binary file
            let mut file_data = vec![];
            match File::open(&input_file) {
                Ok(mut f) => {
                    if let Err(e) = f.read_to_end(&mut file_data) {
                        eprintln!("error: could not read input file '{}': {}", input_file, e);
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("error: could not open input file '{}': {}", input_file, e);
                    process::exit(1);
                }
            }

            // Build IronCrypt
            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&public_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: could not initialize encryption module: {}", e);
                    process::exit(1);
                }
            };

            // Encrypt the binary data
            match crypt.encrypt_binary_data(&file_data, &password) {
                Ok(encrypted_json) => {
                    // Write the JSON
                    match File::create(&output_file) {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(encrypted_json.as_bytes()) {
                                eprintln!("error: could not write encrypted file '{}': {}", output_file, e);
                                process::exit(1);
                            } else {
                                println!("Binary file encrypted and saved to '{output_file}'.");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: could not create output file '{}': {}", output_file, e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: could not encrypt file: {}", e);
                    process::exit(1);
                }
            }
        }

        // ---------------------------------------------------------------
        // 5) Decrypting a binary file
        // ---------------------------------------------------------------
        Commands::EncryptDir {
            input_dir,
            output_file,
            public_key_directory,
            key_version,
            password,
        } => {
            // 1. Archive and compress the directory in memory
            let mut archive_data = Vec::new();
            {
                let encoder = GzEncoder::new(&mut archive_data, Compression::default());
                let mut builder = Builder::new(encoder);
                if let Err(e) = builder.append_dir_all(".", &input_dir) {
                    eprintln!("error: could not archive directory '{}': {}", input_dir, e);
                    process::exit(1);
                }
                // Finalize the archive
                if let Err(e) = builder.into_inner() {
                     eprintln!("error: could not finalize archive: {}", e);
                    process::exit(1);
                }
            }

            // 2. Encrypt the archive data
            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&public_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: could not initialize encryption module: {}", e);
                    process::exit(1);
                }
            };

            match crypt.encrypt_binary_data(&archive_data, &password) {
                Ok(encrypted_json) => {
                    if let Err(e) = std::fs::write(&output_file, encrypted_json) {
                         eprintln!("error: could not write encrypted file '{}': {}", output_file, e);
                        process::exit(1);
                    } else {
                        println!("Directory encrypted and saved to '{}'.", output_file);
                    }
                }
                Err(e) => {
                    eprintln!("error: could not encrypt directory archive: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::DecryptDir {
            input_file,
            output_dir,
            private_key_directory,
            key_version,
            password,
        } => {
            // 1. Read and decrypt the file
            let encrypted_json = match std::fs::read_to_string(&input_file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: could not read encrypted file '{}': {}", input_file, e);
                    process::exit(1);
                }
            };

            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&private_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: could not initialize encryption module: {}", e);
                    process::exit(1);
                }
            };

            let decrypted_data = match crypt.decrypt_binary_data(&encrypted_json, &password) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: could not decrypt data: {}", e);
                    process::exit(1);
                }
            };

            // 2. Decompress and extract the archive
            let gz_decoder = GzDecoder::new(decrypted_data.as_slice());
            let mut archive = Archive::new(gz_decoder);
            if let Err(e) = archive.unpack(&output_dir) {
                eprintln!("error: could not extract archive to '{}': {}", output_dir, e);
                process::exit(1);
            }

            println!("Directory decrypted and extracted to '{}'.", output_dir);
        }
        Commands::RotateKey {
            old_version,
            new_version,
            key_directory,
            key_size,
            file,
            directory,
        } => {
            // 1. Determine the new key size
            let new_key_size = key_size.unwrap_or(2048);

            // 2. Create IronCrypt instances for the old and new versions
            let old_config = IronCryptConfig::default();
            let mut new_config = IronCryptConfig::default();
            new_config.rsa_key_size = new_key_size;

            let old_crypt = match IronCrypt::new(&key_directory, &old_version, old_config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: could not load old key (version {}): {}", old_version, e);
                    process::exit(1);
                }
            };

            // Creating `new_crypt` will generate the new key pair if it doesn't exist
            let _new_crypt = match IronCrypt::new(&key_directory, &new_version, new_config) {
                 Ok(c) => c,
                Err(e) => {
                    eprintln!("error: could not create new key (version {}): {}", new_version, e);
                    process::exit(1);
                }
            };

            let new_public_key_path = format!("{}/public_key_{}.pem", key_directory, new_version);
            let new_public_key = match ironcrypt::load_public_key(&new_public_key_path) {
                 Ok(k) => k,
                Err(e) => {
                    eprintln!("error: could not load new public key '{}': {}", new_public_key_path, e);
                    process::exit(1);
                }
            };

            // 3. Determine the list of files to process
            let files_to_process = if let Some(f) = file {
                vec![f]
            } else if let Some(d) = directory {
                match std::fs::read_dir(&d) {
                    Ok(entries) => entries.filter_map(|entry| {
                        entry.ok().and_then(|e| {
                            let path = e.path();
                            if path.is_file() {
                                path.to_str().map(String::from)
                            } else {
                                None
                            }
                        })
                    }).collect(),
                    Err(e) => {
                        eprintln!("error: could not read directory '{}': {}", d, e);
                        process::exit(1);
                    }
                }
            } else {
                eprintln!("error: please specify a file (--file) or a directory (--directory).");
                process::exit(1);
            };

            // 4. Process each file
            for file_path in files_to_process {
                println!("Processing file: {}...", file_path);
                let encrypted_json = match std::fs::read_to_string(&file_path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("warning: could not read file '{}', skipping. Reason: {}", file_path, e);
                        continue;
                    }
                };

                match old_crypt.re_encrypt_data(&encrypted_json, &new_public_key, &new_version) {
                    Ok(new_json) => {
                        if let Err(e) = std::fs::write(&file_path, new_json) {
                            eprintln!("warning: could not rewrite file '{}', skipping. Reason: {}", file_path, e);
                        }
                    }
                    Err(e) => {
                         eprintln!("warning: could not re-encrypt file '{}', skipping. Reason: {}", file_path, e);
                    }
                }
            }

            println!("\nKey rotation completed successfully.");
        }
        Commands::DecryptFile {
            input_file,
            output_file,
            private_key_directory,
            key_version,
            password,
        } => {
            // Read the encrypted JSON
            let mut encrypted_json = String::new();
            match File::open(&input_file) {
                Ok(mut f) => {
                    if let Err(e) = f.read_to_string(&mut encrypted_json) {
                        eprintln!("error: could not read input file '{}': {}", input_file, e);
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("error: could not open input file '{}': {}", input_file, e);
                    process::exit(1);
                }
            }

            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&private_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: could not initialize encryption module: {}", e);
                    process::exit(1);
                }
            };

            // Decrypt
            match crypt.decrypt_binary_data(&encrypted_json, &password) {
                Ok(plaintext_bytes) => {
                    // Write the decrypted binary
                    match File::create(&output_file) {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(&plaintext_bytes) {
                                eprintln!("error: could not write decrypted file '{}': {}", output_file, e);
                                process::exit(1);
                            } else {
                                println!("Binary file decrypted to '{output_file}'.");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: could not create output file '{}': {}", output_file, e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: could not decrypt file: {}", e);
                    process::exit(1);
                }
            }
        }
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
        let mut config = IronCryptConfig::default();
        config.rsa_key_size = 2048;

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
