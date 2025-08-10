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
    about = "Génération et gestion des clés RSA pour IronCrypt."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Génère une paire de clés RSA.
    Generate {
        #[arg(short = 'v', long)]
        version: String,

        #[arg(short = 'd', long, default_value = "keys")]
        directory: String,

        #[arg(short = 's', long, default_value_t = 2048)]
        key_size: u32,
    },

    /// Hache et chiffre un mot de passe (logique existante).
    Encrypt {
        #[arg(short = 'w', long)]
        password: String,

        #[arg(short = 'd', long, default_value = "keys")]
        public_key_directory: String,

        /// Version de la clé publique (aucune valeur par défaut)
        #[arg(short = 'v', long)]
        key_version: String,
    },

    /// Déchiffre un mot de passe chiffré (logique existante).
    Decrypt {
        #[arg(short = 'w', long)]
        password: String,

        #[arg(short = 'k', long, default_value = "keys")]
        private_key_directory: String,

        /// Version de la clé privée (pas de valeur par défaut)
        #[arg(short = 'v', long)]
        key_version: String,

        #[arg(short = 'd', long, conflicts_with = "file")]
        data: Option<String>,

        #[arg(short = 'f', long, conflicts_with = "data")]
        file: Option<String>,
    },

    /// Chiffre un fichier binaire (nouvelle commande).
    #[command(
        about = "Chiffre un fichier binaire (utilise AES+RSA)",
        alias("encfile"),
        alias("efile"),
        alias("ef")
    )]
    EncryptFile {
        /// Chemin du fichier binaire à chiffrer
        #[arg(short = 'i', long)]
        input_file: String,

        /// Chemin du fichier de sortie (JSON chiffré)
        #[arg(short = 'o', long)]
        output_file: String,

        /// Chemin du répertoire des clés publiques
        #[arg(short = 'd', long, default_value = "keys")]
        public_key_directory: String,

        /// Version de la clé publique à utiliser
        #[arg(short = 'v', long)]
        key_version: String,

        /// Mot de passe "optionnel" (sinon laisser vide)
        #[arg(short = 'w', long, default_value = "")]
        password: String,
    },

    /// Déchiffre un fichier binaire (nouvelle commande).
    #[command(
        about = "Déchiffre un fichier binaire (retourne un .tar, .zip, etc.)",
        alias("decfile"),
        alias("dfile"),
        alias("df")
    )]
    DecryptFile {
        /// Chemin du fichier JSON chiffré
        #[arg(short = 'i', long)]
        input_file: String,

        /// Chemin du fichier binaire déchiffré
        #[arg(short = 'o', long)]
        output_file: String,

        /// Chemin du répertoire des clés privées
        #[arg(short = 'k', long, default_value = "keys")]
        private_key_directory: String,

        /// Version de la clé privée
        #[arg(short = 'v', long)]
        key_version: String,

        /// Mot de passe "optionnel"
        #[arg(short = 'w', long, default_value = "")]
        password: String,
    },

    /// Chiffre un répertoire entier.
    #[command(alias("encdir"))]
    EncryptDir {
        /// Chemin du répertoire à chiffrer.
        #[arg(short = 'i', long)]
        input_dir: String,

        /// Chemin du fichier de sortie chiffré.
        #[arg(short = 'o', long)]
        output_file: String,

        /// Chemin du répertoire des clés publiques.
        #[arg(short = 'd', long, default_value = "keys")]
        public_key_directory: String,

        /// Version de la clé publique à utiliser.
        #[arg(short = 'v', long)]
        key_version: String,

        /// Mot de passe "optionnel" (sinon laisser vide).
        #[arg(short = 'w', long, default_value = "")]
        password: String,
    },

    /// Déchiffre un répertoire entier.
    #[command(alias("decdir"))]
    DecryptDir {
        /// Chemin du fichier chiffré.
        #[arg(short = 'i', long)]
        input_file: String,

        /// Chemin du répertoire de sortie.
        #[arg(short = 'o', long)]
        output_dir: String,

        /// Chemin du répertoire des clés privées.
        #[arg(short = 'k', long, default_value = "keys")]
        private_key_directory: String,

        /// Version de la clé privée.
        #[arg(short = 'v', long)]
        key_version: String,

        /// Mot de passe "optionnel".
        #[arg(short = 'w', long, default_value = "")]
        password: String,
    },

    /// Fait pivoter une clé de chiffrement.
    #[command(alias("rk"))]
    RotateKey {
        /// L'ancienne version de la clé.
        #[arg(long)]
        old_version: String,

        /// La nouvelle version de la clé.
        #[arg(long)]
        new_version: String,

        /// Le répertoire des clés.
        #[arg(short='k', long, default_value = "keys")]
        key_directory: String,

        /// La taille de la nouvelle clé (optionnel, défaut: 2048).
        #[arg(short='s', long)]
        key_size: Option<u32>,

        /// Un fichier unique à rechiffrer.
        #[arg(short='f', long, conflicts_with="directory")]
        file: Option<String>,

        /// Un répertoire de fichiers à rechiffrer.
        #[arg(short='d', long, conflicts_with="file")]
        directory: Option<String>,
    }
}

fn main() {
    let args = Cli::parse();

    match args.command {
        // ---------------------------------------------------------------
        // 1) Génération d'une paire de clés RSA
        // ---------------------------------------------------------------
        Commands::Generate {
            version,
            directory,
            key_size,
        } => {
            if let Err(e) = std::fs::create_dir_all(&directory) {
                eprintln!("error: impossible de créer le répertoire des clés '{}': {}", directory, e);
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
            spinner.set_message("Génération des clés RSA...");
            spinner.enable_steady_tick(Duration::from_millis(100));

            let (private_key, public_key) = match generate_rsa_keys(key_size) {
                Ok((pk, pubk)) => (pk, pubk),
                Err(e) => {
                    spinner.finish_with_message("Erreur.");
                    eprintln!("error: impossible de générer la paire de clés RSA : {}", e);
                    process::exit(1);
                }
            };
            spinner.finish_with_message("Clés RSA générées.");

            match save_keys_to_files(&private_key, &public_key, &private_key_path, &public_key_path) {
                Ok(_) => {
                    println!("Clés RSA sauvegardées avec succès.");
                    println!("Clé privée : {private_key_path}");
                    println!("Clé publique : {public_key_path}");
                }
                Err(e) => {
                    eprintln!("error: impossible de sauvegarder les clés dans les fichiers : {}", e);
                    process::exit(1);
                }
            }
        }

        // ---------------------------------------------------------------
        // 2) Chiffrement d'un mot de passe
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
                    eprintln!("error: impossible d'initialiser le module de chiffrement : {}", e);
                    process::exit(1);
                }
            };
            match crypt.encrypt_password(&password) {
                Ok(encrypted_hash) => {
                    let file_path = "encrypted_data.json";
                    match File::create(file_path) {
                        Ok(mut file) => {
                            if let Err(e) = file.write_all(encrypted_hash.as_bytes()) {
                                eprintln!("error: impossible d'écrire les données chiffrées dans le fichier '{}': {}", file_path, e);
                                process::exit(1);
                            } else {
                                println!("Mot de passe chiffré dans '{file_path}'.");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: impossible de créer le fichier de sortie '{}': {}", file_path, e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: impossible de chiffrer le mot de passe : {}", e);
                    process::exit(1);
                }
            }
        }

        // ---------------------------------------------------------------
        // 3) Déchiffrement/vérification d'un mot de passe
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
                        eprintln!("error: impossible de lire le fichier '{}': {}", f, e);
                        process::exit(1);
                    }
                }
            } else {
                eprintln!("error: veuillez fournir les données chiffrées avec --data ou --file.");
                process::exit(1);
            };

            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&private_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: impossible d'initialiser le module de chiffrement : {}", e);
                    process::exit(1);
                }
            };

            match crypt.verify_password(&encrypted_data, &password) {
                Ok(ok) => {
                    if ok {
                        println!("Mot de passe correct.");
                    } else {
                        eprintln!("error: mot de passe incorrect ou hash non trouvé.");
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("error: impossible de vérifier le mot de passe : {}", e);
                    process::exit(1);
                }
            }
        }

        // ---------------------------------------------------------------
        // 4) Chiffrement d'un fichier binaire
        // ---------------------------------------------------------------
        Commands::EncryptFile {
            input_file,
            output_file,
            public_key_directory,
            key_version,
            password,
        } => {
            // Lire le fichier binaire
            let mut file_data = vec![];
            match File::open(&input_file) {
                Ok(mut f) => {
                    if let Err(e) = f.read_to_end(&mut file_data) {
                        eprintln!("error: impossible de lire le fichier d'entrée '{}': {}", input_file, e);
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("error: impossible d'ouvrir le fichier d'entrée '{}': {}", input_file, e);
                    process::exit(1);
                }
            }

            // Construire IronCrypt
            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&public_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: impossible d'initialiser le module de chiffrement : {}", e);
                    process::exit(1);
                }
            };

            // Chiffrer la data binaire
            match crypt.encrypt_binary_data(&file_data, &password) {
                Ok(encrypted_json) => {
                    // Écriture du JSON
                    match File::create(&output_file) {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(encrypted_json.as_bytes()) {
                                eprintln!("error: impossible d'écrire le fichier chiffré '{}': {}", output_file, e);
                                process::exit(1);
                            } else {
                                println!("Fichier binaire chiffré sauvegardé dans '{output_file}'.");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: impossible de créer le fichier de sortie '{}': {}", output_file, e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: impossible de chiffrer le fichier : {}", e);
                    process::exit(1);
                }
            }
        }

        // ---------------------------------------------------------------
        // 5) Déchiffrement d'un fichier binaire
        // ---------------------------------------------------------------
        Commands::EncryptDir {
            input_dir,
            output_file,
            public_key_directory,
            key_version,
            password,
        } => {
            // 1. Archiver et compresser le répertoire en mémoire
            let mut archive_data = Vec::new();
            {
                let encoder = GzEncoder::new(&mut archive_data, Compression::default());
                let mut builder = Builder::new(encoder);
                if let Err(e) = builder.append_dir_all(".", &input_dir) {
                    eprintln!("error: impossible d'archiver le répertoire '{}': {}", input_dir, e);
                    process::exit(1);
                }
                // Finaliser l'archive
                if let Err(e) = builder.into_inner() {
                     eprintln!("error: impossible de finaliser l'archive : {}", e);
                    process::exit(1);
                }
            }

            // 2. Chiffrer les données de l'archive
            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&public_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: impossible d'initialiser le module de chiffrement : {}", e);
                    process::exit(1);
                }
            };

            match crypt.encrypt_binary_data(&archive_data, &password) {
                Ok(encrypted_json) => {
                    if let Err(e) = std::fs::write(&output_file, encrypted_json) {
                         eprintln!("error: impossible d'écrire le fichier chiffré '{}': {}", output_file, e);
                        process::exit(1);
                    } else {
                        println!("Répertoire chiffré et sauvegardé dans '{}'.", output_file);
                    }
                }
                Err(e) => {
                    eprintln!("error: impossible de chiffrer l'archive du répertoire : {}", e);
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
            // 1. Lire et déchiffrer le fichier
            let encrypted_json = match std::fs::read_to_string(&input_file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: impossible de lire le fichier chiffré '{}': {}", input_file, e);
                    process::exit(1);
                }
            };

            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&private_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: impossible d'initialiser le module de chiffrement : {}", e);
                    process::exit(1);
                }
            };

            let decrypted_data = match crypt.decrypt_binary_data(&encrypted_json, &password) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: impossible de déchiffrer les données : {}", e);
                    process::exit(1);
                }
            };

            // 2. Décompresser et extraire l'archive
            let gz_decoder = GzDecoder::new(decrypted_data.as_slice());
            let mut archive = Archive::new(gz_decoder);
            if let Err(e) = archive.unpack(&output_dir) {
                eprintln!("error: impossible d'extraire l'archive dans '{}': {}", output_dir, e);
                process::exit(1);
            }

            println!("Répertoire déchiffré et extrait dans '{}'.", output_dir);
        }
        Commands::RotateKey {
            old_version,
            new_version,
            key_directory,
            key_size,
            file,
            directory,
        } => {
            // 1. Déterminer la taille de la nouvelle clé
            let new_key_size = key_size.unwrap_or(2048);

            // 2. Créer les instances d'IronCrypt pour l'ancienne et la nouvelle version
            let old_config = IronCryptConfig::default();
            let mut new_config = IronCryptConfig::default();
            new_config.rsa_key_size = new_key_size;

            let old_crypt = match IronCrypt::new(&key_directory, &old_version, old_config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: impossible de charger l'ancienne clé (version {}): {}", old_version, e);
                    process::exit(1);
                }
            };

            // La création de `new_crypt` va générer la nouvelle paire de clés si elle n'existe pas
            let _new_crypt = match IronCrypt::new(&key_directory, &new_version, new_config) {
                 Ok(c) => c,
                Err(e) => {
                    eprintln!("error: impossible de créer la nouvelle clé (version {}): {}", new_version, e);
                    process::exit(1);
                }
            };

            let new_public_key_path = format!("{}/public_key_{}.pem", key_directory, new_version);
            let new_public_key = match ironcrypt::load_public_key(&new_public_key_path) {
                 Ok(k) => k,
                Err(e) => {
                    eprintln!("error: impossible de charger la nouvelle clé publique '{}': {}", new_public_key_path, e);
                    process::exit(1);
                }
            };

            // 3. Déterminer la liste des fichiers à traiter
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
                        eprintln!("error: impossible de lire le répertoire '{}': {}", d, e);
                        process::exit(1);
                    }
                }
            } else {
                eprintln!("error: veuillez spécifier un fichier (--file) ou un répertoire (--directory).");
                process::exit(1);
            };

            // 4. Traiter chaque fichier
            for file_path in files_to_process {
                println!("Traitement du fichier : {}...", file_path);
                let encrypted_json = match std::fs::read_to_string(&file_path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("avertissement: impossible de lire le fichier '{}', ignoré. Raison: {}", file_path, e);
                        continue;
                    }
                };

                match old_crypt.re_encrypt_data(&encrypted_json, &new_public_key, &new_version) {
                    Ok(new_json) => {
                        if let Err(e) = std::fs::write(&file_path, new_json) {
                            eprintln!("avertissement: impossible de réécrire le fichier '{}', ignoré. Raison: {}", file_path, e);
                        }
                    }
                    Err(e) => {
                         eprintln!("avertissement: impossible de re-chiffrer le fichier '{}', ignoré. Raison: {}", file_path, e);
                    }
                }
            }

            println!("\nRotation des clés terminée avec succès.");
        }
        Commands::DecryptFile {
            input_file,
            output_file,
            private_key_directory,
            key_version,
            password,
        } => {
            // Lire le JSON chiffré
            let mut encrypted_json = String::new();
            match File::open(&input_file) {
                Ok(mut f) => {
                    if let Err(e) = f.read_to_string(&mut encrypted_json) {
                        eprintln!("error: impossible de lire le fichier d'entrée '{}': {}", input_file, e);
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("error: impossible d'ouvrir le fichier d'entrée '{}': {}", input_file, e);
                    process::exit(1);
                }
            }

            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&private_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: impossible d'initialiser le module de chiffrement : {}", e);
                    process::exit(1);
                }
            };

            // Déchiffrer
            match crypt.decrypt_binary_data(&encrypted_json, &password) {
                Ok(plaintext_bytes) => {
                    // Écriture du binaire déchiffré
                    match File::create(&output_file) {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(&plaintext_bytes) {
                                eprintln!("error: impossible d'écrire le fichier déchiffré '{}': {}", output_file, e);
                                process::exit(1);
                            } else {
                                println!("Fichier binaire déchiffré dans '{output_file}'.");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: impossible de créer le fichier de sortie '{}': {}", output_file, e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: impossible de déchiffrer le fichier : {}", e);
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

        // Construire IronCrypt
        // Ici on utilise "v1" dans le test, mais c'est juste un exemple d'usage
        let crypt = IronCrypt::new(key_directory, "v1", config).expect("Erreur IronCrypt::new");

        // Chiffrer le mot de passe
        let password = "Str0ngP@ssw0rd!";
        let encrypted = crypt
            .encrypt_password(password)
            .expect("Erreur encrypt_password");

        println!("Encrypted data JSON = {}", encrypted);

        // Vérifier
        let ok = crypt
            .verify_password(&encrypted, password)
            .expect("Erreur verify_password");
        assert!(ok, "Le mot de passe devrait être correct");

        // Vérifier un mauvais mot de passe
        let bad_ok = crypt.verify_password(&encrypted, "bad_password");
        assert!(
            bad_ok.is_err(),
            "Devrait échouer sur un mauvais mot de passe"
        );
    }
}
