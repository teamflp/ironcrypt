use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use ironcrypt::{
    generate_rsa_keys,
    save_keys_to_files,
    IronCrypt,
    IronCryptConfig,
};
use std::fs::File;
use std::io::{Read, Write};
use std::time::Duration;

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
                eprintln!("Erreur lors de la création du répertoire : {e}");
                return;
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
                    spinner.finish_with_message("Erreur génération clés RSA.");
                    eprintln!("Erreur : {e}");
                    return;
                }
            };
            spinner.finish_with_message("Clés RSA générées.");

            match save_keys_to_files(&private_key, &public_key, &private_key_path, &public_key_path) {
                Ok(_) => {
                    println!("Clés RSA sauvegardées avec succès.");
                    println!("Clé privée : {private_key_path}");
                    println!("Clé publique : {public_key_path}");
                }
                Err(e) => eprintln!("Erreur sauvegarde des clés : {e}"),
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
                    eprintln!("Erreur IronCrypt::new : {e}");
                    return;
                }
            };
            match crypt.encrypt_password(&password) {
                Ok(encrypted_hash) => {
                    let file_path = "encrypted_data.json";
                    match File::create(file_path) {
                        Ok(mut file) => {
                            if let Err(e) = file.write_all(encrypted_hash.as_bytes()) {
                                eprintln!("Erreur écriture : {e}");
                            } else {
                                println!("Mot de passe chiffré dans '{file_path}'.");
                            }
                        }
                        Err(e) => eprintln!("Erreur création fichier : {e}"),
                    }
                }
                Err(e) => eprintln!("Erreur chiffrement mot de passe : {e}"),
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
                        eprintln!("Erreur lecture fichier : {e}");
                        return;
                    }
                }
            } else {
                eprintln!("Fournir --data ou --file.");
                return;
            };

            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&private_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Erreur IronCrypt::new : {e}");
                    return;
                }
            };

            match crypt.verify_password(&encrypted_data, &password) {
                Ok(ok) => {
                    if ok {
                        println!("Mot de passe correct.");
                    } else {
                        println!("Mot de passe incorrect ou pas de hash.");
                    }
                }
                Err(e) => eprintln!("Erreur déchiffrement/vérification : {e}"),
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
                        eprintln!("Erreur lecture '{input_file}': {e}");
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("Erreur ouverture '{input_file}': {e}");
                    return;
                }
            }

            // Construire IronCrypt
            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&public_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Erreur IronCrypt::new : {e}");
                    return;
                }
            };

            // Chiffrer la data binaire
            match crypt.encrypt_binary_data(&file_data, &password) {
                Ok(encrypted_json) => {
                    // Écriture du JSON
                    match File::create(&output_file) {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(encrypted_json.as_bytes()) {
                                eprintln!("Erreur écriture '{output_file}': {e}");
                            } else {
                                println!("Fichier binaire chiffré sauvegardé dans '{output_file}'.");
                            }
                        }
                        Err(e) => eprintln!("Erreur création '{output_file}': {e}"),
                    }
                }
                Err(e) => eprintln!("Erreur chiffrement binaire : {e}"),
            }
        }

        // ---------------------------------------------------------------
        // 5) Déchiffrement d'un fichier binaire
        // ---------------------------------------------------------------
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
                        eprintln!("Erreur lecture '{input_file}': {e}");
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("Erreur ouverture '{input_file}': {e}");
                    return;
                }
            }

            let config = IronCryptConfig::default();
            let crypt = match IronCrypt::new(&private_key_directory, &key_version, config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Erreur IronCrypt::new : {e}");
                    return;
                }
            };

            // Déchiffrer
            match crypt.decrypt_binary_data(&encrypted_json, &password) {
                Ok(plaintext_bytes) => {
                    // Écriture du binaire déchiffré
                    match File::create(&output_file) {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(&plaintext_bytes) {
                                eprintln!("Erreur écriture '{output_file}': {e}");
                            } else {
                                println!("Fichier binaire déchiffré dans '{output_file}'.");
                            }
                        }
                        Err(e) => eprintln!("Erreur création '{output_file}': {e}"),
                    }
                }
                Err(e) => eprintln!("Erreur déchiffrement binaire : {e}"),
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
