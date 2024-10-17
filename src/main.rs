use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use ironcrypt::{
    decrypt_and_verify_password, generate_rsa_keys, hash_and_encrypt_password_with_criteria,
    load_public_key, save_keys_to_files, PasswordCriteria,
};
use std::time::Duration;
use std::fs::File;
use std::io::Write;

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
        /// Version de la clé.
        #[arg(short = 'v', long)]
        version: String,

        /// Chemin de sauvegarde pour les clés.
        #[arg(short = 'd', long, default_value = "keys")]
        directory: String,

        /// Taille de la clé (en bits).
        #[arg(short = 's', long, default_value_t = 2048)]
        key_size: u32,
    },
    /// Hache et chiffre un mot de passe.
    Encrypt {
        /// Le mot de passe à hacher et chiffrer.
        #[arg(short = 'w', long)]
        password: String,

        /// Chemin vers le répertoire des clés publiques.
        #[arg(short = 'd', long, default_value = "keys")]
        public_key_directory: String,

        /// Version de la clé publique à utiliser.
        #[arg(short = 'v', long)]
        key_version: String,
    },
    /// Déchiffre les données chiffrées et vérifie le mot de passe.
    Decrypt {
        /// Le mot de passe à vérifier.
        #[arg(short = 'w', long)]
        password: String,

        /// Chemin vers le répertoire des clés privées.
        #[arg(short = 'k', long, default_value = "keys")] // Changé de 'd' à 'k'
        private_key_directory: String,

        /// Données chiffrées à déchiffrer (sous forme de chaîne).
        #[arg(short = 'd', long, conflicts_with = "file")]
        data: Option<String>,

        /// Chemin vers le fichier contenant les données chiffrées.
        #[arg(short = 'f', long, conflicts_with = "data")]
        file: Option<String>,
    },
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Generate {
            version,
            directory,
            key_size,
        } => {
            // Créer le répertoire des clés s'il n'existe pas
            std::fs::create_dir_all(&directory)
                .expect("Erreur lors de la création du répertoire des clés");

            let private_key_path = format!("{}/private_key_{}.pem", directory, version);
            let public_key_path = format!("{}/public_key_{}.pem", directory, version);

            // Créer un spinner
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner} {msg}")
                    .expect("Erreur de configuration du style du spinner")
                    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
            );
            spinner.set_message("Génération des clés RSA en cours...");
            spinner.enable_steady_tick(Duration::from_millis(100));

            // Générer les clés RSA
            let (private_key, public_key) = match generate_rsa_keys(key_size) {
                Ok((priv_key, pub_key)) => (priv_key, pub_key),
                Err(e) => {
                    spinner.finish_with_message("Erreur lors de la génération des clés RSA.");
                    eprintln!("Erreur : {}", e);
                    return;
                }
            };

            // Arrêter le spinner
            spinner.finish_with_message("Génération des clés RSA terminée.");

            // Sauvegarder les clés
            match save_keys_to_files(
                &private_key,
                &public_key,
                &private_key_path,
                &public_key_path,
            ) {
                Ok(_) => {
                    println!("Les clés RSA ont été générées et sauvegardées avec succès.");
                    println!("Clé privée : {}", private_key_path);
                    println!("Clé publique : {}", public_key_path);
                }
                Err(e) => eprintln!("Erreur lors de la sauvegarde des clés : {}", e),
            }
        }
        Commands::Encrypt {
            password,
            public_key_directory,
            key_version,
        } => {
            let public_key_path = format!("{}/public_key_{}.pem", public_key_directory, key_version);
            match load_public_key(&public_key_path) {
                Ok(public_key) => {
                    let criteria = PasswordCriteria::default();
                    match hash_and_encrypt_password_with_criteria(
                        &password,
                        &public_key,
                        &criteria,
                        &key_version,
                    ) {
                        Ok(encrypted_hash) => {
                            // Créer le fichier encrypted_data.json et y écrire les données chiffrées
                            let file_path = "encrypted_data.json";
                            match File::create(file_path) {
                                Ok(mut file) => {
                                    if let Err(e) = file.write_all(encrypted_hash.as_bytes()) {
                                        eprintln!("Erreur lors de l'écriture dans le fichier : {}", e);
                                    } else {
                                        println!("Données chiffrées sauvegardées dans '{}'.", file_path);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Erreur lors de la création du fichier : {}", e);
                                }
                            }
                        }
                        Err(e) => eprintln!("Erreur lors du hachage et du chiffrement : {}", e),
                    }
                }
                Err(e) => eprintln!("Erreur lors du chargement de la clé publique : {}", e),
            }
        }
        Commands::Decrypt {
            password,
            private_key_directory,
            data,
            file,
        } => {
            // Lire les données chiffrées
            let encrypted_data = if let Some(data_str) = data {
                data_str
            } else if let Some(file_path) = file {
                // Lire les données depuis le fichier
                match std::fs::read_to_string(&file_path) {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!(
                            "Erreur lors de la lecture du fichier de données chiffrées : {}",
                            e
                        );
                        return;
                    }
                }
            } else {
                eprintln!("Veuillez fournir les données chiffrées avec --data ou --file.");
                return;
            };

            // Déchiffrer et vérifier le mot de passe
            match decrypt_and_verify_password(&encrypted_data, &password, &private_key_directory) {
                Ok(_) => println!("Le mot de passe est correct."),
                Err(e) => eprintln!(
                    "Le mot de passe est incorrect ou une erreur s'est produite : {}",
                    e
                ),
            }
        }
    }
}
