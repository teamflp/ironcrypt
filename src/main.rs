use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use ironcrypt::{
    generate_rsa_keys,
    hash_and_encrypt_password_with_criteria,
    decrypt_and_verify_password,      // <-- Importation de la fonction decrypt
    load_public_key,
    load_private_key,                 // <-- Importation de la fonction load_private_key
    save_keys_to_files,
    PasswordCriteria,
};
use std::time::Duration;

/// Command Line Interface (CLI) pour IronCrypt.
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
        /// Chemin de sauvegarde pour la clé privée.
        #[arg(short = 'p', long, default_value = "private_key.pem")]
        private_key_path: String,

        /// Chemin de sauvegarde pour la clé publique.
        #[arg(short = 'k', long, default_value = "public_key.pem")]
        public_key_path: String,

        /// Taille de la clé (en bits).
        #[arg(short = 's', long, default_value_t = 2048)]
        key_size: u32,
    },
    /// Hache et chiffre un mot de passe.
    Encrypt {
        /// Le mot de passe à hacher et chiffrer.
        #[arg(short = 'w', long)]
        password: String,

        /// Chemin vers la clé publique pour le chiffrement.
        #[arg(short = 'k', long, default_value = "public_key.pem")]
        public_key_path: String,
    },
    /// Déchiffre les données chiffrées et vérifie le mot de passe.
    Decrypt {
        /// Le mot de passe à vérifier.
        #[arg(short = 'w', long)]
        password: String,

        /// Chemin vers la clé privée pour le déchiffrement.
        #[arg(short = 'k', long, default_value = "private_key.pem")]
        private_key_path: String,

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
            private_key_path,
            public_key_path,
            key_size,
        } => {
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
            public_key_path,
        } => match load_public_key(&public_key_path) {
            Ok(public_key) => {
                let criteria = PasswordCriteria::default();
                match hash_and_encrypt_password_with_criteria(&password, &public_key, &criteria) {
                    Ok(encrypted_hash) => {
                        println!("Mot de passe haché et chiffré : {}", encrypted_hash);
                    }
                    Err(e) => eprintln!("Erreur lors du hachage et du chiffrement : {}", e),
                }
            }
            Err(e) => eprintln!("Erreur lors du chargement de la clé publique : {}", e),
        },
        Commands::Decrypt {
            password,
            private_key_path,
            data,
            file,
        } => {
            // Charger la clé privée
            match load_private_key(&private_key_path) {
                Ok(private_key) => {
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
                    match decrypt_and_verify_password(&encrypted_data, &password, &private_key) {
                        Ok(_) => println!("Le mot de passe est correct."),
                        Err(e) => eprintln!(
                            "Le mot de passe est incorrect ou une erreur s'est produite : {}",
                            e
                        ),
                    }
                }
                Err(e) => eprintln!("Erreur lors du chargement de la clé privée : {}", e),
            }
        } // Ajoutez d'autres sous-commandes ici si nécessaire.
    }
}
