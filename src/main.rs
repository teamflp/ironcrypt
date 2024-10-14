/*
use clap::{Parser, Subcommand};
use ironcrypt::{generate_rsa_keys, save_keys_to_files};

/// Command Line Interface (CLI) pour ironcrypt.
#[derive(Parser)]
#[command(name = "ironcrypt", about = "Génération et gestion des clés RSA pour IronCrypt.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Génère une paire de clés RSA.
    #[command(alias = "g")]
    Generate {
        /// Chemin de sauvegarde pour la clé privée.
        #[arg(short = 'p', long, default_value = "private_key.pem")]
        private_key_path: String,

        /// Chemin de sauvegarde pour la clé publique.
        #[arg(short = 'k', long, default_value = "public_key.pem")]
        public_key_path: String,
    },
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Some(Commands::Generate {
                 private_key_path,
                 public_key_path,
             }) => {
            // Génère les clés RSA.
            let (private_key, public_key) = generate_rsa_keys();

            // Sauvegarde les clés dans les fichiers spécifiés.
            match save_keys_to_files(&private_key, &public_key, &private_key_path, &public_key_path) {
                Ok(_) => {
                    println!("Les clés RSA ont été générées et sauvegardées avec succès.");
                    println!("Clé privée : {}", private_key_path);
                    println!("Clé publique : {}", public_key_path);
                }
                Err(e) => eprintln!("Erreur lors de la sauvegarde des clés : {}", e),
            }
        }
        None => {
            eprintln!("Aucune commande reconnue. Utilisez --help pour plus d'informations.");
        }
    }
}
*/

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use ironcrypt::{
    generate_rsa_keys, hash_and_encrypt_password_with_criteria, load_public_key,
    save_keys_to_files, PasswordCriteria,
};
use std::time::Duration; // <-- Importation de Duration

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
    // Vous pouvez ajouter d'autres sous-commandes comme `Decrypt`, etc.
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
            spinner.enable_steady_tick(Duration::from_millis(100)); // <-- Modification ici

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
        }, // Ajoutez d'autres sous-commandes ici si nécessaire.
    }
}
