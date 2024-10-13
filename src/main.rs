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
