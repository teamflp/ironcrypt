use ironcrypt::{generate_rsa_keys, save_keys_to_files};

/// Fonction principale qui génère des clés RSA et les sauvegarde dans des fichiers PEM.
///
/// Cette fonction génère une paire de clés RSA (privée et publique) à l'aide de la fonction
/// `generate_rsa_keys`, puis les sauvegarde dans des fichiers PEM spécifiés à l'aide de
/// `save_keys_to_files`.
///
/// # Chemins des fichiers de clés
///
/// - `private_key_path` : Le chemin où la clé privée sera sauvegardée (exemple : "private_key.pem").
/// - `public_key_path` : Le chemin où la clé publique sera sauvegardée (exemple : "public_key.pem").
///
/// # Comportement
///
/// - En cas de succès, les fichiers de clés sont créés et un message de confirmation est affiché.
/// - En cas d'erreur, un message d'erreur est affiché indiquant la raison de l'échec.
///
/// # Exemple
///
/// ```rust
/// fn main() {
///     let (private_key, public_key) = generate_rsa_keys();
///     let private_key_path = "private_key.pem";
///     let public_key_path = "public_key.pem";
///
///     match save_keys_to_files(&private_key, &public_key, private_key_path, public_key_path) {
///         Ok(_) => {
///             println!("Les clés RSA ont été générées et sauvegardées avec succès.");
///             println!("Clé privée : {}", private_key_path);
///             println!("Clé publique : {}", public_key_path);
///         }
///         Err(e) => println!("Erreur : {}", e),
///     }
/// }
/// ```
///
/// Dans cet exemple, la fonction génère une clé privée et une clé publique, puis les sauvegarde
/// dans les fichiers "private_key.pem" et "public_key.pem".
///
/// # Remarques
///
/// - Assurez-vous que les chemins des fichiers sont accessibles en écriture pour que les clés
///   puissent être sauvegardées correctement.
/// - Cette fonction est souvent utilisée lors de la configuration initiale d'un système nécessitant
///   une cryptographie RSA pour le chiffrement ou la signature numérique.
fn main() {
    let (private_key, public_key) = generate_rsa_keys();
    let private_key_path = "private_key.pem";
    let public_key_path = "public_key.pem";

    match save_keys_to_files(&private_key, &public_key, private_key_path, public_key_path) {
        Ok(_) => {
            println!("Les clés RSA ont été générées et sauvegardées avec succès.");
            println!("Clé privée : {}", private_key_path);
            println!("Clé publique : {}", public_key_path);
        }
        Err(e) => println!("Erreur : {}", e),
    }
}
