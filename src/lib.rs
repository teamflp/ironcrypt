mod criteria;
mod encryption;
mod hashing;
mod rsa_utils;
mod handle_error;

// Expose les fonctions et structures de la bibliothèque pour les utiliser dans le binaire.
//
// Les `pub use` suivants permettent d'exposer certaines fonctions et structures de modules internes
// afin qu'elles soient accessibles directement aux utilisateurs de la bibliothèque. Cela simplifie
// l'accès aux principales fonctionnalités de la bibliothèque depuis le module racine.
//
// # Fonctions et Structures Exposées
//
// - `is_password_strong` : Vérifie si un mot de passe respecte les critères de robustesse spécifiés.
// - `PasswordCriteria` : Structure qui définit les exigences minimales pour un mot de passe sécurisé.
// - `decrypt_and_verify_password` : Déchiffre un hash chiffré et vérifie si un mot de passe correspond au hash déchiffré.
// - `hash_and_encrypt_password_with_criteria` : Hache un mot de passe, vérifie sa robustesse et le chiffre avec une clé publique RSA.
// - `hash_password` : Hache un mot de passe en utilisant l'algorithme Argon2 pour le stockage sécurisé.
// - `generate_rsa_keys` : Génère une paire de clés RSA (privée et publique).
// - `load_rsa_keys` : Charge les clés RSA à partir de fichiers PEM pour les réutiliser.
// - `save_keys_to_files` : Sauvegarde les clés RSA dans des fichiers PEM pour une persistance sécurisée.
//
// # Exemple
//
/// ```rust
/// // use my_crate::{
//     is_password_strong, PasswordCriteria, decrypt_and_verify_password,
//     hash_and_encrypt_password_with_criteria, hash_password, generate_rsa_keys,
//     load_rsa_keys, save_keys_to_files,
//   // };
//
// fn main() {
//     // Crée un critère de mot de passe personnalisé.
//     let criteria = PasswordCriteria::default();
//
//     // Génère des clés RSA et les sauvegarde dans des fichiers.
//     let (private_key, public_key) = generate_rsa_keys();
//     save_keys_to_files(&private_key, &public_key, "private_key.pem", "public_key.pem").unwrap();
//
//     // Vérifie si un mot de passe est robuste.
//     let password = "MySecureP@ssw0rd";
//     is_password_strong(password, &criteria).unwrap();
//
//     // Hache et chiffre le mot de passe.
//     let encrypted_hash = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria).unwrap();
//
//     // Déchiffre et vérifie le mot de passe.
//     decrypt_and_verify_password(&encrypted_hash, password, &private_key).unwrap();
// }
// ```
//
// Dans cet exemple, toutes les fonctions et structures exposées sont utilisées pour générer et sauvegarder
// des clés RSA, vérifier la robustesse d'un mot de passe, le hacher et le chiffrer, puis le déchiffrer
// et le vérifier après déchiffrement.
//
// # Remarques
//
// - En exposant ces fonctions via `pub use`, les utilisateurs de la bibliothèque n'ont pas besoin
//   de connaître la structure interne des modules, ce qui simplifie l'intégration de la bibliothèque
//   dans leurs projets.
// - Les fonctions exposées couvrent les principales fonctionnalités de la bibliothèque, facilitant
//   la gestion des mots de passe et des clés RSA.
pub use criteria::{is_password_strong, PasswordCriteria};
pub use encryption::{decrypt_and_verify_password, hash_and_encrypt_password_with_criteria};
pub use hashing::hash_password;
pub use rsa_utils::{generate_rsa_keys, load_rsa_keys, save_keys_to_files};
pub use handle_error::IronCryptError;
