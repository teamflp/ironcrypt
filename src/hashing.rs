use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{self, Argon2, PasswordHasher};

/// Hache un mot de passe avec Argon2id.
/// Hache un mot de passe en utilisant l'algorithme Argon2.
///
/// Cette fonction prend un mot de passe sous forme de chaîne de caractères et le hache
/// en utilisant l'algorithme Argon2, considéré comme l'un des plus sûrs pour le stockage de mots de passe.
/// Un sel aléatoire est généré à chaque hachage pour renforcer la sécurité et garantir
/// que même deux mots de passe identiques auront des hachages différents.
///
/// # Arguments
///
/// * `password` - Une référence à une chaîne de caractères représentant le mot de passe à hacher.
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok(String)` : Le mot de passe haché encodé sous forme de chaîne de caractères en cas de succès.
/// - `Err(String)` : Un message d'erreur détaillant la raison de l'échec si le hachage échoue.
///
/// # Exemple
///
/// ```rust
/// use ironcrypt::hash_password;
///
/// let password = "MySecureP@ssw0rd";
/// match hash_password(password) {
///     Ok(hashed) => println!("Mot de passe haché : {}", hashed),
///     Err(e) => println!("Erreur : {}", e),
/// }
/// ```
///
/// Dans cet exemple, le mot de passe "MySecureP@ssw0rd" est haché, et le résultat est affiché
/// si l'opération est réussie. En cas d'échec, un message d'erreur est affiché.
///
/// # Remarques
///
/// - Le sel est généré automatiquement à l'aide de `SaltString::generate` et est incorporé
///   dans le hachage final, ce qui le rend prêt pour une vérification future.
/// - Utilisez cette fonction pour stocker les mots de passe de manière sécurisée dans votre base de données
///   en utilisant le hachage résultant au lieu du mot de passe en clair.
///
/// # Erreurs
///
/// La fonction peut renvoyer une `Err` si :
/// - La génération du sel ou le processus de hachage échoue.
/// - Une erreur interne survient lors de l'appel à `hash_password` de la bibliothèque Argon2.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Erreur lors du hachage du mot de passe: {e:?}"))
}
