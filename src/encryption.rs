use crate::criteria::{is_password_strong, PasswordCriteria};
use argon2::password_hash::SaltString;
use argon2::{self, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;


/// Hache un mot de passe et le chiffre après vérification des critères de robustesse.
///
/// Cette fonction prend un mot de passe, vérifie qu'il respecte les critères de robustesse spécifiés,
/// le hache en utilisant l'algorithme Argon2, puis chiffre le hash avec une clé publique RSA
/// en utilisant le schéma de remplissage OAEP avec SHA-256. Le résultat est ensuite encodé en base64
/// pour un stockage sécurisé.
///
/// # Arguments
///
/// * `password` - Une référence à une chaîne de caractères représentant le mot de passe à hacher et chiffrer.
/// * `public_key` - Une référence à la clé publique RSA (`RsaPublicKey`) utilisée pour chiffrer le hash.
/// * `criteria` - Une référence à `PasswordCriteria` spécifiant les exigences de robustesse que le mot de passe doit respecter.
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok(String)` : Le hash chiffré encodé en base64 si l'opération réussit.
/// - `Err(argon2::password_hash::Error)` : Une erreur détaillant la raison de l'échec, par exemple, si le mot de passe
///   ne respecte pas les critères ou si le hachage/chiffrement échoue.
///
/// # Exemple
///
/// ```rust
/// use ironcrypt::{hash_and_encrypt_password_with_criteria, generate_rsa_keys, PasswordCriteria};
///
/// let password = "StrongP@ssw0rd";
/// let criteria = PasswordCriteria::default();
/// let (_, public_key) = generate_rsa_keys();
///
/// match hash_and_encrypt_password_with_criteria(password, &public_key, &criteria) {
///     Ok(encrypted_hash) => println!("Mot de passe haché et chiffré : {}", encrypted_hash),
///     Err(e) => println!("Erreur lors du hachage et du chiffrement : {:?}", e),
/// }
/// ```
///
/// Dans cet exemple, le mot de passe "StrongP@ssw0rd" est haché et chiffré avec une clé publique
/// après avoir vérifié qu'il respecte les critères de robustesse. Le résultat encodé en base64 est prêt
/// à être stocké en toute sécurité.
///
/// # Remarques
///
/// - Le sel est généré automatiquement à l'aide de `SaltString::generate` pour garantir que le même mot de passe
///   ne produira jamais le même hash, améliorant ainsi la sécurité contre les attaques par table de hachage.
/// - La clé publique est utilisée pour chiffrer le hash afin de garantir que seule la clé privée correspondante
///   pourra le déchiffrer.
/// - Le résultat est encodé en base64 pour faciliter le stockage dans des bases de données ou le transfert sécurisé.
///
/// # Erreurs
///
/// La fonction peut renvoyer une `Err` si :
/// - Le mot de passe ne respecte pas les critères de robustesse spécifiés.
/// - Une erreur survient lors de la génération du sel ou du hachage avec Argon2.
/// - Une erreur survient lors du chiffrement du hash avec la clé publique.
pub fn hash_and_encrypt_password_with_criteria(password: &str, public_key: &RsaPublicKey, criteria: &PasswordCriteria,) -> Result<String, argon2::password_hash::Error> {
    // Vérification de la robustesse du mot de passe
    is_password_strong(password, criteria).map_err(|_| argon2::password_hash::Error::Password)?;

    // Utilisation de OsRng pour générer un SaltString
    let mut rng = OsRng; // Remplacez thread_rng par OsRng
    let salt = SaltString::generate(&mut rng);

    // Configure Argon2 pour un hachage sécurisé
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;

    // Chiffrement du hash avec la clé publique en utilisant OAEP avec SHA-256
    let padding = Oaep::new::<Sha256>(); // Utilisez sha2::Sha256 directement
    let encrypted_hash: Vec<u8> = public_key
        .encrypt(&mut OsRng, padding, hash.to_string().as_bytes())
        .map_err(|_| argon2::password_hash::Error::Password)?;

    Ok(base64_standard.encode(&encrypted_hash))
}


/// Déchiffre un hash chiffré et vérifie si un mot de passe correspond au hash déchiffré.
///
/// Cette fonction prend un hash chiffré, le déchiffre à l'aide d'une clé privée RSA,
/// puis vérifie si le mot de passe fourni correspond au hash déchiffré en utilisant
/// l'algorithme de vérification d'Argon2. Le hash déchiffré est d'abord décodé à partir
/// de la chaîne base64 avant d'être analysé et vérifié.
///
/// # Arguments
///
/// * `encrypted_hash` - Une référence à une chaîne de caractères encodée en base64 représentant
///   le hash chiffré à déchiffrer.
/// * `password` - Une référence à une chaîne de caractères représentant le mot de passe à vérifier.
/// * `private_key` - Une référence à la clé privée RSA (`RsaPrivateKey`) utilisée pour déchiffrer le hash.
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok(())` : Si le mot de passe correspond au hash déchiffré.
/// - `Err(argon2::password_hash::Error)` : Une erreur détaillant la raison de l'échec,
///   par exemple, si le déchiffrement échoue ou si le mot de passe ne correspond pas.
///
/// # Exemple
///
/// ```rust
/// use ironcrypt::{decrypt_and_verify_password, generate_rsa_keys, hash_and_encrypt_password_with_criteria, PasswordCriteria};
///
/// let (private_key, public_key) = generate_rsa_keys();
/// let password = "StrongP@ssw0rd";
/// let criteria = PasswordCriteria::default();
///
/// // Hachage et chiffrement du mot de passe
/// let encrypted_hash = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria)
///     .expect("Erreur lors du hachage et du chiffrement");
///
/// // Déchiffrement et vérification du mot de passe
/// match decrypt_and_verify_password(&encrypted_hash, password, &private_key) {
///     Ok(_) => println!("Le mot de passe est valide."),
///     Err(e) => println!("Erreur lors de la vérification du mot de passe : {:?}", e),
/// }
/// ```
///
/// Dans cet exemple, le mot de passe "StrongP@ssw0rd" est d'abord haché et chiffré, puis vérifié
/// après déchiffrement pour s'assurer qu'il correspond au hash d'origine.
///
/// # Remarques
///
/// - Cette fonction repose sur l'utilisation d'Argon2 pour vérifier le mot de passe, ce qui garantit
///   une vérification sécurisée et résistante aux attaques.
/// - La clé privée doit être gardée en sécurité, car elle est nécessaire pour déchiffrer les hashes chiffrés.
///
/// # Erreurs
///
/// La fonction peut renvoyer une `Err` si :
/// - La chaîne encodée en base64 ne peut pas être décodée.
/// - Le déchiffrement du hash avec la clé privée échoue.
/// - La conversion du hash déchiffré en chaîne de caractères échoue.
/// - Le hash déchiffré ne peut pas être analysé en tant que `PasswordHash`.
/// - Le mot de passe ne correspond pas au hash déchiffré.
pub fn decrypt_and_verify_password(
    encrypted_hash: &str,
    password: &str,
    private_key: &RsaPrivateKey,
) -> Result<(), argon2::password_hash::Error> {
    // Décode la chaîne base64 en octets
    let encrypted_hash = base64_standard.decode(encrypted_hash)
        .map_err(|_| argon2::password_hash::Error::Password)?;

    // Déchiffrement du hash
    let decrypted_hash = private_key
        .decrypt(Oaep::new::<Sha256>(), &encrypted_hash)
        .map_err(|_| argon2::password_hash::Error::Password)?;

    // Conversion du hash déchiffré en chaîne de caractères
    let decrypted_hash_str = String::from_utf8(decrypted_hash)
        .map_err(|_| argon2::password_hash::Error::Password)?;

    // Analyse du hash déchiffré
    let parsed_hash = PasswordHash::new(&decrypted_hash_str)
        .map_err(|_| argon2::password_hash::Error::Password)?;

    // Vérification du mot de passe avec Argon2
    let argon2 = Argon2::default();
    argon2.verify_password(password.as_bytes(), &parsed_hash)
}


// tests unitaires
#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rand::rngs::OsRng;
    use crate::criteria::PasswordCriteria;

    #[test]
    fn test_hash_and_encrypt_password_with_criteria_success() {
        // Génération de clés RSA pour le test
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Erreur de génération de la clé privée");
        let public_key = RsaPublicKey::from(&private_key);

        // Définition des critères de mot de passe (exemple : au moins 8 caractères)
        let criteria = PasswordCriteria {
            min_length: 8,
            require_uppercase: false,
            require_numbers: false,
            require_special_chars: false,
            max_length: None,
            uppercase: 1,
            lowercase: 1,
            digits: 1,
            special_chars: 1,
            disallowed_patterns: vec![],
        };

        // Mot de passe qui respecte les critères
        let password = "StrongP@ssw0rd";

        // Appel de la fonction de hachage et chiffrement
        let result = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria);

        // Vérification que le résultat est Ok et non une erreur
        assert!(result.is_ok(), "Le hachage et le chiffrement du mot de passe ont échoué");

        // Vérification que la chaîne encodée en base64 n'est pas vide
        let encrypted_hash = result.unwrap();
        assert!(!encrypted_hash.is_empty(), "Le hash chiffré ne doit pas être vide");
    }

    #[test]
    fn test_decrypt_and_verify_password_success() {
        // Génération de clés RSA pour le test
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Erreur de génération de la clé privée");
        let public_key = RsaPublicKey::from(&private_key);

        // Définition des critères de mot de passe (exemple : au moins 8 caractères)
        let criteria = PasswordCriteria {
            min_length: 8,
            require_uppercase: false,
            require_numbers: false,
            require_special_chars: false,
            max_length: None,
            uppercase: 1,
            lowercase: 1,
            digits: 1,
            special_chars: 1,
            disallowed_patterns: vec![],
        };

        // Mot de passe qui respecte les critères
        let password = "StrongP@ssw0rd";

        // Appel de la fonction de hachage et chiffrement
        let encrypted_hash = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria)
            .expect("Le hachage et le chiffrement du mot de passe ont échoué");

        // Appel de la fonction de déchiffrement et vérification
        let result = decrypt_and_verify_password(&encrypted_hash, password, &private_key);

        // Vérification que le résultat est Ok et non une erreur
        assert!(result.is_ok(), "La vérification du mot de passe a échoué");
    }

    #[test]
    fn test_hash_and_encrypt_password_with_criteria_failure() {
        // Génération de clés RSA pour le test
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Erreur de génération de la clé privée");
        let public_key = RsaPublicKey::from(&private_key);

        // Définition des critères de mot de passe (exemple : au moins 8 caractères)
        let criteria = PasswordCriteria {
            min_length: 8,
            require_uppercase: false,
            require_numbers: false,
            require_special_chars: false,
            max_length: None,
            uppercase: 1,
            lowercase: 1,
            digits: 1,
            special_chars: 1,
            disallowed_patterns: vec![],
        };

        // Mot de passe qui ne respecte pas les critères (pas de caractère spécial)
        let password = "weakpassword";

        // Appel de la fonction de hachage et chiffrement
        let result = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria);

        // Vérification que le résultat est une erreur
        assert!(result.is_err(), "Le mot de passe ne respectant pas les critères aurait dû échouer");
    }

    #[test]
    fn test_decrypt_and_verify_password_failure() {
        // Génération de clés RSA pour le test
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Erreur de génération de la clé privée");
        let public_key = RsaPublicKey::from(&private_key);

        // Définition des critères de mot de passe (exemple : au moins 8 caractères)
        let criteria = PasswordCriteria {
            min_length: 8,
            require_uppercase: false,
            require_numbers: false,
            require_special_chars: false,
            max_length: None,
            uppercase: 1,
            lowercase: 1,
            digits: 1,
            special_chars: 1,
            disallowed_patterns: vec![],
        };

        // Mot de passe qui respecte les critères
        let password = "StrongP@ssw0rd";

        // Appel de la fonction de hachage et chiffrement
        let encrypted_hash = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria)
            .expect("Le hachage et le chiffrement du mot de passe ont échoué");

        // Appel de la fonction de déchiffrement et vérification avec un mauvais mot de passe
        let wrong_password = "WrongPassword123";
        let result = decrypt_and_verify_password(&encrypted_hash, wrong_password, &private_key);

        // Vérification que le résultat est une erreur
        assert!(result.is_err(), "La vérification aurait dû échouer pour un mot de passe incorrect");
    }
}
