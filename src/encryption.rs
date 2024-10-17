use crate::criteria::PasswordCriteria;
use crate::handle_error::IronCryptError;
use crate::load_private_key;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::AeadCore;
use aes_gcm::{Aes256Gcm, Nonce};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Algorithm;
use argon2::Argon2;
use argon2::Params;
use argon2::Version;

use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;

use rand::rngs::OsRng;
use rand::RngCore;

use rsa::{Oaep, RsaPublicKey};

use sha2::Sha256;

use serde_json;


pub fn hash_and_encrypt_password_with_criteria(
    password: &str,
    public_key: &RsaPublicKey,
    criteria: &PasswordCriteria,
    key_version: &str,
) -> Result<String, IronCryptError> {
    // Vérifier les critères du mot de passe
    criteria.validate(password)?;

    // Configurer Argon2 avec les paramètres désirés
    let memory_cost = 65536; // 64 MiB
    let time_cost = 3;
    let parallelism = 1;

    let params = Params::new(memory_cost, time_cost, parallelism, None).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Générer un sel aléatoire
    let salt = SaltString::generate(&mut OsRng);

    // Hacher le mot de passe
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    // Générer une clé symétrique aléatoire (256 bits pour AES-256)
    let mut symmetric_key = [0u8; 32];
    OsRng.fill_bytes(&mut symmetric_key);

    // Chiffrer le hash avec AES-GCM
    let cipher = Aes256Gcm::new_from_slice(&symmetric_key).map_err(|e| {
        IronCryptError::EncryptionError(format!(
            "Erreur lors de l'initialisation du cipher : {}",
            e
        ))
    })?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96 bits; unique par message
    let ciphertext = cipher
        .encrypt(&nonce, password_hash.as_bytes())
        .map_err(|e| {
            IronCryptError::EncryptionError(format!("Erreur lors du chiffrement du hash : {}", e))
        })?;

    // Chiffrer la clé symétrique avec RSA
    let padding = Oaep::new::<Sha256>();
    let encrypted_symmetric_key = public_key
        .encrypt(&mut OsRng, padding, &symmetric_key)
        .map_err(|e| {
            IronCryptError::EncryptionError(format!(
                "Erreur lors du chiffrement de la clé symétrique : {}",
                e
            ))
        })?;

    // Sérialiser le tout en JSON avec la version de la clé
    let data = serde_json::json!({
        "key_version": key_version,
        "encrypted_symmetric_key": base64_standard.encode(&encrypted_symmetric_key),
        "nonce": base64_standard.encode(&nonce),
        "ciphertext": base64_standard.encode(&ciphertext),
    });

    Ok(data.to_string())
}

/// Déchiffre des données chiffrées et vérifie si un mot de passe correspond au hash déchiffré.
///
/// Cette fonction utilise le processus inverse de la fonction `hash_and_encrypt_password_with_criteria` :
/// - **Désérialisation** : Les données chiffrées encodées en base64 sont décodées et désérialisées depuis le format JSON.
/// - **Déchiffrement de la clé symétrique** : La clé symétrique est déchiffrée avec la clé privée RSA en utilisant OAEP avec SHA-256.
/// - **Déchiffrement symétrique** : Le hash du mot de passe est déchiffré avec AES-256-GCM en utilisant la clé symétrique déchiffrée.
/// - **Vérification du mot de passe** : Le mot de passe fourni est vérifié par rapport au hash déchiffré en utilisant Argon2.
///
/// # Arguments
///
/// * `encrypted_data` - Une référence à une chaîne de caractères encodée en base64 représentant
///   les données chiffrées (clé symétrique chiffrée, nonce, ciphertext).
/// * `password` - Une référence à une chaîne de caractères représentant le mot de passe à vérifier.
/// * `private_key` - Une référence à la clé privée RSA (`RsaPrivateKey`) utilisée pour déchiffrer la clé symétrique.
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok(())` : Si le mot de passe correspond au hash déchiffré.
/// - `Err(IronCryptError)` : Une erreur détaillant la raison de l'échec, par exemple, si le déchiffrement
///   échoue ou si le mot de passe ne correspond pas.
///
/// # Exemple
///
/// ```rust
/// use ironcrypt::{
///     decrypt_and_verify_password, generate_rsa_keys, hash_and_encrypt_password_with_criteria,
///     PasswordCriteria,
/// };
///
/// let (private_key, public_key) = generate_rsa_keys(2048).expect("Erreur lors de la génération des clés RSA");
/// let password = "StrongP@ssw0rd";
/// let criteria = PasswordCriteria::default();
/// let key_version = "v1";
///
/// // Hachage et chiffrement du mot de passe
/// let encrypted_data = hash_and_encrypt_password_with_criteria(password, &public_key, &criteria, &key_version)
///     .expect("Erreur lors du hachage et du chiffrement");
///
/// // Déchiffrement et vérification du mot de passe
/// match decrypt_and_verify_password(&encrypted_data, password, &key_version) {
///     Ok(_) => println!("Le mot de passe est valide."),
///     Err(e) => println!("Erreur lors de la vérification du mot de passe : {:?}", e),
/// }
/// ```
///
/// Dans cet exemple, le mot de passe "StrongP@ssw0rd" est d'abord haché et chiffré en utilisant un chiffrement hybride.
/// Ensuite, il est déchiffré et vérifié pour s'assurer qu'il correspond au hash d'origine.
///
/// # Remarques
///
/// - **Clé privée RSA** : La clé privée doit être gardée en sécurité, car elle est nécessaire pour déchiffrer
///   la clé symétrique et, par conséquent, le hash du mot de passe.
/// - **Intégrité des données** : AES-GCM assure l'intégrité des données chiffrées. Toute modification non autorisée
///   des données sera détectée lors du déchiffrement.
///
/// # Erreurs
///
/// La fonction peut renvoyer une `Err(IronCryptError)` si :
/// - Les données encodées en base64 ne peuvent pas être décodées.
/// - La désérialisation du JSON échoue.
/// - Des champs requis sont manquants dans les données désérialisées.
/// - Le déchiffrement de la clé symétrique avec la clé privée RSA échoue.
/// - Le déchiffrement du hash avec AES-GCM échoue (par exemple, en cas de nonce incorrect ou de données altérées).
/// - La conversion du hash déchiffré en chaîne de caractères échoue.
/// - Le hash déchiffré ne peut pas être analysé en tant que `PasswordHash`.
/// - Le mot de passe ne correspond pas au hash déchiffré.
///
/// # Sécurité
///
/// - **Confidentialité** : La clé privée RSA est nécessaire pour déchiffrer la clé symétrique, assurant que seules
///   les parties autorisées peuvent accéder au hash du mot de passe.
/// - **Résistance aux attaques** : En utilisant Argon2 pour le hachage, la fonction assure une résistance accrue
///   contre les attaques par force brute et par dictionnaire.
///
/// # Notes
///
/// - **Gestion des erreurs** : Les erreurs retournées fournissent des messages explicites pour faciliter le débogage
///   tout en évitant de divulguer des informations sensibles.
/// - **Utilisation cohérente** : Cette fonction doit être utilisée en conjonction avec
///   `hash_and_encrypt_password_with_criteria` pour assurer la cohérence du processus de chiffrement et de déchiffrement.

pub fn decrypt_and_verify_password(
    encrypted_data: &str,
    password: &str,
    private_key_directory: &str,
) -> Result<(), IronCryptError> {
    // Parser les données JSON
    let data: serde_json::Value = serde_json::from_str(encrypted_data).map_err(|e| {
        IronCryptError::DecryptionError(format!("Erreur lors du parsing des données : {}", e))
    })?;

    // Récupérer la version de la clé
    let key_version = data["key_version"].as_str().ok_or_else(|| {
        IronCryptError::DecryptionError("Champ 'key_version' manquant".to_string())
    })?;

    // Construire le chemin vers la clé privée correspondante
    let private_key_path = format!("{}/private_key_{}.pem", private_key_directory, key_version);

    // Charger la clé privée
    let private_key = load_private_key(&private_key_path)?;

    // Récupérer les champs
    let encrypted_symmetric_key_b64 =
        data["encrypted_symmetric_key"].as_str().ok_or_else(|| {
            IronCryptError::DecryptionError("Champ 'encrypted_symmetric_key' manquant".to_string())
        })?;
    let nonce_b64 = data["nonce"]
        .as_str()
        .ok_or_else(|| IronCryptError::DecryptionError("Champ 'nonce' manquant".to_string()))?;
    let ciphertext_b64 = data["ciphertext"].as_str().ok_or_else(|| {
        IronCryptError::DecryptionError("Champ 'ciphertext' manquant".to_string())
    })?;

    // Décoder les données base64
    let encrypted_symmetric_key = base64_standard
        .decode(encrypted_symmetric_key_b64)
        .map_err(|e| {
            IronCryptError::DecryptionError(format!(
                "Erreur lors du décodage de la clé symétrique chiffrée : {}",
                e
            ))
        })?;
    let nonce = base64_standard.decode(nonce_b64).map_err(|e| {
        IronCryptError::DecryptionError(format!("Erreur lors du décodage du nonce : {}", e))
    })?;
    let ciphertext = base64_standard.decode(ciphertext_b64).map_err(|e| {
        IronCryptError::DecryptionError(format!("Erreur lors du décodage du ciphertext : {}", e))
    })?;

    // Déchiffrer la clé symétrique avec RSA
    let padding = Oaep::new::<Sha256>();
    let symmetric_key = private_key
        .decrypt(padding, &encrypted_symmetric_key)
        .map_err(|e| {
            IronCryptError::DecryptionError(format!(
                "Erreur lors du déchiffrement de la clé symétrique : {}",
                e
            ))
        })?;

    // Déchiffrer le hash avec AES-GCM
    let cipher = Aes256Gcm::new_from_slice(&symmetric_key).map_err(|e| {
        IronCryptError::DecryptionError(format!(
            "Erreur lors de l'initialisation du cipher : {}",
            e
        ))
    })?;
    let nonce = Nonce::from_slice(&nonce);
    let decrypted_hash = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|e| {
        IronCryptError::DecryptionError(format!("Erreur lors du déchiffrement du hash : {}", e))
    })?;

    // Convertir le hash déchiffré en chaîne de caractères
    let decrypted_hash_str = String::from_utf8(decrypted_hash).map_err(|e| {
        IronCryptError::DecryptionError(format!(
            "Erreur lors de la conversion du hash déchiffré : {}",
            e
        ))
    })?;

    // Analyse du hash déchiffré
    let parsed_hash = PasswordHash::new(&decrypted_hash_str).map_err(|e| {
        IronCryptError::DecryptionError(format!("Erreur lors du parsing du hash déchiffré : {}", e))
    })?;

    // Créer une instance d'Argon2
    let argon2 = Argon2::default();

    // Vérifier le mot de passe
    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| IronCryptError::InvalidPassword)?;

    Ok(())
}
