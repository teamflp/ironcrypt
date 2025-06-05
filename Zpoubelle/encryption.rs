// encryption.rs

use crate::handle_error::IronCryptError;
use crate::{load_private_key, IronCryptConfig};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit}; // Décommentez cette ligne pour importer le trait KeyInit
use aes_gcm::{AesGcm, Nonce};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::{Oaep, RsaPublicKey};
use serde_json;
use sha2::Sha256;

// Définition des alias de types pour AES-GCM avec différentes tailles de clés
type Aes128Gcm = AesGcm<Aes128, U12>;
type Aes192Gcm = AesGcm<Aes192, U12>;
type Aes256Gcm = AesGcm<Aes256, U12>;

/// Hache et chiffre un mot de passe en utilisant les paramètres de configuration spécifiés.
///
/// # Arguments
///
/// - `password`: Le mot de passe à hacher et chiffrer.
/// - `public_key`: La clé publique RSA utilisée pour chiffrer la clé symétrique.
/// - `config`: La configuration de sécurité `IronCryptConfig`, incluant les paramètres d'Argon2 et les critères de mot de passe.
/// - `key_version`: La version de la clé publique utilisée.
///
/// # Retour
///
/// Renvoie une chaîne JSON contenant les données chiffrées.
///
/// # Erreurs
///
/// Renvoie `IronCryptError` en cas d'échec du hachage, du chiffrement ou si le mot de passe ne respecte pas les critères.
pub fn hash_and_encrypt_password(
    password: &str,
    public_key: &RsaPublicKey,
    config: &IronCryptConfig,
    key_version: &str,
) -> Result<String, IronCryptError> {
    // Vérifier les critères du mot de passe
    config.password_criteria.validate(password)?;

    // Configurer Argon2 avec les paramètres désirés
    let params = Params::new(
        config.argon2_memory_cost,
        config.argon2_time_cost,
        config.argon2_parallelism,
        None,
    )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Générer un sel aléatoire
    let salt = SaltString::generate(&mut OsRng);

    // Hacher le mot de passe
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    // Générer une clé symétrique aléatoire (en fonction de la taille spécifiée)
    let key_size_bytes = config.aes_key_size / 8;
    let mut symmetric_key = vec![0u8; key_size_bytes];
    OsRng.fill_bytes(&mut symmetric_key);

    // Générer un nonce aléatoire de 96 bits (12 octets)
    let mut nonce_bytes = [0u8; 12]; // 12 octets pour le nonce AES
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Sélectionner le cipher AES approprié en fonction de la taille de la clé
    let ciphertext = match config.aes_key_size {
        128 => {
            let cipher = Aes128Gcm::new_from_slice(&symmetric_key)?;
            cipher.encrypt(nonce, password_hash.as_bytes())?
        }
        192 => {
            let cipher = Aes192Gcm::new_from_slice(&symmetric_key)?;
            cipher.encrypt(nonce, password_hash.as_bytes())?
        }
        256 => {
            let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
            cipher.encrypt(nonce, password_hash.as_bytes())?
        }
        _ => {
            return Err(IronCryptError::EncryptionError(
                "Taille de clé AES invalide. Doit être 128, 192 ou 256 bits.".to_string(),
            ));
        }
    };

    // Chiffrer la clé symétrique avec RSA
    let padding = Oaep::new::<Sha256>();
    let encrypted_symmetric_key = public_key.encrypt(&mut OsRng, padding, &symmetric_key)?;

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
/// # Arguments
///
/// - `encrypted_data`: Les données chiffrées sous forme de chaîne JSON.
/// - `password`: Le mot de passe à vérifier.
/// - `private_key_directory`: Le répertoire où se trouve la clé privée.
///
/// # Retour
///
/// Renvoie `Ok(())` si le mot de passe est valide, ou une erreur `IronCryptError` sinon.
pub fn decrypt_and_verify_password(
    encrypted_data: &str,
    password: &str,
    private_key_directory: &str,
) -> Result<(), IronCryptError> {
    // Parser les données JSON
    let data: serde_json::Value = serde_json::from_str(encrypted_data)?;

    // Récupérer la version de la clé
    let key_version = data["key_version"].as_str().ok_or_else(|| {
        IronCryptError::DecryptionError("Champ 'key_version' manquant".to_string())
    })?;

    // Construire le chemin vers la clé privée correspondante
    let private_key_path = format!("{}/private_key_{}.pem", private_key_directory, key_version);
    println!("Chemin de la clé privée : {}", private_key_path);

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
    let encrypted_symmetric_key = base64_standard.decode(encrypted_symmetric_key_b64)?;
    let nonce_bytes = base64_standard.decode(nonce_b64)?;
    let ciphertext = base64_standard.decode(ciphertext_b64)?;

    println!("Longueur du nonce_bytes : {}", nonce_bytes.len());
    println!(
        "Longueur du encrypted_symmetric_key : {}",
        encrypted_symmetric_key.len()
    );

    // Vérifier la longueur du nonce
    if nonce_bytes.len() != 12 {
        return Err(IronCryptError::DecryptionError(
            format!("Nonce invalide lors du déchiffrement. Taille attendue: 12 octets, taille obtenue: {} octets", nonce_bytes.len()),
        ));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Déchiffrer la clé symétrique avec RSA
    let padding = Oaep::new::<Sha256>();
    let symmetric_key = private_key.decrypt(padding, &encrypted_symmetric_key)?;

    println!("Longueur de la clé symétrique : {}", symmetric_key.len());

    // Sélectionner le cipher AES approprié en fonction de la longueur de la clé
    let decrypted_hash = match symmetric_key.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(&symmetric_key)?;
            cipher.decrypt(nonce, ciphertext.as_ref())?
        }
        24 => {
            let cipher = Aes192Gcm::new_from_slice(&symmetric_key)?;
            cipher.decrypt(nonce, ciphertext.as_ref())?
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(&symmetric_key)?;
            cipher.decrypt(nonce, ciphertext.as_ref())?
        }
        _ => {
            return Err(IronCryptError::DecryptionError(format!(
                "Taille de clé AES invalide lors du déchiffrement. Taille obtenue: {} octets",
                symmetric_key.len()
            )));
        }
    };

    // Convertir le hash déchiffré en chaîne de caractères
    let decrypted_hash_str = String::from_utf8(decrypted_hash)?;

    // Analyse du hash déchiffré
    let parsed_hash = PasswordHash::new(&decrypted_hash_str)?;

    // Créer une instance d'Argon2 avec les mêmes paramètres utilisés lors du hachage
    let argon2 = Argon2::default();

    // Vérifier le mot de passe
    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| IronCryptError::InvalidPassword)?;

    Ok(())
}
