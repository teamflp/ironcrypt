use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
use rsa::{Oaep, RsaPublicKey};
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{IronCryptError, PasswordCriteria};

/// Configuration of Argon2 parameters for hashing.
#[derive(Clone, Debug)]
pub struct Argon2Config {
    pub memory_cost: u32, // per ex. 65536 (64 Mo)
    pub time_cost: u32,   // per ex. 3
    pub parallelism: u32, // per ex. 1
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_cost: 65536,
            time_cost: 3,
            parallelism: 1,
        }
    }
}

/// Serializable return structure containing encryption information.
#[derive(Serialize, Debug)]
pub struct EncryptedData {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
    pub nonce: String,
    pub ciphertext: String,
    /// Optional, if `hash_password` is `true` and we want to return the hash.
    pub password_hash: Option<String>,
}

/// Chiffre des données binaires (data) via AES-256-GCM + RSA,
/// et (optionnellement) hache le mot de passe en Argon2id.
///
/// # Étapes
/// 1) Vérifie la robustesse du mot de passe (`criteria.validate`).
/// 2) (Optionnel) Hachage du mot de passe via Argon2.
/// 3) Génère une clé symétrique AES-256 (aléatoire).
/// 4) Chiffre `data` via AES-256-GCM.
/// 5) Chiffre la clé symétrique via RSA (OAEP/SHA-256).
/// 6) Retourne une structure `EncryptedData` sérialisable.
///
/// # Paramètres
/// - `data`: Les données binaires à chiffrer.
/// - `password`: Le mot de passe à valider et éventuellement à hacher.
/// - `public_key`: Clé publique RSA (pour chiffrer la clé AES).
/// - `criteria`: Critères de robustesse du mot de passe.
/// - `key_version`: Identifiant de version de la clé (ex. "v1"), utile pour la rotation.
/// - `argon_cfg`: Configuration Argon2 (mémoire, time cost, etc.).
/// - `hash_password`: Si `true`, on hache le mot de passe et on l'inclut dans `EncryptedData`.
///
/// # Retour
/// - `Ok(EncryptedData)` en cas de succès,
/// - `Err(IronCryptError)` si une erreur survient (mot de passe trop faible, chiffrement, etc.).
pub fn encrypt_data_with_criteria(
    data: &[u8],
    password: &mut String, // mut pour pouvoir zeroize ensuite
    public_key: &RsaPublicKey,
    criteria: &PasswordCriteria,
    key_version: &str,
    argon_cfg: Argon2Config,
    hash_password: bool,
) -> Result<EncryptedData, IronCryptError> {
    // 1) Vérifier la robustesse du mot de passe
    criteria.validate(password)?;

    // Argon2 hashing (if hash_password == true)
    let password_hash = if hash_password {
        let params = Params::new(
            argon_cfg.memory_cost,
            argon_cfg.time_cost,
            argon_cfg.parallelism,
            None,
        )?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Use the same OsRng from argon2::password_hash::rand_core
        let salt = SaltString::generate(&mut OsRng);

        let hash_str = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
        Some(base64_standard.encode(hash_str))
    } else {
        None
    };

    // Generate AES key
    let mut symmetric_key = [0u8; 32];
    // still safe, because we re-imported RngCore from argon2's rand_core
    OsRng.fill_bytes(&mut symmetric_key);

    // 4) Chiffrement des données en AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
        .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96 bits = 12 octets
    let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| {
        IronCryptError::EncryptionError(format!("Erreur lors du chiffrement AES : {e}"))
    })?;

    // 5) Chiffrement de la clé symétrique via RSA (OAEP/SHA-256)
    let padding = Oaep::new::<Sha256>();
    let encrypted_symmetric_key = public_key
        .encrypt(&mut OsRng, padding, &symmetric_key)
        .map_err(|e| {
            IronCryptError::EncryptionError(format!(
                "Erreur lors du chiffrement de la clé symétrique RSA : {e}"
            ))
        })?;

    // 6) Construction de la structure de retour
    let result = EncryptedData {
        key_version: key_version.to_string(),
        encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
        nonce: base64_standard.encode(&nonce),
        ciphertext: base64_standard.encode(&ciphertext),
        password_hash,
    };

    // Effacer la clé symétrique en mémoire (bonne pratique)
    symmetric_key.zeroize();

    // Effacer le mot de passe en clair si on veut éviter de le garder en mémoire plus longtemps
    password.zeroize();

    Ok(result)
}

