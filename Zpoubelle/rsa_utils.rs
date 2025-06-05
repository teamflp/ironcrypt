// rsa_utils.rs

use crate::handle_error::IronCryptError;
use rand::rngs::OsRng;
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Génère une paire de clés RSA (privée et publique).
///
/// Cette fonction crée une clé privée RSA de la taille spécifiée ainsi que la clé publique correspondante.
/// Les clés sont générées en utilisant un générateur de nombres aléatoires sécurisé (`OsRng`),
/// garantissant un niveau élevé de sécurité pour les opérations de chiffrement et de signature numérique.
///
/// # Arguments
///
/// * `key_size` - La taille de la clé en bits (par exemple, 2048).
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok((RsaPrivateKey, RsaPublicKey))` : Les clés générées.
/// - `Err(IronCryptError)` : Une erreur si la génération échoue.
pub fn generate_rsa_keys(key_size: u32) -> Result<(RsaPrivateKey, RsaPublicKey), IronCryptError> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, key_size as usize).map_err(|e| {
        IronCryptError::KeyGenerationError(format!(
            "Erreur lors de la génération de la clé privée : {}",
            e
        ))
    })?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok((private_key, public_key))
}

/// Charge la clé publique RSA à partir d'un fichier PEM.
///
/// Cette fonction lit le fichier PEM spécifié et charge la clé publique RSA qu'il contient.
///
/// # Arguments
///
/// * `public_key_path` - Le chemin vers le fichier contenant la clé publique au format PEM.
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok(RsaPublicKey)` : La clé publique chargée avec succès.
/// - `Err(IronCryptError)` : Une erreur si le chargement échoue.
pub fn load_public_key(public_key_path: &str) -> Result<RsaPublicKey, IronCryptError> {
    let public_pem = std::fs::read_to_string(public_key_path)?;
    let public_key = RsaPublicKey::from_pkcs1_pem(&public_pem).map_err(|e| {
        IronCryptError::KeyLoadingError(format!(
            "Erreur lors du chargement de la clé publique : {}",
            e
        ))
    })?;
    Ok(public_key)
}

/// Charge la clé privée RSA à partir d'un fichier PEM.
///
/// Cette fonction lit le fichier PEM spécifié et charge la clé privée RSA qu'il contient.
///
/// # Arguments
///
/// * `private_key_path` - Le chemin vers le fichier contenant la clé privée au format PEM.
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok(RsaPrivateKey)` : La clé privée chargée avec succès.
/// - `Err(IronCryptError)` : Une erreur si le chargement échoue.
pub fn load_private_key(private_key_path: &str) -> Result<RsaPrivateKey, IronCryptError> {
    let private_pem = std::fs::read_to_string(private_key_path)?;
    let private_key = RsaPrivateKey::from_pkcs1_pem(&private_pem).map_err(|e| {
        IronCryptError::KeyLoadingError(format!(
            "Erreur lors du chargement de la clé privée : {}",
            e
        ))
    })?;
    Ok(private_key)
}

/// Sauvegarde les clés RSA générées dans des fichiers.
///
/// Cette fonction prend une clé privée et une clé publique RSA, les convertit en format PEM,
/// puis les enregistre dans les fichiers spécifiés.
///
/// # Arguments
///
/// * `private_key` - Une référence à la clé privée RSA à sauvegarder.
/// * `public_key` - Une référence à la clé publique RSA à sauvegarder.
/// * `priv_path` - Le chemin du fichier où la clé privée sera sauvegardée.
/// * `pub_path` - Le chemin du fichier où la clé publique sera sauvegardée.
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok(())` : Si les clés ont été sauvegardées avec succès.
/// - `Err(IronCryptError)` : Une erreur si la sauvegarde échoue.
pub fn save_keys_to_files(
    private_key: &RsaPrivateKey,
    public_key: &RsaPublicKey,
    priv_path: &str,
    pub_path: &str,
) -> Result<(), IronCryptError> {
    // Convertir la clé privée en format PKCS#1 PEM
    let private_pem = private_key.to_pkcs1_pem(Default::default()).map_err(|e| {
        IronCryptError::KeySavingError(format!(
            "Erreur lors de la conversion de la clé privée : {}",
            e
        ))
    })?;

    // Convertir la clé publique en format PKCS#1 PEM
    let public_pem = public_key.to_pkcs1_pem(Default::default()).map_err(|e| {
        IronCryptError::KeySavingError(format!(
            "Erreur lors de la conversion de la clé publique : {}",
            e
        ))
    })?;

    // Sauvegarder la clé privée
    std::fs::write(priv_path, private_pem.as_bytes())?;

    // Sauvegarder la clé publique
    std::fs::write(pub_path, public_pem.as_bytes())?;

    Ok(())
}

/// Charge les clés RSA (privée et publique) à partir de fichiers PEM.
///
/// Cette fonction utilise `load_private_key` et `load_public_key` pour charger les clés à partir des fichiers spécifiés.
///
/// # Arguments
///
/// * `private_key_path` - Le chemin vers le fichier de la clé privée.
/// * `public_key_path` - Le chemin vers le fichier de la clé publique.
///
/// # Retour
///
/// Renvoie un `Result` contenant :
/// - `Ok((RsaPrivateKey, RsaPublicKey))` : Les clés chargées avec succès.
/// - `Err(IronCryptError)` : Une erreur si le chargement échoue.
pub fn load_rsa_keys(
    private_key_path: &str,
    public_key_path: &str,
) -> Result<(RsaPrivateKey, RsaPublicKey), IronCryptError> {
    let private_key = load_private_key(private_key_path)?;
    let public_key = load_public_key(public_key_path)?;
    Ok((private_key, public_key))
}
