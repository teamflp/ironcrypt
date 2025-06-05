use crate::{
    generate_rsa_keys, load_private_key, load_public_key, save_keys_to_files, IronCryptError,
};
use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use argon2::PasswordVerifier;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine;
// use rand::RngCore as MyRngCore;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::config::IronCryptConfig;
use crate::criteria::PasswordCriteria;

#[derive(Clone, Debug)]
pub struct Argon2Config {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
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

/// Structure renvoyée après chiffrement (données JSON + base64).
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    pub key_version: String,
    pub encrypted_symmetric_key: String,
    pub nonce: String,
    pub ciphertext: String,
    /// Optionnel, si `hash_password` est `true`.
    pub password_hash: Option<String>,
}

/// La structure `IronCrypt` gère la génération/chargement des clés
/// et expose des méthodes pour chiffrer/déchiffrer un mot de passe ou des données binaires.
pub struct IronCrypt {
    key_directory: String,
    key_version: String,
    pub config: IronCryptConfig,
}

impl IronCrypt {
    /// Crée une nouvelle instance d'IronCrypt (génère les clés RSA si besoin).
    pub fn new(
        directory: &str,
        version: &str,
        config: IronCryptConfig,
    ) -> Result<Self, IronCryptError> {
        let instance = Self {
            key_directory: directory.to_string(),
            key_version: version.to_string(),
            config,
        };
        instance.ensure_keys_exist()?;
        Ok(instance)
    }

    fn ensure_keys_exist(&self) -> Result<(), IronCryptError> {
        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);

        if !Path::new(&self.key_directory).exists() {
            fs::create_dir_all(&self.key_directory)?;
        }

        if !Path::new(&private_key_path).exists() {
            let (priv_key, pub_key) = generate_rsa_keys(self.config.rsa_key_size)?;
            save_keys_to_files(&priv_key, &pub_key, &private_key_path, &public_key_path)?;
        }
        Ok(())
    }

    /// Chiffre un mot de passe (logique existante).
    /// Retourne une chaîne JSON (base64) prête à être stockée dans "encrypted_data.json".
    pub fn encrypt_password(&self, password: &str) -> Result<String, IronCryptError> {
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);
        let public_key = load_public_key(&public_key_path)?;

        let mut pwd_string = password.to_string();
        let criteria: &PasswordCriteria = &self.config.password_criteria;

        let argon_cfg = Argon2Config {
            memory_cost: self.config.argon2_memory_cost,
            time_cost: self.config.argon2_time_cost,
            parallelism: self.config.argon2_parallelism,
        };

        // On chiffre des données vides (b""), en hachant le mot de passe (hash_password = true).
        let enc_data = self.encrypt_data_with_criteria(
            b"",
            &mut pwd_string,
            &public_key,
            criteria,
            &self.key_version,
            argon_cfg,
            true,
        )?;

        let json_str = serde_json::to_string(&enc_data)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
        Ok(json_str)
    }

    /// Vérifie un mot de passe en déchiffrant la chaîne JSON (logique existante).
    pub fn verify_password(
        &self,
        encrypted_json: &str,
        user_input_password: &str,
    ) -> Result<bool, IronCryptError> {
        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        self.decrypt_data_and_verify_password(
            encrypted_json,
            user_input_password,
            &private_key_path,
        )
    }

    // --------------------------------------------------------------------
    //                          NOUVELLES METHODES
    // --------------------------------------------------------------------

    /// Chiffre n'importe quelle donnée binaire (data) en JSON (base64).
    /// Le `password` peut être utilisé (ou pas) pour imposer un Argon2, si `hash_password=false`, on ignore le hash.
    pub fn encrypt_binary_data(
        &self,
        data: &[u8],
        password: &str,
    ) -> Result<String, IronCryptError> {
        // 1) Charger la clé publique
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);
        let public_key = load_public_key(&public_key_path)?;

        // 2) Convertir en mutable (nécessaire si on hache le password)
        let mut pwd_string = password.to_string();

        // 3) On peut décider ici de ne pas hacher le password. Pour l'exemple, "false"
        //    Si vous voulez un Argon2, mettez "true" + adapter "criteria" etc.
        let hash_it = false;

        let enc_data = self.encrypt_data_with_criteria(
            data,
            &mut pwd_string,
            &public_key,
            &self.config.password_criteria,
            &self.key_version,
            Argon2Config::default(),
            hash_it,
        )?;

        // 4) Sérialiser en JSON
        let json_str = serde_json::to_string(&enc_data)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
        Ok(json_str)
    }

    /// Déchiffre un JSON (base64) représentant des données binaires,
    /// et renvoie un Vec<u8> (le binaire original).
    pub fn decrypt_binary_data(
        &self,
        encrypted_json: &str,
        password: &str,
    ) -> Result<Vec<u8>, IronCryptError> {
        // 1) Désérialiser le JSON -> EncryptedData
        let ed: EncryptedData = serde_json::from_str(encrypted_json)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        // 2) Charger la clé privée
        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        let private_key = load_private_key(&private_key_path)?;

        // 3) Déchiffrer la clé symétrique
        let encrypted_key_bytes = base64_standard
            .decode(&ed.encrypted_symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(format!("Erreur decode symkey : {e}")))?;

        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key
            .decrypt(padding, &encrypted_key_bytes)
            .map_err(|e| IronCryptError::DecryptionError(format!("RSA decrypt error : {e}")))?;

        // 4) Déchiffrer les données (ciphertext)
        let ciphertext = base64_standard.decode(&ed.ciphertext).map_err(|e| {
            IronCryptError::DecryptionError(format!("Erreur decode ciphertext : {e}"))
        })?;

        let nonce_bytes = base64_standard
            .decode(&ed.nonce)
            .map_err(|e| IronCryptError::DecryptionError(format!("Erreur decode nonce : {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(format!("Erreur init AES : {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| IronCryptError::DecryptionError(format!("AES decrypt : {e}")))?;

        // 5) Si "ed.password_hash" existe => comparer Argon2 + `password`
        if let Some(hash_b64) = ed.password_hash.as_ref() {
            let decoded_hash = base64_standard.decode(hash_b64).map_err(|e| {
                IronCryptError::DecryptionError(format!("Decode password_hash : {e}"))
            })?;
            let hash_str = String::from_utf8(decoded_hash)
                .map_err(|e| IronCryptError::DecryptionError(format!("UTF8 decode : {e}")))?;

            // Vérifier
            let parsed_hash = PasswordHash::new(&hash_str)
                .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
            let argon2 = Argon2::default();
            if argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_err()
            {
                return Err(IronCryptError::InvalidPassword);
            }
        }

        // Retourner le binaire déchiffré
        Ok(plaintext)
    }

    // --------------------------------------------------------------------
    // Méthodes internes existantes
    // --------------------------------------------------------------------

    fn encrypt_data_with_criteria(
        &self,
        data: &[u8],
        password: &mut String,
        public_key: &RsaPublicKey,
        criteria: &PasswordCriteria,
        key_version: &str,
        argon_cfg: Argon2Config,
        hash_password: bool,
    ) -> Result<EncryptedData, IronCryptError> {
        // 1) Vérifier la robustesse si besoin
        criteria.validate(password)?;

        // 2) Hachage optionnel
        let password_hash = if hash_password {
            let params = Params::new(
                argon_cfg.memory_cost,
                argon_cfg.time_cost,
                argon_cfg.parallelism,
                None,
            )?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let salt = SaltString::generate(&mut OsRng);

            let hash_str = argon2
                .hash_password(password.as_bytes(), &salt)?
                .to_string();
            Some(base64_standard.encode(hash_str))
        } else {
            None
        };

        // 3) Clé symétrique
        let mut symmetric_key = [0u8; 32];
        OsRng.fill_bytes(&mut symmetric_key);

        // 4) AES-GCM
        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
            .map_err(|e| IronCryptError::EncryptionError(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| IronCryptError::EncryptionError(format!("Chiffrement AES: {e}")))?;

        // 5) Chiffrement de la clé symétrique en RSA
        let padding = Oaep::new::<Sha256>();
        let encrypted_symmetric_key = public_key
            .encrypt(&mut OsRng, padding, &symmetric_key)
            .map_err(|e| IronCryptError::EncryptionError(format!("Chiffrement RSA: {e}")))?;

        let result = EncryptedData {
            key_version: key_version.to_string(),
            encrypted_symmetric_key: base64_standard.encode(&encrypted_symmetric_key),
            nonce: base64_standard.encode(&nonce_bytes),
            ciphertext: base64_standard.encode(&ciphertext),
            password_hash,
        };

        symmetric_key.zeroize();
        password.zeroize();

        Ok(result)
    }

    fn decrypt_data_and_verify_password(
        &self,
        encrypted_data_json: &str,
        input_password: &str,
        private_key_pem_path: &str,
    ) -> Result<bool, IronCryptError> {
        let ed: EncryptedData = serde_json::from_str(encrypted_data_json)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        // 1) Charger la clé privée
        let private_key_pem = std::fs::read_to_string(private_key_pem_path)?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_pem)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;

        // 2) Déchiffrer la clé symétrique
        let encrypted_key_bytes = base64_standard
            .decode(ed.encrypted_symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
        let padding = Oaep::new::<Sha256>();
        let symmetric_key = private_key
            .decrypt(padding, &encrypted_key_bytes)
            .map_err(|e| IronCryptError::DecryptionError(format!("RSA decrypt error: {e}")))?;

        // 3) AES decrypt
        let ciphertext = base64_standard
            .decode(ed.ciphertext)
            .map_err(|e| IronCryptError::DecryptionError(format!("Decode ciphertext: {e}")))?;
        let nonce_bytes = base64_standard
            .decode(ed.nonce)
            .map_err(|e| IronCryptError::DecryptionError(format!("Decode nonce: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(&symmetric_key)
            .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let _plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| IronCryptError::DecryptionError(format!("AES decrypt error: {e}")))?;

        // 4) Comparer le hash Argon2 si password_hash
        if let Some(hash_b64) = ed.password_hash {
            let decoded_hash = base64_standard
                .decode(hash_b64)
                .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
            let hash_str = String::from_utf8(decoded_hash)
                .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
            let parsed_hash = PasswordHash::new(&hash_str)
                .map_err(|e| IronCryptError::DecryptionError(e.to_string()))?;
            let argon2 = Argon2::default();
            if argon2
                .verify_password(input_password.as_bytes(), &parsed_hash)
                .is_err()
            {
                return Err(IronCryptError::InvalidPassword);
            }
        }

        Ok(true)
    }
}
