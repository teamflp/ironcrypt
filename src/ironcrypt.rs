use crate::config::IronCryptConfig;
use crate::decrypt_and_verify_password;
use crate::generate_rsa_keys;
use crate::hash_and_encrypt_password_with_criteria;
use crate::load_private_key;
use crate::load_public_key;
use crate::save_keys_to_files;
use crate::IronCryptError;
use std::path::Path;

/// La structure `IronCrypt` est responsable de la gestion du chiffrement et de la vérification des mots de passe.
/// Elle utilise des clés RSA pour le chiffrement asymétrique et Argon2 pour le hachage sécurisé des mots de passe.
/// Les clés sont stockées dans un répertoire défini, et une vérification automatique de leur existence est effectuée.
///
/// # Champs
///
/// - `key_directory`: Le répertoire où sont stockées les clés RSA (privée et publique).
/// - `key_version`: La version des clés utilisée pour distinguer les différentes paires de clés.
/// - `config`: Les configurations de sécurité définies par `IronCryptConfig`, telles que la taille des clés RSA, les critères de mot de passe, etc.
///
/// # Exemple
///
/// ```rust
/// use ironcrypt::{IronCrypt, IronCryptConfig};
/// use std::fs;
/// use std::path::Path;
///
/// // Créer une configuration sécurisée avec des paramètres par défaut
/// let config = IronCryptConfig::default();
///
/// // Chemin temporaire pour les tests
/// let key_directory = "test_keys";
///
/// // Assurer que le répertoire de clés existe
/// if !Path::new(key_directory).exists() {
///     fs::create_dir_all(key_directory).expect("Erreur lors de la création du répertoire de clés");
/// }
///
/// let crypt = IronCrypt::new(key_directory, "v1", config).expect("Erreur lors de la création d'IronCrypt");
///
/// let encrypted = crypt.encrypt_password("MyS3cureP@ssw0rd!")
///     .expect("Erreur lors du chiffrement du mot de passe");
///
/// let is_valid = crypt.verify_password(&encrypted, "MyS3cureP@ssw0rd!")
///     .expect("Erreur lors de la vérification du mot de passe");
///
/// assert!(is_valid, "Le mot de passe devrait être valide");
/// ```
pub struct IronCrypt {
    key_directory: String,
    key_version: String,
    config: IronCryptConfig,
}

impl IronCrypt {
    /// Crée une nouvelle instance d'IronCrypt avec le répertoire des clés, la version de clé, et la configuration de sécurité spécifiée.
    ///
    /// Cette fonction vérifie également si les clés RSA existent déjà dans le répertoire fourni.
    /// Si elles n'existent pas, elles sont générées automatiquement en fonction de la taille spécifiée dans `IronCryptConfig`.
    ///
    /// # Arguments
    ///
    /// * `directory` - Le répertoire où seront stockées les clés RSA.
    /// * `version` - La version de la clé utilisée pour identifier les différentes paires de clés.
    /// * `config` - La configuration de sécurité, définie par `IronCryptConfig`, incluant la taille des clés RSA, les critères de mot de passe, etc.
    ///
    /// # Retour
    ///
    /// Renvoie une instance d'`IronCrypt` ou une erreur si la génération ou le chargement des clés échoue.
    ///
    /// # Exemple
    ///
    /// ```rust
    /// use ironcrypt::{IronCrypt, IronCryptConfig};
    /// use std::fs;
    /// use std::path::Path;
    ///
    /// // Créer une configuration sécurisée avec des paramètres par défaut
    /// let config = IronCryptConfig::default();
    ///
    /// // Chemin temporaire pour les tests
    /// let key_directory = "test_keys";
    ///
    /// // Assurer que le répertoire de clés existe
    /// if !Path::new(key_directory).exists() {
    ///     fs::create_dir_all(key_directory).expect("Erreur lors de la création du répertoire de clés");
    /// }
    ///
    /// let crypt = IronCrypt::new(key_directory, "v1", config).expect("Erreur lors de la création d'IronCrypt");
    /// ```
    pub fn new(
        directory: &str,
        version: &str,
        config: IronCryptConfig,
    ) -> Result<Self, IronCryptError> {
        let instance = IronCrypt {
            key_directory: directory.to_string(),
            key_version: version.to_string(),
            config,
        };
        instance.ensure_keys_exist()?;
        Ok(instance)
    }

    /// Vérifie si les clés RSA existent déjà dans le répertoire spécifié.
    ///
    /// Si elles n'existent pas, cette fonction génère une nouvelle paire de clés RSA (privée et publique) et les stocke
    /// dans le répertoire défini par `key_directory` et `key_version`.
    ///
    /// # Erreurs
    ///
    /// Renvoie une erreur de type `IronCryptError` si la génération des clés ou leur sauvegarde échoue.
    ///
    /// # Exemple
    ///
    /// Cette fonction est appelée automatiquement lors de la création d'une nouvelle instance d'`IronCrypt`.
    fn ensure_keys_exist(&self) -> Result<(), IronCryptError> {
        let private_key_path = format!("{}/private_key_{}.pem", self.key_directory, self.key_version);
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);

        // Créer le répertoire si nécessaire
        if !Path::new(&self.key_directory).exists() {
            std::fs::create_dir_all(&self.key_directory)
                .expect("Erreur lors de la création du répertoire des clés");
        }

        // Générer et sauvegarder les clés si elles n'existent pas
        if !Path::new(&private_key_path).exists() {
            let (private_key, public_key) = generate_rsa_keys(self.config.rsa_key_size)?;
            save_keys_to_files(&private_key, &public_key, &private_key_path, &public_key_path)?;
        }
        Ok(())
    }

    /// Chiffre un mot de passe en utilisant la clé publique RSA et les critères de sécurité définis.
    ///
    /// Cette fonction utilise la clé publique RSA pour chiffrer le mot de passe après l'avoir haché avec Argon2.
    /// Les critères de robustesse du mot de passe sont définis dans `IronCryptConfig` via `PasswordCriteria`.
    ///
    /// # Arguments
    ///
    /// * `password` - Le mot de passe à chiffrer.
    ///
    /// # Retour
    ///
    /// Renvoie une chaîne de caractères représentant les données chiffrées ou une erreur en cas de problème.
    ///
    /// # Erreurs
    ///
    /// - `IronCryptError::EncryptionError` : Si le chiffrement échoue.
    /// - `IronCryptError::KeyLoadingError` : Si la clé publique ne peut pas être chargée.
    ///
    /// # Exemple
    ///
    /// ```rust
    /// use ironcrypt::{IronCrypt, IronCryptConfig};
    /// use std::fs;
    /// use std::path::Path;
    ///
    /// // Créer une configuration sécurisée avec des paramètres par défaut
    /// let config = IronCryptConfig::default();
    ///
    /// // Créer le répertoire des clés pour les tests
    /// let key_directory = "test_keys";
    ///
    /// if !Path::new(key_directory).exists() {
    ///     fs::create_dir_all(key_directory).expect("Erreur lors de la création du répertoire des clés");
    /// }
    ///
    /// let crypt = IronCrypt::new(key_directory, "v1", config)
    ///     .expect("Erreur lors de la création d'IronCrypt");
    ///
    /// let encrypted = crypt.encrypt_password("MyS3cureP@ssw0rd!")
    ///     .expect("Erreur lors du chiffrement du mot de passe");
    /// println!("Mot de passe chiffré : {}", encrypted);
    /// ```
    pub fn encrypt_password(&self, password: &str) -> Result<String, IronCryptError> {
        let public_key_path = format!("{}/public_key_{}.pem", self.key_directory, self.key_version);
        let public_key = load_public_key(&public_key_path)?;
        hash_and_encrypt_password_with_criteria(
            password,
            &public_key,
            &self.config.password_criteria,
            &self.key_version,
        )
    }

    /// Vérifie un mot de passe chiffré en utilisant la clé privée RSA correspondante.
    ///
    /// Cette fonction déchiffre les données chiffrées avec la clé privée RSA, puis compare le mot de passe fourni
    /// avec celui qui a été chiffré et haché initialement. Elle renvoie `true` si le mot de passe est valide, `false` sinon.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - Les données chiffrées à vérifier (générées par `encrypt_password`).
    /// * `user_input_password` - Le mot de passe que l'utilisateur entre pour vérification.
    ///
    /// # Retour
    ///
    /// Renvoie `true` si le mot de passe est correct, ou une erreur si une vérification échoue.
    ///
    /// # Erreurs
    ///
    /// - `IronCryptError::DecryptionError` : Si le déchiffrement échoue.
    /// - `IronCryptError::InvalidPassword` : Si le mot de passe est incorrect.
    ///
    /// # Exemple
    ///
    /// ```rust
    /// use ironcrypt::IronCrypt;
    /// use ironcrypt::IronCryptConfig;
    ///
    /// // Créer une configuration sécurisée avec des paramètres par défaut
    /// let config = IronCryptConfig::default();
    ///
    /// let crypt = IronCrypt::new("keys", "v1", config)
    ///     .expect("Erreur lors de la création d'IronCrypt");
    ///
    /// let encrypted = crypt.encrypt_password("MyS3cureP@ssw0rd!")
    ///     .expect("Erreur lors du chiffrement du mot de passe");
    ///
    /// let is_valid = crypt.verify_password(&encrypted, "MyS3cureP@ssw0rd!")
    ///     .expect("Erreur lors de la vérification du mot de passe");
    /// if is_valid {
    ///     println!("Le mot de passe est correct !");
    /// } else {
    ///     println!("Le mot de passe est incorrect !");
    /// }
    /// ```
    pub fn verify_password(
        &self,
        encrypted_data: &str,
        user_input_password: &str,
    ) -> Result<bool, IronCryptError> {
        let private_key_path = format!(
            "{}/private_key_{}.pem",
            self.key_directory, self.key_version
        );
        load_private_key(&private_key_path)?;
        decrypt_and_verify_password(encrypted_data, user_input_password, &self.key_directory)
            .map(|_| true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Configuration de base pour les tests.
    fn setup() -> IronCrypt {
        // Créer une configuration sécurisée avec des paramètres par défaut
        let config = IronCryptConfig::default();

        // Chemin temporaire pour les tests
        let key_directory = "test_keys";

        // Assurer que le répertoire de clés existe
        if !Path::new(key_directory).exists() {
            fs::create_dir_all(key_directory).expect("Erreur lors de la création du répertoire de clés pour les tests");
        }

        // Créer une instance d'IronCrypt pour les tests
        let crypt = IronCrypt::new(key_directory, "v1", config)
            .expect("Erreur lors de la création d'IronCrypt pour les tests");

        // Assurer que les clés existent
        crypt.ensure_keys_exist().expect("Erreur lors de la vérification ou de la génération des clés");

        crypt
    }

    /// Test pour vérifier le chiffrement d'un mot de passe
    #[test]
    fn test_encrypt_password() {
        let crypt = setup();  // Initialisation de crypt ici
        let password = "MyS3cureP@ssw0rd!";

        let encrypted_data = crypt.encrypt_password(password)
            .expect("Erreur lors du chiffrement du mot de passe");  // Initialisation de encrypted_data ici

        assert!(!encrypted_data.is_empty(), "Le mot de passe chiffré ne doit pas être vide");
    }

    /// Test pour vérifier la vérification d'un mot de passe chiffré
    #[test]
    fn test_verify_password() {
        let crypt = setup();  // Initialisation de crypt ici
        let password = "MyS3cureP@ssw0rd!";

        // Chiffrer le mot de passe
        let encrypted_data = crypt.encrypt_password(password)
            .expect("Erreur lors du chiffrement du mot de passe");

        // Vérifier le mot de passe
        let is_valid = crypt.verify_password(&encrypted_data, password)
            .expect("Erreur lors de la vérification du mot de passe");

        assert!(is_valid, "Le mot de passe devrait être valide");
    }
}
