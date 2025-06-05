// config.rs
use crate::PasswordCriteria;

/// Configuration pour la sécurité d'IronCrypt, incluant la taille des clés et les critères de robustesse des mots de passe.
pub struct IronCryptConfig {
    pub rsa_key_size: u32,                   // Taille des clés RSA
    pub argon2_memory_cost: u32,             // Coût mémoire pour Argon2
    pub argon2_time_cost: u32,               // Coût temporel pour Argon2
    pub argon2_parallelism: u32,             // Nombre de threads pour Argon2
    pub aes_key_size: usize,                 // Taille de la clé AES (128, 192, ou 256 bits)
    pub password_criteria: PasswordCriteria, // Critères de robustesse du mot de passe
}

impl Default for IronCryptConfig {
    /// Retourne une configuration par défaut sécurisée.
    fn default() -> Self {
        Self {
            rsa_key_size: 2048,
            argon2_memory_cost: 65536,
            argon2_time_cost: 3,
            argon2_parallelism: 1,
            aes_key_size: 256,
            password_criteria: PasswordCriteria::default(),
        }
    }
}

impl IronCryptConfig {
    /// Permet de définir une taille de clé RSA personnalisée.
    pub fn with_rsa_key_size(mut self, rsa_key_size: u32) -> Self {
        self.rsa_key_size = rsa_key_size;
        self
    }

    // Vous pouvez ajouter des méthodes similaires pour les autres paramètres
    /// Permet de définir un coût mémoire personnalisé pour Argon2.
    pub fn with_argon2_memory_cost(mut self, memory_cost: u32) -> Self {
        self.argon2_memory_cost = memory_cost;
        self
    }

    /// Permet de définir un coût temporel personnalisé pour Argon2.
    pub fn with_argon2_time_cost(mut self, time_cost: u32) -> Self {
        self.argon2_time_cost = time_cost;
        self
    }

    /// Permet de définir une taille de clé AES personnalisée.
    pub fn with_aes_key_size(mut self, aes_key_size: usize) -> Self {
        self.aes_key_size = aes_key_size;
        self
    }

    /// Permet de définir des critères de mot de passe personnalisés.
    pub fn with_password_criteria(mut self, criteria: PasswordCriteria) -> Self {
        self.password_criteria = criteria;
        self
    }
}
