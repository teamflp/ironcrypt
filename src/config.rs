// config.rs
use crate::PasswordCriteria;

/// Configuration pour la sécurité d'IronCrypt, incluant la taille des clés et les critères de robustesse des mots de passe.
pub struct IronCryptConfig {
    pub rsa_key_size: u32,         // Taille des clés RSA
    pub argon2_memory_cost: u32,   // Coût mémoire pour Argon2
    pub argon2_time_cost: u32,     // Coût temporel pour Argon2
    pub aes_key_size: usize,       // Taille de la clé AES (128, 192, ou 256 bits)
    pub password_criteria: PasswordCriteria,  // Critères de robustesse du mot de passe
}

impl IronCryptConfig {
    /// Retourne une configuration par défaut sécurisée.
    pub fn default() -> Self {
        Self {
            rsa_key_size: 2048,             // Clé RSA par défaut : 2048 bits
            argon2_memory_cost: 65536,      // 64 MiB pour Argon2
            argon2_time_cost: 3,            // Coût temporel : 3 passes
            aes_key_size: 256,              // Utilisation d'AES-256
            password_criteria: PasswordCriteria::default(),
        }
    }

    /// Permet de définir une taille de clé RSA personnalisée.
    pub fn with_rsa_key_size(mut self, rsa_key_size: u32) -> Self {
        self.rsa_key_size = rsa_key_size;
        self
    }
}
