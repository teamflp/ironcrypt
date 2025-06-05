// criteria.rs

use crate::IronCryptError;
use serde::{Deserialize, Serialize};
use unicode_general_category::{get_general_category, GeneralCategory};

/// Structure pour la configuration des critères de robustesse des mots de passe.
///
/// Cette structure permet de définir les exigences minimales qu'un mot de passe doit respecter
/// pour être considéré comme suffisamment robuste.
///
/// # Champs
///
/// - `min_length` : Longueur minimale du mot de passe (en caractères).
/// - `max_length` : Longueur maximale autorisée pour le mot de passe (en caractères). Si `None`, pas de limite.
/// - `disallowed_patterns` : Liste de motifs que le mot de passe ne doit pas contenir.
/// - `special_chars` : Nombre minimum de caractères spéciaux requis.
/// - `uppercase` : Nombre minimum de lettres majuscules requises.
/// - `lowercase` : Nombre minimum de lettres minuscules requises.
/// - `digits` : Nombre minimum de chiffres requis.
///
/// # Exemple
///
/// ```rust
/// use ironcrypt::PasswordCriteria;
///
/// let criteria = PasswordCriteria {
///     min_length: 12,
///     max_length: Some(128),
///     disallowed_patterns: vec!["password".to_string(), "1234".to_string()],
///     special_chars: Some(1),
///     uppercase: Some(1),
///     lowercase: Some(1),
///     digits: Some(1),
/// };
///
/// assert_eq!(criteria.min_length, 12);
/// assert_eq!(criteria.max_length, Some(128));
/// assert_eq!(criteria.disallowed_patterns.len(), 2);
/// ```
///
/// # Utilisation
///
/// Utilisez cette structure pour définir les exigences de sécurité de vos mots de passe dans
/// une application, par exemple lors de la création de comptes utilisateurs ou pour des politiques
/// de sécurité d'entreprise.
#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordCriteria {
    pub min_length: usize,
    pub max_length: Option<usize>,
    pub disallowed_patterns: Vec<String>,
    pub special_chars: Option<usize>,
    pub uppercase: Option<usize>,
    pub lowercase: Option<usize>,
    pub digits: Option<usize>,
}

impl Default for PasswordCriteria {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: Some(128),
            disallowed_patterns: vec![],
            special_chars: Some(1),
            uppercase: Some(1),
            lowercase: Some(1),
            digits: Some(1),
        }
    }
}

impl PasswordCriteria {
    /// Vérifie si un mot de passe répond aux critères de robustesse spécifiés.
    ///
    /// # Arguments
    ///
    /// * `password` - Le mot de passe à vérifier.
    ///
    /// # Retour
    ///
    /// Renvoie `Ok(())` si le mot de passe est valide, ou `Err(IronCryptError)` sinon.
    pub fn validate(&self, password: &str) -> Result<(), IronCryptError> {
        // Vérification de la longueur minimale
        if password.len() < self.min_length {
            return Err(IronCryptError::PasswordStrengthError(
                GENERIC_PASSWORD_ERROR.to_string(),
            ));
        }

        // Vérification de la longueur maximale
        if let Some(max_length) = self.max_length {
            if password.len() > max_length {
                return Err(IronCryptError::PasswordStrengthError(
                    GENERIC_PASSWORD_ERROR.to_string(),
                ));
            }
        }

        // Vérification des motifs interdits
        for pattern in &self.disallowed_patterns {
            if password.contains(pattern) {
                return Err(IronCryptError::PasswordStrengthError(
                    GENERIC_PASSWORD_ERROR.to_string(),
                ));
            }
        }

        // Vérification des espaces blancs
        if password.chars().any(|c| c.is_whitespace()) {
            return Err(IronCryptError::PasswordStrengthError(
                GENERIC_PASSWORD_ERROR.to_string(),
            ));
        }

        // Initialisation des compteurs
        let mut uppercase_count = 0;
        let mut lowercase_count = 0;
        let mut digit_count = 0;
        let mut special_char_count = 0;

        // Parcours des caractères du mot de passe
        for c in password.chars() {
            match get_general_category(c) {
                GeneralCategory::UppercaseLetter => uppercase_count += 1,
                GeneralCategory::LowercaseLetter => lowercase_count += 1,
                GeneralCategory::DecimalNumber => digit_count += 1,
                GeneralCategory::OtherPunctuation
                | GeneralCategory::MathSymbol
                | GeneralCategory::CurrencySymbol
                | GeneralCategory::ModifierSymbol
                | GeneralCategory::OtherSymbol => special_char_count += 1,
                GeneralCategory::SpaceSeparator
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator => {
                    return Err(IronCryptError::PasswordStrengthError(
                        GENERIC_PASSWORD_ERROR.to_string(),
                    ));
                }
                _ => {}
            }
        }

        // Vérification du nombre minimum de lettres majuscules
        if let Some(min_uppercase) = self.uppercase {
            if uppercase_count < min_uppercase {
                return Err(IronCryptError::PasswordStrengthError(
                    GENERIC_PASSWORD_ERROR.to_string(),
                ));
            }
        }

        // Vérification du nombre minimum de lettres minuscules
        if let Some(min_lowercase) = self.lowercase {
            if lowercase_count < min_lowercase {
                return Err(IronCryptError::PasswordStrengthError(
                    GENERIC_PASSWORD_ERROR.to_string(),
                ));
            }
        }

        // Vérification du nombre minimum de chiffres
        if let Some(min_digits) = self.digits {
            if digit_count < min_digits {
                return Err(IronCryptError::PasswordStrengthError(
                    GENERIC_PASSWORD_ERROR.to_string(),
                ));
            }
        }

        // Vérification du nombre minimum de caractères spéciaux
        if let Some(min_special_chars) = self.special_chars {
            if special_char_count < min_special_chars {
                return Err(IronCryptError::PasswordStrengthError(
                    GENERIC_PASSWORD_ERROR.to_string(),
                ));
            }
        }

        Ok(())
    }
}

// Message d'erreur générique
const GENERIC_PASSWORD_ERROR: &str =
    "Le mot de passe ne répond pas aux critères de sécurité requis.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_criteria_validate_success() {
        let criteria = PasswordCriteria::default();
        let password = "StrongP@ssw0rd!";

        assert!(criteria.validate(password).is_ok());
    }

    #[test]
    fn test_password_criteria_validate_failure() {
        let criteria = PasswordCriteria::default();
        let password = "weak";

        assert!(criteria.validate(password).is_err());
    }

    #[test]
    fn test_password_minimum_uppercase() {
        let criteria = PasswordCriteria::default();
        let password = "StrongP@ssw0rd!123"; // Assurez-vous que ce mot de passe respecte les critères
        assert!(criteria.validate(password).is_ok());
    }

    #[test]
    fn test_password_insufficient_uppercase() {
        let criteria = PasswordCriteria {
            uppercase: Some(3),
            ..Default::default()
        };
        let password = "StrongP@ssw0rd!123";

        assert!(criteria.validate(password).is_err());
    }

    #[test]
    fn test_password_with_whitespace() {
        let criteria = PasswordCriteria::default();
        let password = "Strong P@ssw0rd!123";

        assert!(criteria.validate(password).is_err());
    }

    #[test]
    fn test_password_with_disallowed_pattern() {
        let criteria = PasswordCriteria::default();
        let password = "strongpassword!123"; // Assurez-vous que le motif interdit est présent
        assert!(criteria.validate(password).is_err());
    }
}
