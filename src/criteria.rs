use crate::IronCryptError;
use serde::{Deserialize, Serialize};

/// Structure pour la configuration des critères de robustesse des mots de passe.
///
/// Cette structure permet de définir les exigences minimales qu'un mot de passe doit respecter
/// pour être considéré comme suffisamment robuste.
///
/// # Champs
///
/// - `min_length` : La longueur minimale que le mot de passe doit atteindre (en caractères).
/// - `require_uppercase` : Indique si le mot de passe doit contenir au moins une lettre majuscule.
/// - `require_numbers` : Indique si le mot de passe doit contenir au moins un chiffre.
/// - `require_special_chars` : Indique si le mot de passe doit contenir au moins un caractère spécial non alphanumérique.
/// - `max_length` : Longueur maximale autorisée pour le mot de passe (en caractères). Si `None`, pas de limite de longueur.
/// - `disallowed_patterns` : Une liste de motifs ou de sous-chaînes que le mot de passe ne doit pas contenir (ex. : "password", "1234").
/// - `special_chars` : Nombre minimum de caractères spéciaux requis dans le mot de passe. Si `0`, le critère n'est pas appliqué.
/// - `uppercase` : Nombre minimum de lettres majuscules requises dans le mot de passe. Si `0`, le critère n'est pas appliqué.
/// - `lowercase` : Nombre minimum de lettres minuscules requises dans le mot de passe. Si `0`, le critère n'est pas appliqué.
/// - `digits` : Nombre minimum de chiffres requis dans le mot de passe. Si `0`, le critère n'est pas appliqué.
///
/// # Exemple
///
/// ```rust
/// use ironcrypt::PasswordCriteria;
///
/// let criteria = PasswordCriteria {
///     min_length: 12,
///     require_uppercase: true,
///     require_numbers: true,
///     require_special_chars: true,
///     max_length: Some(128),
///     disallowed_patterns: vec!["password".to_string(), "1234".to_string()],
///     special_chars: 2,
///     uppercase: 1,
///     lowercase: 1,
///     digits: 1,
/// };
///
/// assert_eq!(criteria.min_length, 12);
/// assert!(criteria.require_uppercase);
/// assert!(criteria.require_numbers);
/// assert!(criteria.require_special_chars);
/// assert_eq!(criteria.max_length, Some(128));
/// assert_eq!(criteria.disallowed_patterns.len(), 2);
/// ```
///
/// Dans cet exemple, une configuration personnalisée de `PasswordCriteria` est créée, spécifiant
/// les exigences minimales pour les mots de passe, y compris la longueur minimale, la présence
/// de lettres majuscules, de chiffres et de caractères spéciaux.
///
/// # Utilisation
///
/// Utilisez cette structure pour définir les exigences de sécurité de vos mots de passe dans
/// une application, par exemple lors de la création de comptes utilisateurs ou pour des politiques
/// de sécurité d'entreprise.
#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordCriteria {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_numbers: bool,
    pub require_special_chars: bool,
    pub max_length: Option<usize>,
    pub disallowed_patterns: Vec<String>,
    pub special_chars: i32,
    pub uppercase: i32,
    pub lowercase: i32,
    pub digits: i32,
}


impl PasswordCriteria {
    /// Crée une configuration par défaut pour les critères de robustesse des mots de passe.
    ///
    /// Cette méthode renvoie une instance de `PasswordCriteria` avec des paramètres par défaut qui
    /// garantissent un niveau de sécurité élevé pour les mots de passe.
    ///
    /// # Valeurs par défaut
    ///
    /// - `min_length`: 12 - Le mot de passe doit contenir au moins 12 caractères.
    /// - `max_length`: Some(128) - Le mot de passe ne doit pas dépasser 128 caractères.
    /// - `require_uppercase`: true - Le mot de passe doit contenir au moins une lettre majuscule.
    /// - `require_numbers`: true - Le mot de passe doit contenir au moins un chiffre.
    /// - `require_special_chars`: true - Le mot de passe doit contenir au moins un caractère spécial.
    /// - `disallowed_patterns`: vec![] - Aucun motif interdit par défaut.
    /// - `special_chars`: 0 - Pas de minimum imposé pour les caractères spéciaux (géré par `require_special_chars`).
    /// - `uppercase`: 0 - Pas de minimum imposé pour les lettres majuscules (géré par `require_uppercase`).
    /// - `lowercase`: 0 - Pas de minimum imposé pour les lettres minuscules.
    /// - `digits`: 0 - Pas de minimum imposé pour les chiffres (géré par `require_numbers`).
    ///
    /// # Exemple
    ///
    /// ```rust
    /// use ironcrypt::PasswordCriteria;
    ///
    /// let criteria = PasswordCriteria::default();
    /// assert_eq!(criteria.min_length, 12);
    /// assert!(criteria.require_uppercase);
    /// assert!(criteria.require_numbers);
    /// assert!(criteria.require_special_chars);
    /// assert_eq!(criteria.max_length, Some(128));
    /// assert!(criteria.disallowed_patterns.is_empty());
    /// ```
    ///
    /// Dans cet exemple, une configuration par défaut de `PasswordCriteria` est créée et vérifiée pour
    /// s'assurer que les valeurs par défaut sont bien définies.
    ///
    /// # Utilisation
    ///
    /// Utilisez cette méthode pour obtenir rapidement une configuration de critères de mot de passe robuste.
    /// Vous pouvez ensuite modifier les valeurs si nécessaire pour ajuster les exigences à votre contexte.
    ///
    /// # Retour
    ///
    /// Renvoie une instance de `PasswordCriteria` avec des valeurs par défaut.
    pub fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_numbers: true,
            require_special_chars: true,
            max_length: Some(128),
            disallowed_patterns: vec![],
            special_chars: 0,
            uppercase: 0,
            lowercase: 0,
            digits: 0,
        }
    }
}



/// Vérifie si un mot de passe répond aux critères de robustesse spécifiés.
///
/// # Arguments
///
/// * `password` - Une référence à une chaîne de caractères représentant le mot de passe à vérifier.
/// * `criteria` - Une référence à `PasswordCriteria` définissant les exigences minimales pour le mot de passe.
///
/// # Critères de Vérification
///
/// La fonction vérifie les éléments suivants en fonction des critères définis :
///
/// - Longueur minimale : Le mot de passe doit contenir au moins `min_length` caractères.
/// - Longueur maximale (si spécifiée) : Le mot de passe ne doit pas dépasser `max_length` caractères.
/// - Présence de lettres majuscules : Si `require_uppercase` est vrai, le mot de passe doit contenir au moins une lettre majuscule.
/// - Présence de chiffres : Si `require_numbers` est vrai, le mot de passe doit contenir au moins un chiffre.
/// - Présence de caractères spéciaux : Si `require_special_chars` est vrai, le mot de passe doit contenir au moins un caractère spécial non alphanumérique.
/// - Absence de motifs interdits : Si `disallowed_patterns` contient des motifs, le mot de passe ne doit pas contenir ces chaînes de caractères.
///
/// # Retour
///
/// Renvoie `Ok(())` si le mot de passe répond à tous les critères.
/// Renvoie une `Err` contenant un message d'erreur si le mot de passe ne respecte pas un des critères.
///
/// # Exemple
///
/// ```rust
/// use ironcrypt::{is_password_strong, PasswordCriteria};
///
/// let criteria = PasswordCriteria {
///     min_length: 8,
///     max_length: Some(20),
///     require_uppercase: true,
///     require_numbers: true,
///     require_special_chars: true,
///     disallowed_patterns: vec!["password".to_string(), "1234".to_string()],
///     digits: 0,
///     lowercase: 0,
///     special_chars: 0,
///     uppercase: 0,
/// };
///
/// let password = "StrongP@ssw0rd";
/// match is_password_strong(password, &criteria) {
///     Ok(_) => println!("Le mot de passe est suffisamment robuste."),
///     Err(e) => println!("Erreur : {}", e),
/// }
/// ```
///
/// Dans cet exemple, le mot de passe "StrongP@ssw0rd" respecte les critères spécifiés et la fonction retourne `Ok(())`.
///
/// # Erreurs
///
/// La fonction renvoei une `Err` de type `IronCryptError::PasswordStrengthError` avec un message d'erreur détaillé. si :
///
/// - La longueur du mot de passe est inférieure à `min_length`.
/// - La longueur du mot de passe est supérieure à `max_length` (si spécifié).
/// - `require_uppercase` est `true` mais le mot de passe ne contient pas de lettre majuscule.
/// - `require_numbers` est `true` mais le mot de passe ne contient pas de chiffre.
/// - `require_special_chars` est `true` mais le mot de passe ne contient pas de caractère spécial.
/// - Le mot de passe contient un motif interdit de `disallowed_patterns`.

pub fn is_password_strong(password: &str, criteria: &PasswordCriteria) -> Result<(), IronCryptError> {
    if password.len() < criteria.min_length {
        return Err(IronCryptError::PasswordStrengthError(format!(
            "Le mot de passe doit contenir au moins {} caractères.",
            criteria.min_length
        )));
    }

    if let Some(max_length) = criteria.max_length {
        if password.len() > max_length {
            return Err(IronCryptError::PasswordStrengthError(format!(
                "Le mot de passe ne doit pas dépasser {} caractères.",
                max_length
            )));
        }
    }

    if criteria.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err(IronCryptError::PasswordStrengthError(
            "Le mot de passe doit contenir au moins une lettre majuscule.".to_string(),
        ));
    }

    if criteria.require_numbers && !password.chars().any(|c| c.is_digit(10)) {
        return Err(IronCryptError::PasswordStrengthError(
            "Le mot de passe doit contenir au moins un chiffre.".to_string(),
        ));
    }

    if criteria.require_special_chars && !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(IronCryptError::PasswordStrengthError(
            "Le mot de passe doit contenir au moins un caractère spécial.".to_string(),
        ));
    }

    for pattern in &criteria.disallowed_patterns {
        if password.contains(pattern) {
            return Err(IronCryptError::PasswordStrengthError(format!(
                "Le mot de passe ne doit pas contenir le motif interdit : '{}'.",
                pattern
            )));
        }
    }

    Ok(())
}