use crate::IronCryptError;
use serde::{Deserialize, Serialize};
use unicode_general_category::{get_general_category, GeneralCategory};

/// Defines the criteria for validating password strength.
///
/// This struct is used to configure the minimum requirements a password must meet.
///
/// # Examples
///
/// ```
/// use ironcrypt::criteria::PasswordCriteria;
///
/// let criteria = PasswordCriteria {
///     min_length: 16,
///     max_length: Some(128),
///     uppercase: Some(2),
///     lowercase: Some(2),
///     digits: Some(2),
///     special_chars: Some(2),
///     disallowed_patterns: vec!["123".to_string()],
/// };
///
/// assert!(criteria.validate("StrongPassword123!@#").is_ok());
/// assert!(criteria.validate("weak").is_err());
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordCriteria {
    /// The minimum required length of the password.
    pub min_length: usize,
    /// The maximum allowed length of the password. If `None`, there is no upper limit.
    pub max_length: Option<usize>,
    /// A list of patterns that are not allowed to appear in the password (e.g., "password", "12345").
    pub disallowed_patterns: Vec<String>,
    /// The minimum number of special characters required. If `None`, no check is performed.
    /// Special characters include punctuation, symbols, etc.
    pub special_chars: Option<usize>,
    /// The minimum number of uppercase letters required. If `None`, no check is performed.
    pub uppercase: Option<usize>,
    /// The minimum number of lowercase letters required. If `None`, no check is performed.
    pub lowercase: Option<usize>,
    /// The minimum number of numeric digits required. If `None`, no check is performed.
    pub digits: Option<usize>,
}

impl Default for PasswordCriteria {
    /// Creates a new `PasswordCriteria` with strong default values.
    ///
    /// - **Min Length:** 12
    /// - **Max Length:** 128
    /// - **Required Characters:** At least 1 uppercase, 1 lowercase, 1 digit, and 1 special character.
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
    /// Validates a password against the defined criteria.
    ///
    /// Returns `Ok(())` if the password is valid, otherwise returns a `PasswordStrengthError`.
    pub fn validate(&self, password: &str) -> Result<(), IronCryptError> {
        // Minimum length
        if password.len() < self.min_length {
            return Err(IronCryptError::PasswordStrengthError(
                "Password is too short".to_string(),
            ));
        }

        // Maximum length
        if let Some(max_length) = self.max_length {
            if password.len() > max_length {
                return Err(IronCryptError::PasswordStrengthError(
                    "Password is too long".to_string(),
                ));
            }
        }

        // Disallowed patterns
        for pattern in &self.disallowed_patterns {
            if password.contains(pattern) {
                return Err(IronCryptError::PasswordStrengthError(
                    "Password contains a disallowed pattern".to_string(),
                ));
            }
        }

        // Counters
        let mut uppercase_count = 0;
        let mut lowercase_count = 0;
        let mut digit_count = 0;
        let mut special_char_count = 0;

        for c in password.chars() {
            match get_general_category(c) {
                GeneralCategory::UppercaseLetter => uppercase_count += 1,
                GeneralCategory::LowercaseLetter => lowercase_count += 1,
                GeneralCategory::DecimalNumber => digit_count += 1,
                GeneralCategory::OtherSymbol
                | GeneralCategory::OtherPunctuation
                | GeneralCategory::MathSymbol
                | GeneralCategory::CurrencySymbol
                | GeneralCategory::ModifierSymbol => special_char_count += 1,
                // Disallow spaces
                GeneralCategory::SpaceSeparator
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator => {
                    return Err(IronCryptError::PasswordStrengthError(
                        "Spaces are not allowed".to_string(),
                    ))
                }
                _ => {}
            }
        }

        if let Some(min_u) = self.uppercase {
            if uppercase_count < min_u {
                return Err(IronCryptError::PasswordStrengthError(
                    "Not enough uppercase letters".to_string(),
                ));
            }
        }

        if let Some(min_l) = self.lowercase {
            if lowercase_count < min_l {
                return Err(IronCryptError::PasswordStrengthError(
                    "Not enough lowercase letters".to_string(),
                ));
            }
        }

        if let Some(min_d) = self.digits {
            if digit_count < min_d {
                return Err(IronCryptError::PasswordStrengthError(
                    "Not enough digits".to_string(),
                ));
            }
        }

        if let Some(min_s) = self.special_chars {
            if special_char_count < min_s {
                return Err(IronCryptError::PasswordStrengthError(
                    "Not enough special characters".to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_criteria_valid() {
        let criteria = PasswordCriteria::default();
        assert!(criteria.validate("ValidPassword123!").is_ok());
    }

    #[test]
    fn test_password_too_short() {
        let criteria = PasswordCriteria::default();
        let err = criteria.validate("Short1!").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Password strength error: Password is too short"
        );
    }

    #[test]
    fn test_password_no_uppercase() {
        let criteria = PasswordCriteria::default();
        let err = criteria.validate("nouppercase123!").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Password strength error: Not enough uppercase letters"
        );
    }

    #[test]
    fn test_password_no_lowercase() {
        let criteria = PasswordCriteria::default();
        let err = criteria.validate("NOLOWERCASE123!").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Password strength error: Not enough lowercase letters"
        );
    }

    #[test]
    fn test_password_no_digit() {
        let criteria = PasswordCriteria::default();
        let err = criteria.validate("NoDigitPassword!").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Password strength error: Not enough digits"
        );
    }

    #[test]
    fn test_password_no_special_char() {
        let criteria = PasswordCriteria::default();
        let err = criteria.validate("NoSpecialChar123").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Password strength error: Not enough special characters"
        );
    }
}
