use crate::IronCryptError;
use serde::{Deserialize, Serialize};
use unicode_general_category::{get_general_category, GeneralCategory};

/// Structure for configuring password strength criteria.
///
/// This structure allows defining the minimum requirements that a password must meet
/// to be considered sufficiently strong.
///
/// # Fields
///
/// - `min_length`: Minimum length of the password (in characters).
/// - `max_length`: Maximum allowed length (if `None`, no limit).
/// - `disallowed_patterns`: Disallowed patterns.
/// - `special_chars`: Minimum number of special characters.
/// - `uppercase`: Minimum number of uppercase letters.
/// - `lowercase`: Minimum number of lowercase letters.
/// - `digits`: Minimum number of digits.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordCriteria {
    pub min_length: usize,
    pub max_length: Option<usize>,
    pub require_uppercase: bool,
    pub require_numbers: bool,
    pub require_special_chars: bool,
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
            require_uppercase: true,
            require_numbers: true,
            require_special_chars: true,
            disallowed_patterns: vec![],
            special_chars: Some(1),
            uppercase: Some(1),
            lowercase: Some(1),
            digits: Some(1),
        }
    }
}

impl PasswordCriteria {
    /// Checks if a password meets the specified strength criteria.
    ///
    /// Returns `Ok(())` if everything is compliant, otherwise `Err(IronCryptError)`.
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
                // If you want to disallow spaces
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
