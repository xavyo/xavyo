//! Validation utilities for authentication.
//!
//! Provides email and password validation according to the spec requirements.

use regex::Regex;
use std::sync::LazyLock;

/// Minimum password length requirement.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Maximum password length requirement.
pub const MAX_PASSWORD_LENGTH: usize = 128;

/// Maximum email length requirement.
pub const MAX_EMAIL_LENGTH: usize = 255;

/// Special characters allowed in passwords.
pub const SPECIAL_CHARS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

/// Email validation regex (simplified RFC 5322).
/// Uses `LazyLock` for compile-once initialization. The regex pattern is a constant,
/// so the `expect()` here is acceptable - if this fails, it's a programming error.
static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        .expect("EMAIL_REGEX is a valid regex pattern")
});

/// Result of password validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordValidationResult {
    /// Whether the password is valid.
    pub is_valid: bool,
    /// List of validation errors (empty if valid).
    pub errors: Vec<PasswordValidationError>,
}

/// Specific password validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordValidationError {
    /// Password is too short.
    TooShort { min: usize, actual: usize },
    /// Password is too long.
    TooLong { max: usize, actual: usize },
    /// Missing uppercase letter.
    MissingUppercase,
    /// Missing lowercase letter.
    MissingLowercase,
    /// Missing digit.
    MissingDigit,
    /// Missing special character.
    MissingSpecialChar,
}

impl std::fmt::Display for PasswordValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { min, actual } => {
                write!(f, "Password too short: {actual} characters (minimum {min})")
            }
            Self::TooLong { max, actual } => {
                write!(f, "Password too long: {actual} characters (maximum {max})")
            }
            Self::MissingUppercase => {
                write!(f, "Password must contain at least one uppercase letter")
            }
            Self::MissingLowercase => {
                write!(f, "Password must contain at least one lowercase letter")
            }
            Self::MissingDigit => write!(f, "Password must contain at least one digit"),
            Self::MissingSpecialChar => {
                write!(
                    f,
                    "Password must contain at least one special character ({SPECIAL_CHARS})"
                )
            }
        }
    }
}

/// Validate a password against the security requirements.
///
/// Requirements (FR-003):
/// - Minimum 8 characters
/// - Maximum 128 characters
/// - At least 1 uppercase letter (A-Z)
/// - At least 1 lowercase letter (a-z)
/// - At least 1 digit (0-9)
/// - At least 1 special character from: `!@#$%^&*()_+-=[]{}|;:,.<>?`
///
/// # Arguments
///
/// * `password` - The password to validate
///
/// # Returns
///
/// A `PasswordValidationResult` containing validation status and any errors.
#[must_use]
pub fn validate_password(password: &str) -> PasswordValidationResult {
    let mut errors = Vec::new();
    let len = password.chars().count();

    // Length checks
    if len < MIN_PASSWORD_LENGTH {
        errors.push(PasswordValidationError::TooShort {
            min: MIN_PASSWORD_LENGTH,
            actual: len,
        });
    }

    if len > MAX_PASSWORD_LENGTH {
        errors.push(PasswordValidationError::TooLong {
            max: MAX_PASSWORD_LENGTH,
            actual: len,
        });
    }

    // Character class checks
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| SPECIAL_CHARS.contains(c));

    if !has_uppercase {
        errors.push(PasswordValidationError::MissingUppercase);
    }

    if !has_lowercase {
        errors.push(PasswordValidationError::MissingLowercase);
    }

    if !has_digit {
        errors.push(PasswordValidationError::MissingDigit);
    }

    if !has_special {
        errors.push(PasswordValidationError::MissingSpecialChar);
    }

    PasswordValidationResult {
        is_valid: errors.is_empty(),
        errors,
    }
}

/// Result of email validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailValidationResult {
    /// Whether the email is valid.
    pub is_valid: bool,
    /// Validation error (if any).
    pub error: Option<EmailValidationError>,
}

/// Specific email validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailValidationError {
    /// Email is empty.
    Empty,
    /// Email is too long.
    TooLong { max: usize, actual: usize },
    /// Email format is invalid.
    InvalidFormat,
}

impl std::fmt::Display for EmailValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Email address is required"),
            Self::TooLong { max, actual } => {
                write!(f, "Email too long: {actual} characters (maximum {max})")
            }
            Self::InvalidFormat => write!(f, "Invalid email format"),
        }
    }
}

/// Validate an email address.
///
/// Requirements (FR-002):
/// - Must match RFC 5322 email format
/// - Maximum 255 characters
/// - Cannot be empty
///
/// # Arguments
///
/// * `email` - The email address to validate
///
/// # Returns
///
/// An `EmailValidationResult` containing validation status and any error.
#[must_use]
pub fn validate_email(email: &str) -> EmailValidationResult {
    // Empty check
    if email.is_empty() {
        return EmailValidationResult {
            is_valid: false,
            error: Some(EmailValidationError::Empty),
        };
    }

    // Length check
    let len = email.len();
    if len > MAX_EMAIL_LENGTH {
        return EmailValidationResult {
            is_valid: false,
            error: Some(EmailValidationError::TooLong {
                max: MAX_EMAIL_LENGTH,
                actual: len,
            }),
        };
    }

    // Format check
    if !EMAIL_REGEX.is_match(email) {
        return EmailValidationResult {
            is_valid: false,
            error: Some(EmailValidationError::InvalidFormat),
        };
    }

    EmailValidationResult {
        is_valid: true,
        error: None,
    }
}

/// Normalize an email address (lowercase).
///
/// Per FR-002, emails should be stored in lowercase for case-insensitive comparison.
#[must_use]
pub fn normalize_email(email: &str) -> String {
    email.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    mod password_validation {
        use super::*;

        #[test]
        fn valid_password() {
            let result = validate_password("SecureP@ss1");
            assert!(result.is_valid);
            assert!(result.errors.is_empty());
        }

        #[test]
        fn too_short() {
            let result = validate_password("Aa1!");
            assert!(!result.is_valid);
            assert!(result.errors.contains(&PasswordValidationError::TooShort {
                min: MIN_PASSWORD_LENGTH,
                actual: 4,
            }));
        }

        #[test]
        fn too_long() {
            let long_pass = format!("Aa1!{}", "x".repeat(130));
            let result = validate_password(&long_pass);
            assert!(!result.is_valid);
            assert!(matches!(
                result.errors.first(),
                Some(PasswordValidationError::TooLong { .. })
            ));
        }

        #[test]
        fn missing_uppercase() {
            let result = validate_password("securep@ss1");
            assert!(!result.is_valid);
            assert!(result
                .errors
                .contains(&PasswordValidationError::MissingUppercase));
        }

        #[test]
        fn missing_lowercase() {
            let result = validate_password("SECUREP@SS1");
            assert!(!result.is_valid);
            assert!(result
                .errors
                .contains(&PasswordValidationError::MissingLowercase));
        }

        #[test]
        fn missing_digit() {
            let result = validate_password("SecureP@ss");
            assert!(!result.is_valid);
            assert!(result
                .errors
                .contains(&PasswordValidationError::MissingDigit));
        }

        #[test]
        fn missing_special() {
            let result = validate_password("SecurePass1");
            assert!(!result.is_valid);
            assert!(result
                .errors
                .contains(&PasswordValidationError::MissingSpecialChar));
        }

        #[test]
        fn multiple_errors() {
            let result = validate_password("abc");
            assert!(!result.is_valid);
            assert!(result.errors.len() >= 4); // Too short + missing classes
        }

        #[test]
        fn all_special_chars_accepted() {
            for ch in SPECIAL_CHARS.chars() {
                let password = format!("SecurePass1{ch}");
                let result = validate_password(&password);
                assert!(result.is_valid, "Special char '{ch}' should be accepted");
            }
        }
    }

    mod email_validation {
        use super::*;

        #[test]
        fn valid_email() {
            let result = validate_email("test@example.com");
            assert!(result.is_valid);
            assert!(result.error.is_none());
        }

        #[test]
        fn valid_email_with_subdomain() {
            let result = validate_email("user@mail.example.com");
            assert!(result.is_valid);
        }

        #[test]
        fn valid_email_with_plus() {
            let result = validate_email("user+tag@example.com");
            assert!(result.is_valid);
        }

        #[test]
        fn empty_email() {
            let result = validate_email("");
            assert!(!result.is_valid);
            assert_eq!(result.error, Some(EmailValidationError::Empty));
        }

        #[test]
        fn too_long_email() {
            let long_email = format!("{}@example.com", "a".repeat(300));
            let result = validate_email(&long_email);
            assert!(!result.is_valid);
            assert!(matches!(
                result.error,
                Some(EmailValidationError::TooLong { .. })
            ));
        }

        #[test]
        fn invalid_format_no_at() {
            let result = validate_email("notanemail");
            assert!(!result.is_valid);
            assert_eq!(result.error, Some(EmailValidationError::InvalidFormat));
        }

        #[test]
        fn invalid_format_no_domain() {
            let result = validate_email("user@");
            assert!(!result.is_valid);
            assert_eq!(result.error, Some(EmailValidationError::InvalidFormat));
        }

        #[test]
        fn invalid_format_no_local() {
            let result = validate_email("@example.com");
            assert!(!result.is_valid);
            assert_eq!(result.error, Some(EmailValidationError::InvalidFormat));
        }
    }

    mod normalize_email {
        use super::*;

        #[test]
        fn lowercase_conversion() {
            assert_eq!(normalize_email("TEST@EXAMPLE.COM"), "test@example.com");
        }

        #[test]
        fn mixed_case() {
            assert_eq!(normalize_email("TeSt@ExAmPlE.cOm"), "test@example.com");
        }

        #[test]
        fn already_lowercase() {
            assert_eq!(normalize_email("test@example.com"), "test@example.com");
        }
    }
}
