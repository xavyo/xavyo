//! Email validation following RFC 5322.
//!
//! Validates email addresses using a comprehensive regex pattern that handles:
//! - Standard email addresses (user@example.com)
//! - Plus addressing (user+tag@example.com)
//! - International domain names after Punycode conversion
//! - Subdomains (user@mail.example.com)

use super::error::ValidationError;
use serde_json::json;
use std::sync::LazyLock;

/// RFC 5322 compliant email regex pattern.
///
/// This pattern validates:
/// - Local part: alphanumeric, dots, underscores, plus signs, hyphens
/// - Domain: alphanumeric with hyphens, proper TLD structure
/// - No consecutive dots, no leading/trailing dots
static EMAIL_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
    ).expect("EMAIL_REGEX is a valid regex pattern")
});

/// Maximum allowed email length (per RFC 5321).
const MAX_EMAIL_LENGTH: usize = 254;

/// Minimum reasonable email length (a@b.c).
const MIN_EMAIL_LENGTH: usize = 5;

/// Validate an email address.
///
/// # Arguments
///
/// * `email` - The email address to validate
///
/// # Returns
///
/// * `Ok(())` if the email is valid
/// * `Err(ValidationError)` if the email is invalid
///
/// # Examples
///
/// ```
/// use xavyo_api_users::validation::validate_email;
///
/// // Valid emails
/// assert!(validate_email("user@example.com").is_ok());
/// assert!(validate_email("user+tag@example.com").is_ok());
/// assert!(validate_email("user.name@subdomain.example.com").is_ok());
///
/// // Invalid emails
/// assert!(validate_email("invalid-email").is_err());
/// assert!(validate_email("@example.com").is_err());
/// assert!(validate_email("user@").is_err());
/// ```
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    let email = email.trim();

    // Check for empty email
    if email.is_empty() {
        return Err(ValidationError::new(
            "email",
            "required",
            "Email is required",
        ));
    }

    // Check minimum length
    if email.len() < MIN_EMAIL_LENGTH {
        return Err(ValidationError::with_constraints(
            "email",
            "too_short",
            format!("Email must be at least {MIN_EMAIL_LENGTH} characters"),
            json!({"min_length": MIN_EMAIL_LENGTH, "actual": email.len()}),
        ));
    }

    // Check maximum length (RFC 5321)
    if email.len() > MAX_EMAIL_LENGTH {
        return Err(ValidationError::with_constraints(
            "email",
            "too_long",
            format!("Email must not exceed {MAX_EMAIL_LENGTH} characters"),
            json!({"max_length": MAX_EMAIL_LENGTH, "actual": email.len()}),
        ));
    }

    // Check for @ symbol
    if !email.contains('@') {
        return Err(ValidationError::new(
            "email",
            "invalid_format",
            "Email must contain an @ symbol",
        ));
    }

    // Validate against RFC 5322 pattern
    if !EMAIL_REGEX.is_match(email) {
        return Err(ValidationError::new(
            "email",
            "invalid_format",
            "Invalid email format",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_standard_email() {
        assert!(validate_email("user@example.com").is_ok());
    }

    #[test]
    fn test_valid_email_with_plus_addressing() {
        assert!(validate_email("user+tag@example.com").is_ok());
    }

    #[test]
    fn test_valid_email_with_subdomain() {
        assert!(validate_email("user@mail.example.com").is_ok());
    }

    #[test]
    fn test_valid_email_with_dots_in_local_part() {
        assert!(validate_email("user.name@example.com").is_ok());
    }

    #[test]
    fn test_valid_email_with_numbers() {
        assert!(validate_email("user123@example123.com").is_ok());
    }

    #[test]
    fn test_valid_email_with_hyphen_in_domain() {
        assert!(validate_email("user@my-example.com").is_ok());
    }

    #[test]
    fn test_invalid_email_empty() {
        let result = validate_email("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "required");
    }

    #[test]
    fn test_invalid_email_whitespace_only() {
        let result = validate_email("   ");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "required");
    }

    #[test]
    fn test_invalid_email_no_at_symbol() {
        let result = validate_email("invalid-email");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "invalid_format");
    }

    #[test]
    fn test_invalid_email_no_domain() {
        let result = validate_email("user@");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_email_no_local_part() {
        let result = validate_email("@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_email_double_at() {
        let result = validate_email("user@@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_email_no_tld() {
        let result = validate_email("user@example");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_email_too_short() {
        let result = validate_email("a@b");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "too_short");
    }

    #[test]
    fn test_invalid_email_too_long() {
        let long_local = "a".repeat(250);
        let email = format!("{}@example.com", long_local);
        let result = validate_email(&email);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "too_long");
    }

    #[test]
    fn test_email_trimmed() {
        // Leading/trailing whitespace should be trimmed
        assert!(validate_email("  user@example.com  ").is_ok());
    }

    #[test]
    fn test_valid_email_case_insensitive() {
        assert!(validate_email("User@Example.COM").is_ok());
    }
}
