//! Username validation.
//!
//! Validates usernames according to these rules:
//! - Length: 3-64 characters
//! - Must start with a letter (a-z, A-Z)
//! - Can contain: letters, numbers, underscores, hyphens
//! - ASCII only (for LDAP/AD compatibility)

use super::error::ValidationError;
use serde_json::json;
use std::sync::LazyLock;

/// Username validation regex.
///
/// - Must start with a letter
/// - Followed by 2-63 alphanumeric, underscore, or hyphen characters
/// - Total length: 3-64 characters
static USERNAME_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[a-zA-Z][a-zA-Z0-9_-]{2,63}$")
        .expect("USERNAME_REGEX is a valid regex pattern")
});

/// Minimum username length.
const MIN_USERNAME_LENGTH: usize = 3;

/// Maximum username length.
const MAX_USERNAME_LENGTH: usize = 64;

/// Validate a username.
///
/// # Arguments
///
/// * `username` - The username to validate
///
/// # Returns
///
/// * `Ok(())` if the username is valid
/// * `Err(ValidationError)` if the username is invalid
///
/// # Examples
///
/// ```
/// use xavyo_api_users::validation::validate_username;
///
/// // Valid usernames
/// assert!(validate_username("john_doe").is_ok());
/// assert!(validate_username("user123").is_ok());
/// assert!(validate_username("alice-smith").is_ok());
///
/// // Invalid usernames
/// assert!(validate_username("ab").is_err()); // too short
/// assert!(validate_username("123user").is_err()); // starts with number
/// assert!(validate_username("user@name").is_err()); // invalid character
/// ```
pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    let username = username.trim();

    // Check for empty username
    if username.is_empty() {
        return Err(ValidationError::new(
            "username",
            "required",
            "Username is required",
        ));
    }

    // Check minimum length
    if username.len() < MIN_USERNAME_LENGTH {
        return Err(ValidationError::with_constraints(
            "username",
            "too_short",
            format!(
                "Username must be at least {} characters",
                MIN_USERNAME_LENGTH
            ),
            json!({"min_length": MIN_USERNAME_LENGTH, "actual": username.len()}),
        ));
    }

    // Check maximum length
    if username.len() > MAX_USERNAME_LENGTH {
        return Err(ValidationError::with_constraints(
            "username",
            "too_long",
            format!(
                "Username must not exceed {} characters",
                MAX_USERNAME_LENGTH
            ),
            json!({"max_length": MAX_USERNAME_LENGTH, "actual": username.len()}),
        ));
    }

    // Check if starts with letter
    let first_char = username.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() {
        return Err(ValidationError::new(
            "username",
            "invalid_start",
            "Username must start with a letter",
        ));
    }

    // Check for non-ASCII characters
    if !username.is_ascii() {
        return Err(ValidationError::new(
            "username",
            "non_ascii",
            "Username must contain only ASCII characters (letters, numbers, underscores, hyphens)",
        ));
    }

    // Validate against pattern
    if !USERNAME_REGEX.is_match(username) {
        return Err(ValidationError::new(
            "username",
            "invalid_format",
            "Username can only contain letters, numbers, underscores, and hyphens",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_username_simple() {
        assert!(validate_username("john").is_ok());
    }

    #[test]
    fn test_valid_username_with_underscore() {
        assert!(validate_username("john_doe").is_ok());
    }

    #[test]
    fn test_valid_username_with_hyphen() {
        assert!(validate_username("john-doe").is_ok());
    }

    #[test]
    fn test_valid_username_with_numbers() {
        assert!(validate_username("user123").is_ok());
    }

    #[test]
    fn test_valid_username_mixed() {
        assert!(validate_username("Alice_Smith-99").is_ok());
    }

    #[test]
    fn test_valid_username_min_length() {
        assert!(validate_username("abc").is_ok());
    }

    #[test]
    fn test_valid_username_max_length() {
        let username = format!("a{}", "b".repeat(63));
        assert!(validate_username(&username).is_ok());
    }

    #[test]
    fn test_invalid_username_empty() {
        let result = validate_username("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "required");
    }

    #[test]
    fn test_invalid_username_too_short() {
        let result = validate_username("ab");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "too_short");
        assert!(err.constraints.is_some());
    }

    #[test]
    fn test_invalid_username_too_long() {
        let username = format!("a{}", "b".repeat(64));
        let result = validate_username(&username);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "too_long");
    }

    #[test]
    fn test_invalid_username_starts_with_number() {
        let result = validate_username("123user");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "invalid_start");
    }

    #[test]
    fn test_invalid_username_starts_with_underscore() {
        let result = validate_username("_user");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "invalid_start");
    }

    #[test]
    fn test_invalid_username_starts_with_hyphen() {
        let result = validate_username("-user");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "invalid_start");
    }

    #[test]
    fn test_invalid_username_with_space() {
        let result = validate_username("john doe");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "invalid_format");
    }

    #[test]
    fn test_invalid_username_with_at_symbol() {
        let result = validate_username("user@name");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_username_with_special_chars() {
        let result = validate_username("user#name!");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_username_unicode() {
        let result = validate_username("José");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "non_ascii");
    }

    #[test]
    fn test_username_trimmed() {
        // Leading/trailing whitespace should be trimmed
        assert!(validate_username("  john  ").is_ok());
    }
}
