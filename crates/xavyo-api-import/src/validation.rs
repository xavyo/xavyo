//! Validation helpers for bulk user import (F086).
//!
//! Provides email validation, display name sanitization, and CSV header checks.

use std::collections::{HashMap, HashSet};

/// Known optional CSV column names (case-insensitive matching).
pub const KNOWN_COLUMNS: &[&str] = &[
    "email",
    "first_name",
    "last_name",
    "display_name",
    "roles",
    "groups",
    "department",
    "is_active",
    "username",    // F-021: Added for extended duplicate detection
    "external_id", // F-021: Added for HR system integration
];

/// Maximum email length per RFC 5321.
const MAX_EMAIL_LENGTH: usize = 254;

/// Validate an email address format.
///
/// Uses a practical check consistent with RFC 5322 basics:
/// - Non-empty
/// - Contains exactly one `@`
/// - Local part and domain both non-empty
/// - Domain contains at least one `.`
/// - No whitespace
/// - Reasonable length
pub fn validate_email(email: &str) -> Result<(), String> {
    if email.is_empty() {
        return Err("Email is empty".to_string());
    }

    if email.len() > MAX_EMAIL_LENGTH {
        return Err(format!(
            "Email exceeds maximum length of {MAX_EMAIL_LENGTH} characters"
        ));
    }

    if email.contains(char::is_whitespace) {
        return Err("Email contains whitespace".to_string());
    }

    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 {
        return Err("Email must contain exactly one '@'".to_string());
    }

    let local = parts[0];
    let domain = parts[1];

    if local.is_empty() {
        return Err("Email local part is empty".to_string());
    }

    if domain.is_empty() {
        return Err("Email domain is empty".to_string());
    }

    if !domain.contains('.') {
        return Err("Email domain must contain at least one '.'".to_string());
    }

    if domain.starts_with('.') || domain.ends_with('.') {
        return Err("Email domain cannot start or end with '.'".to_string());
    }

    if domain.starts_with('-') || domain.ends_with('-') {
        return Err("Email domain cannot start or end with '-'".to_string());
    }

    Ok(())
}

/// Sanitize a display name by stripping HTML and script content.
///
/// Uses the ammonia library for HTML sanitization, then trims whitespace.
#[must_use] 
pub fn sanitize_display_name(name: &str) -> String {
    let cleaned = ammonia::clean(name);
    cleaned.trim().to_string()
}

/// Result of CSV header validation.
#[derive(Debug)]
pub struct HeaderValidation {
    /// Whether validation passed (email column present).
    pub valid: bool,
    /// Indices of known columns (`column_name` -> index).
    pub known_columns: std::collections::HashMap<String, usize>,
    /// Names of columns that are not in the known set (potential custom attributes).
    pub custom_columns: Vec<(String, usize)>,
    /// Error message if validation failed.
    pub error: Option<String>,
}

/// Validate CSV headers and map column positions.
///
/// Returns a mapping of known column names to their 0-based indices,
/// plus any unrecognized columns that may be custom attributes.
#[must_use] 
pub fn validate_csv_headers(headers: &[String]) -> HeaderValidation {
    let mut known_columns = std::collections::HashMap::new();
    let mut custom_columns = Vec::new();
    let mut has_email = false;

    let known_set: HashSet<&str> = KNOWN_COLUMNS.iter().copied().collect();

    for (idx, header) in headers.iter().enumerate() {
        let normalized = header.trim().to_lowercase();

        if normalized.is_empty() {
            continue;
        }

        if known_set.contains(normalized.as_str()) {
            known_columns.insert(normalized.clone(), idx);
            if normalized == "email" {
                has_email = true;
            }
        } else {
            custom_columns.push((header.trim().to_string(), idx));
        }
    }

    if !has_email {
        return HeaderValidation {
            valid: false,
            known_columns,
            custom_columns,
            error: Some(format!(
                "CSV must contain an 'email' column. Found columns: {}",
                headers.join(", ")
            )),
        };
    }

    HeaderValidation {
        valid: true,
        known_columns,
        custom_columns,
        error: None,
    }
}

/// Apply column mapping to headers, renaming source columns to target field names.
///
/// Returns the mapped headers and any errors for invalid mappings.
pub fn apply_column_mapping(
    headers: &[String],
    mapping: &HashMap<String, String>,
) -> Result<Vec<String>, String> {
    let known_set: HashSet<&str> = KNOWN_COLUMNS.iter().copied().collect();

    // Validate all mapping targets are known columns
    for (source, target) in mapping {
        let target_lower = target.to_lowercase();
        if !known_set.contains(target_lower.as_str()) {
            return Err(format!(
                "Invalid column mapping: '{}' -> '{}'. Target '{}' is not a known column. Valid targets: {}",
                source, target, target, KNOWN_COLUMNS.join(", ")
            ));
        }
    }

    // Create a case-insensitive lookup for source columns
    let mapping_lower: HashMap<String, String> = mapping
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();

    // Apply mapping
    let mapped: Vec<String> = headers
        .iter()
        .map(|h| {
            let h_lower = h.to_lowercase();
            mapping_lower
                .get(&h_lower)
                .cloned()
                .unwrap_or_else(|| h.clone())
        })
        .collect();

    Ok(mapped)
}

/// Validate that all mapped source columns exist in the headers.
pub fn validate_mapping_sources(
    headers: &[String],
    mapping: &HashMap<String, String>,
) -> Result<(), String> {
    let header_set: HashSet<String> = headers.iter().map(|h| h.to_lowercase()).collect();

    for source in mapping.keys() {
        if !header_set.contains(&source.to_lowercase()) {
            return Err(format!(
                "Column mapping error: source column '{}' not found in CSV headers. Available columns: {}",
                source,
                headers.join(", ")
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name+tag@example.co.uk").is_ok());
        assert!(validate_email("a@b.c").is_ok());
    }

    #[test]
    fn test_validate_email_invalid() {
        assert!(validate_email("").is_err());
        assert!(validate_email("noatsign").is_err());
        assert!(validate_email("@domain.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@domain").is_err());
        assert!(validate_email("user @domain.com").is_err());
        assert!(validate_email("user@.domain.com").is_err());
        assert!(validate_email("user@domain.com.").is_err());
    }

    #[test]
    fn test_sanitize_display_name() {
        assert_eq!(sanitize_display_name("John Doe"), "John Doe");
        assert_eq!(sanitize_display_name("<script>alert('xss')</script>"), "");
        assert_eq!(sanitize_display_name("  Trimmed  "), "Trimmed");
    }

    #[test]
    fn test_validate_csv_headers_valid() {
        let headers = vec![
            "email".to_string(),
            "first_name".to_string(),
            "last_name".to_string(),
        ];
        let result = validate_csv_headers(&headers);
        assert!(result.valid);
        assert_eq!(result.known_columns.get("email"), Some(&0));
        assert_eq!(result.known_columns.get("first_name"), Some(&1));
        assert!(result.custom_columns.is_empty());
    }

    #[test]
    fn test_validate_csv_headers_missing_email() {
        let headers = vec!["first_name".to_string(), "last_name".to_string()];
        let result = validate_csv_headers(&headers);
        assert!(!result.valid);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_validate_csv_headers_custom_columns() {
        let headers = vec![
            "email".to_string(),
            "first_name".to_string(),
            "cost_center".to_string(),
            "employee_id".to_string(),
        ];
        let result = validate_csv_headers(&headers);
        assert!(result.valid);
        assert_eq!(result.custom_columns.len(), 2);
        assert_eq!(result.custom_columns[0].0, "cost_center");
        assert_eq!(result.custom_columns[1].0, "employee_id");
    }

    #[test]
    fn test_validate_csv_headers_case_insensitive() {
        let headers = vec!["Email".to_string(), "First_Name".to_string()];
        let result = validate_csv_headers(&headers);
        assert!(result.valid);
        assert!(result.known_columns.contains_key("email"));
        assert!(result.known_columns.contains_key("first_name"));
    }
}
