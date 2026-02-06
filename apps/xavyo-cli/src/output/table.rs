//! Table display helpers for CLI commands

use crate::error::{CliError, CliResult};

/// Truncate a string for table display, handling Unicode safely.
///
/// If the string exceeds `max_len`, it is truncated with "..." appended.
/// Uses character boundaries to avoid panicking on multi-byte characters.
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

/// Validate pagination parameters (limit and offset).
///
/// - `limit` must be between 1 and 100 inclusive
/// - `offset` must be >= 0
pub fn validate_pagination(limit: i32, offset: i32) -> CliResult<()> {
    if !(1..=100).contains(&limit) {
        return Err(CliError::Validation(
            "Limit must be between 1 and 100.".to_string(),
        ));
    }
    if offset < 0 {
        return Err(CliError::Validation("Offset must be >= 0.".to_string()));
    }
    Ok(())
}

/// Parse a comma-separated string into a list, filtering empty entries.
pub fn parse_comma_list(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_exact_length() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        let result = truncate("hello world this is long", 10);
        assert!(result.len() <= 10);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_unicode() {
        // Should not panic on multi-byte chars
        let result = truncate("héllo wörld café", 10);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_validate_pagination_valid() {
        assert!(validate_pagination(50, 0).is_ok());
        assert!(validate_pagination(1, 0).is_ok());
        assert!(validate_pagination(100, 50).is_ok());
    }

    #[test]
    fn test_validate_pagination_invalid_limit() {
        assert!(validate_pagination(0, 0).is_err());
        assert!(validate_pagination(101, 0).is_err());
        assert!(validate_pagination(-1, 0).is_err());
    }

    #[test]
    fn test_validate_pagination_invalid_offset() {
        assert!(validate_pagination(50, -1).is_err());
    }

    #[test]
    fn test_parse_comma_list() {
        assert_eq!(parse_comma_list("a, b, c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_comma_list_filters_empty() {
        assert_eq!(parse_comma_list("a,,b, ,c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_comma_list_single() {
        assert_eq!(parse_comma_list("admin"), vec!["admin"]);
    }
}
