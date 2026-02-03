//! Pagination parameter validation.
//!
//! Validates pagination parameters with rejection (not clamping) for invalid values:
//! - offset: must be >= 0
//! - limit: must be between 1 and MAX_LIMIT (100)

use super::error::ValidationError;
use serde_json::json;

/// Default page size.
pub const DEFAULT_LIMIT: i64 = 20;

/// Maximum allowed page size.
pub const MAX_LIMIT: i64 = 100;

/// Minimum allowed page size.
pub const MIN_LIMIT: i64 = 1;

/// Validate pagination parameters.
///
/// # Arguments
///
/// * `offset` - The offset for pagination (None defaults to 0)
/// * `limit` - The limit for pagination (None defaults to DEFAULT_LIMIT)
///
/// # Returns
///
/// * `Ok((offset, limit))` with validated values
/// * `Err(Vec<ValidationError>)` if any parameter is invalid
///
/// # Examples
///
/// ```
/// use xavyo_api_users::validation::validate_pagination;
///
/// // Valid pagination
/// assert!(validate_pagination(Some(0), Some(50)).is_ok());
/// assert!(validate_pagination(None, None).is_ok()); // uses defaults
///
/// // Invalid pagination
/// assert!(validate_pagination(Some(-1), Some(50)).is_err()); // negative offset
/// assert!(validate_pagination(Some(0), Some(500)).is_err()); // exceeds max
/// assert!(validate_pagination(Some(0), Some(0)).is_err()); // zero limit
/// ```
pub fn validate_pagination(
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<(i64, i64), Vec<ValidationError>> {
    let mut errors = Vec::new();

    // Validate offset
    let validated_offset = match offset {
        Some(o) if o < 0 => {
            errors.push(ValidationError::with_constraints(
                "offset",
                "negative",
                "Offset must be a non-negative integer",
                json!({"min": 0, "actual": o}),
            ));
            0 // Use default for return value calculation
        }
        Some(o) => o,
        None => 0,
    };

    // Validate limit
    let validated_limit = match limit {
        Some(l) if l < MIN_LIMIT => {
            errors.push(ValidationError::with_constraints(
                "limit",
                "too_small",
                format!("Limit must be at least {}", MIN_LIMIT),
                json!({"min": MIN_LIMIT, "actual": l}),
            ));
            DEFAULT_LIMIT
        }
        Some(l) if l > MAX_LIMIT => {
            errors.push(ValidationError::with_constraints(
                "limit",
                "too_large",
                format!("Limit must not exceed {}", MAX_LIMIT),
                json!({"max": MAX_LIMIT, "actual": l}),
            ));
            DEFAULT_LIMIT
        }
        Some(l) => l,
        None => DEFAULT_LIMIT,
    };

    if errors.is_empty() {
        Ok((validated_offset, validated_limit))
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_pagination_with_values() {
        let result = validate_pagination(Some(10), Some(50));
        assert!(result.is_ok());
        let (offset, limit) = result.unwrap();
        assert_eq!(offset, 10);
        assert_eq!(limit, 50);
    }

    #[test]
    fn test_valid_pagination_defaults() {
        let result = validate_pagination(None, None);
        assert!(result.is_ok());
        let (offset, limit) = result.unwrap();
        assert_eq!(offset, 0);
        assert_eq!(limit, DEFAULT_LIMIT);
    }

    #[test]
    fn test_valid_pagination_offset_only() {
        let result = validate_pagination(Some(100), None);
        assert!(result.is_ok());
        let (offset, limit) = result.unwrap();
        assert_eq!(offset, 100);
        assert_eq!(limit, DEFAULT_LIMIT);
    }

    #[test]
    fn test_valid_pagination_limit_only() {
        let result = validate_pagination(None, Some(50));
        assert!(result.is_ok());
        let (offset, limit) = result.unwrap();
        assert_eq!(offset, 0);
        assert_eq!(limit, 50);
    }

    #[test]
    fn test_valid_pagination_min_limit() {
        let result = validate_pagination(Some(0), Some(1));
        assert!(result.is_ok());
        let (_, limit) = result.unwrap();
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_valid_pagination_max_limit() {
        let result = validate_pagination(Some(0), Some(100));
        assert!(result.is_ok());
        let (_, limit) = result.unwrap();
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_invalid_pagination_negative_offset() {
        let result = validate_pagination(Some(-1), Some(50));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "offset");
        assert_eq!(errors[0].code, "negative");
    }

    #[test]
    fn test_invalid_pagination_zero_limit() {
        let result = validate_pagination(Some(0), Some(0));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "limit");
        assert_eq!(errors[0].code, "too_small");
    }

    #[test]
    fn test_invalid_pagination_negative_limit() {
        let result = validate_pagination(Some(0), Some(-5));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "limit");
        assert_eq!(errors[0].code, "too_small");
    }

    #[test]
    fn test_invalid_pagination_exceeds_max_limit() {
        let result = validate_pagination(Some(0), Some(500));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "limit");
        assert_eq!(errors[0].code, "too_large");
        // Check constraints
        let constraints = errors[0].constraints.as_ref().unwrap();
        assert_eq!(constraints["max"], 100);
        assert_eq!(constraints["actual"], 500);
    }

    #[test]
    fn test_invalid_pagination_multiple_errors() {
        let result = validate_pagination(Some(-10), Some(500));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 2);
        // Should have both offset and limit errors
        let fields: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
        assert!(fields.contains(&"offset"));
        assert!(fields.contains(&"limit"));
    }
}
