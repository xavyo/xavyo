//! Validation error types.

use serde::Serialize;
use utoipa::ToSchema;

/// A single validation error with field information.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ValidationError {
    /// The field name that failed validation.
    pub field: String,
    /// Error code for programmatic handling.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Optional constraint details (e.g., `max_length`, pattern).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,
}

impl ValidationError {
    /// Create a new validation error.
    pub fn new(
        field: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            code: code.into(),
            message: message.into(),
            constraints: None,
        }
    }

    /// Create a validation error with constraint details.
    pub fn with_constraints(
        field: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
        constraints: serde_json::Value,
    ) -> Self {
        Self {
            field: field.into(),
            code: code.into(),
            message: message.into(),
            constraints: Some(constraints),
        }
    }
}

/// Result type for validation operations.
pub type ValidationResult<T> = Result<T, Vec<ValidationError>>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validation_error_new() {
        let err = ValidationError::new("email", "invalid_format", "Invalid email format");
        assert_eq!(err.field, "email");
        assert_eq!(err.code, "invalid_format");
        assert_eq!(err.message, "Invalid email format");
        assert!(err.constraints.is_none());
    }

    #[test]
    fn test_validation_error_with_constraints() {
        let err = ValidationError::with_constraints(
            "username",
            "too_short",
            "Username must be at least 3 characters",
            json!({"min_length": 3, "actual": 2}),
        );
        assert_eq!(err.field, "username");
        assert!(err.constraints.is_some());
        let constraints = err.constraints.unwrap();
        assert_eq!(constraints["min_length"], 3);
        assert_eq!(constraints["actual"], 2);
    }

    #[test]
    fn test_validation_error_serialization() {
        let err = ValidationError::new("email", "invalid_format", "Invalid email format");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"field\":\"email\""));
        assert!(json.contains("\"code\":\"invalid_format\""));
        // constraints should be omitted when None
        assert!(!json.contains("constraints"));
    }

    #[test]
    fn test_validation_error_serialization_with_constraints() {
        let err = ValidationError::with_constraints(
            "page_size",
            "exceeds_max",
            "Page size exceeds maximum",
            json!({"max": 100, "actual": 500}),
        );
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"constraints\""));
        assert!(json.contains("\"max\":100"));
    }
}
