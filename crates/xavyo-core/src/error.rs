//! Error Types
//!
//! This module provides standardized error types for xavyo.
//!
//! # Example
//!
//! ```
//! use xavyo_core::{XavyoError, Result};
//!
//! fn find_user(id: &str) -> Result<String> {
//!     if id.is_empty() {
//!         return Err(XavyoError::NotFound {
//!             resource: "User".to_string(),
//!             id: None,
//!         });
//!     }
//!     Ok(format!("User {}", id))
//! }
//! ```

use crate::ids::TenantId;
use serde::Serialize;
use thiserror::Error;

/// Standardized error type for xavyo.
///
/// This enum provides consistent error types that can be used across all
/// xavyo services. Each variant maps to common error scenarios and can be
/// easily converted to HTTP status codes.
///
/// # Variants
///
/// - `Unauthorized` - Authentication/authorization failure (HTTP 401)
/// - `NotFound` - Resource not found (HTTP 404)
/// - `TenantMismatch` - Tenant isolation violation (HTTP 403)
/// - `ValidationError` - Input validation failure (HTTP 400)
///
/// # Example
///
/// ```
/// use xavyo_core::{XavyoError, TenantId};
///
/// let error = XavyoError::TenantMismatch {
///     expected: TenantId::new(),
///     actual: TenantId::new(),
/// };
///
/// println!("Error: {}", error);
/// ```
#[derive(Debug, Clone, Error, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum XavyoError {
    /// Authentication or authorization failure.
    ///
    /// Use when a user is not authenticated or lacks permission.
    /// Maps to HTTP 401 Unauthorized.
    #[error("Unauthorized{}", message.as_ref().map(|m| format!(": {m}")).unwrap_or_default())]
    Unauthorized {
        /// Optional message providing more context
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    /// Requested resource was not found.
    ///
    /// Use when a database lookup returns no results.
    /// Maps to HTTP 404 Not Found.
    #[error("{resource} not found{}", id.as_ref().map(|i| format!(": {i}")).unwrap_or_default())]
    NotFound {
        /// The type of resource that was not found (e.g., "User", "Document")
        resource: String,
        /// Optional identifier of the resource
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },

    /// Tenant isolation violation.
    ///
    /// Use when an operation attempts to access data from a different tenant.
    /// This is a critical security error. Maps to HTTP 403 Forbidden.
    #[error("Tenant mismatch: expected {expected}, got {actual}")]
    TenantMismatch {
        /// The expected tenant ID
        expected: TenantId,
        /// The actual tenant ID that was provided
        actual: TenantId,
    },

    /// Input validation failure.
    ///
    /// Use when user input fails validation rules.
    /// Maps to HTTP 400 Bad Request.
    #[error("Validation error on field '{field}': {message}")]
    ValidationError {
        /// The field that failed validation
        field: String,
        /// Description of the validation failure
        message: String,
    },
}

/// Type alias for Results using `XavyoError`.
///
/// This provides a convenient shorthand for function signatures:
///
/// ```
/// use xavyo_core::{Result, XavyoError};
///
/// fn example() -> Result<String> {
///     Ok("success".to_string())
/// }
/// ```
pub type Result<T> = std::result::Result<T, XavyoError>;

#[cfg(test)]
mod tests {
    use super::*;

    // T023: XavyoError::Unauthorized Display tests
    mod unauthorized_tests {
        use super::*;

        #[test]
        fn test_display_without_message() {
            let error = XavyoError::Unauthorized { message: None };
            assert_eq!(error.to_string(), "Unauthorized");
        }

        #[test]
        fn test_display_with_message() {
            let error = XavyoError::Unauthorized {
                message: Some("Invalid token".to_string()),
            };
            assert_eq!(error.to_string(), "Unauthorized: Invalid token");
        }

        #[test]
        fn test_is_std_error() {
            let error = XavyoError::Unauthorized { message: None };
            let _: &dyn std::error::Error = &error;
        }
    }

    // T024: XavyoError::NotFound Display tests
    mod not_found_tests {
        use super::*;

        #[test]
        fn test_display_without_id() {
            let error = XavyoError::NotFound {
                resource: "User".to_string(),
                id: None,
            };
            assert_eq!(error.to_string(), "User not found");
        }

        #[test]
        fn test_display_with_id() {
            let error = XavyoError::NotFound {
                resource: "Document".to_string(),
                id: Some("doc-123".to_string()),
            };
            assert_eq!(error.to_string(), "Document not found: doc-123");
        }

        #[test]
        fn test_different_resource_types() {
            let errors = [XavyoError::NotFound {
                    resource: "User".to_string(),
                    id: None,
                },
                XavyoError::NotFound {
                    resource: "Session".to_string(),
                    id: None,
                },
                XavyoError::NotFound {
                    resource: "Tenant".to_string(),
                    id: None,
                }];

            assert!(errors[0].to_string().contains("User"));
            assert!(errors[1].to_string().contains("Session"));
            assert!(errors[2].to_string().contains("Tenant"));
        }
    }

    // T025: XavyoError::TenantMismatch Display tests
    mod tenant_mismatch_tests {
        use super::*;

        #[test]
        fn test_display_includes_both_tenants() {
            let expected = TenantId::new();
            let actual = TenantId::new();
            let error = XavyoError::TenantMismatch { expected, actual };

            let display = error.to_string();
            assert!(display.contains("Tenant mismatch"));
            assert!(display.contains("expected"));
            assert!(display.contains("got"));
        }

        #[test]
        fn test_indicates_isolation_violation() {
            let expected = TenantId::new();
            let actual = TenantId::new();
            let error = XavyoError::TenantMismatch { expected, actual };

            // The display should make it clear this is about tenant mismatch
            let display = error.to_string();
            assert!(display.to_lowercase().contains("tenant"));
            assert!(display.to_lowercase().contains("mismatch"));
        }
    }

    // T026: XavyoError::ValidationError Display tests
    mod validation_error_tests {
        use super::*;

        #[test]
        fn test_display_includes_field_and_message() {
            let error = XavyoError::ValidationError {
                field: "email".to_string(),
                message: "must be a valid email address".to_string(),
            };

            let display = error.to_string();
            assert!(display.contains("email"));
            assert!(display.contains("must be a valid email address"));
        }

        #[test]
        fn test_display_format() {
            let error = XavyoError::ValidationError {
                field: "password".to_string(),
                message: "too short".to_string(),
            };

            assert_eq!(
                error.to_string(),
                "Validation error on field 'password': too short"
            );
        }

        #[test]
        fn test_empty_field_name() {
            let error = XavyoError::ValidationError {
                field: String::new(),
                message: "required".to_string(),
            };

            // Should still produce valid output
            let display = error.to_string();
            assert!(display.contains("required"));
        }
    }

    // T027: XavyoError serialization to JSON tests
    mod serde_tests {
        use super::*;

        #[test]
        fn test_unauthorized_serialization() {
            let error = XavyoError::Unauthorized {
                message: Some("test".to_string()),
            };
            let json = serde_json::to_string(&error).unwrap();
            assert!(json.contains("\"type\":\"unauthorized\""));
            assert!(json.contains("\"message\":\"test\""));
        }

        #[test]
        fn test_unauthorized_skips_none_message() {
            let error = XavyoError::Unauthorized { message: None };
            let json = serde_json::to_string(&error).unwrap();
            assert!(!json.contains("message"));
        }

        #[test]
        fn test_not_found_serialization() {
            let error = XavyoError::NotFound {
                resource: "User".to_string(),
                id: Some("123".to_string()),
            };
            let json = serde_json::to_string(&error).unwrap();
            assert!(json.contains("\"type\":\"not_found\""));
            assert!(json.contains("\"resource\":\"User\""));
            assert!(json.contains("\"id\":\"123\""));
        }

        #[test]
        fn test_tenant_mismatch_serialization() {
            let expected = TenantId::new();
            let actual = TenantId::new();
            let error = XavyoError::TenantMismatch { expected, actual };
            let json = serde_json::to_string(&error).unwrap();
            assert!(json.contains("\"type\":\"tenant_mismatch\""));
            assert!(json.contains("\"expected\""));
            assert!(json.contains("\"actual\""));
        }

        #[test]
        fn test_validation_error_serialization() {
            let error = XavyoError::ValidationError {
                field: "email".to_string(),
                message: "invalid".to_string(),
            };
            let json = serde_json::to_string(&error).unwrap();
            assert!(json.contains("\"type\":\"validation_error\""));
            assert!(json.contains("\"field\":\"email\""));
            assert!(json.contains("\"message\":\"invalid\""));
        }

        #[test]
        fn test_json_is_parseable() {
            let error = XavyoError::NotFound {
                resource: "Test".to_string(),
                id: None,
            };
            let json = serde_json::to_string(&error).unwrap();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert!(value.is_object());
        }
    }

    // T028: Result type alias usage tests
    mod result_tests {
        use super::*;

        fn success_function() -> Result<String> {
            Ok("success".to_string())
        }

        fn error_function() -> Result<String> {
            Err(XavyoError::NotFound {
                resource: "Test".to_string(),
                id: None,
            })
        }

        fn propagating_function() -> Result<String> {
            error_function()?;
            Ok("never reached".to_string())
        }

        #[test]
        fn test_result_ok_variant() {
            let result = success_function();
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "success");
        }

        #[test]
        fn test_result_err_variant() {
            let result = error_function();
            assert!(result.is_err());
        }

        #[test]
        fn test_question_mark_propagation() {
            let result = propagating_function();
            assert!(result.is_err());
        }

        #[test]
        fn test_result_with_different_ok_types() {
            fn number_result() -> Result<i32> {
                Ok(42)
            }

            fn vec_result() -> Result<Vec<String>> {
                Ok(vec!["a".to_string()])
            }

            assert_eq!(number_result().unwrap(), 42);
            assert_eq!(vec_result().unwrap().len(), 1);
        }
    }
}
