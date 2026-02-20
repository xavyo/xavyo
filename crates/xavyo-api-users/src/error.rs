//! Error types for the User Management API.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use utoipa::ToSchema;

/// A single attribute validation error with field name and description.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AttributeFieldError {
    /// The attribute name that failed validation.
    pub attribute: String,
    /// Description of the validation failure.
    pub error: String,
}

/// A single field validation error with detailed information.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FieldValidationError {
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

impl From<crate::validation::ValidationError> for FieldValidationError {
    fn from(err: crate::validation::ValidationError) -> Self {
        Self {
            field: err.field,
            code: err.code,
            message: err.message,
            constraints: err.constraints,
        }
    }
}

/// Error type for the User Management API.
#[derive(Debug, thiserror::Error)]
pub enum ApiUsersError {
    /// User not found (or cross-tenant access attempt).
    #[error("User not found")]
    NotFound,

    /// Email already exists in tenant.
    #[error("Email already exists")]
    EmailConflict,

    /// Validation error (invalid email, weak password, etc.).
    #[error("Validation error: {0}")]
    Validation(String),

    /// Admin role required.
    #[error("Admin role required")]
    Forbidden,

    /// Authentication required.
    #[error("Authentication required")]
    Unauthorized,

    /// Internal server error.
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    // Custom Attributes errors (F070)
    /// Custom attribute validation failed with one or more field-level errors.
    #[error("Attribute validation failed")]
    AttributeValidationFailed {
        /// Individual field validation errors.
        errors: Vec<AttributeFieldError>,
    },

    /// Attribute definition not found.
    #[error("Attribute definition not found")]
    AttributeDefinitionNotFound,

    /// Attribute definition name already exists in tenant.
    #[error("Attribute definition name already exists")]
    AttributeDefinitionConflict,

    /// Attribute definition cannot be deleted because user data exists.
    #[error("Attribute definition is in use by existing user data")]
    AttributeDefinitionInUse,

    /// Tenant has reached the maximum number of attribute definitions (100).
    #[error("Maximum number of attribute definitions reached (100)")]
    AttributeDefinitionLimitExceeded,

    /// Cannot change `data_type` on an attribute definition when user data exists.
    #[error("Cannot change data type when user data exists for this attribute")]
    AttributeDataTypeChangeRejected,

    // Group Hierarchy errors (F071)
    /// Maximum hierarchy depth of 10 levels exceeded.
    #[error("Maximum hierarchy depth of 10 levels exceeded")]
    MaxDepthExceeded,

    /// Moving this group would create a circular reference.
    #[error("Moving this group would create a circular reference")]
    CycleDetected,

    /// Parent group belongs to a different tenant.
    #[error("Parent group belongs to a different tenant")]
    CrossTenantParent,

    /// Cannot delete group because it has child groups.
    #[error("Cannot delete group because it has child groups")]
    HasChildren,

    /// Group not found.
    #[error("Group not found")]
    GroupNotFound,

    /// Group member not found (user not a member of the specified group).
    #[error("Member not found in group")]
    GroupMemberNotFound,

    /// Parent group not found.
    #[error("Parent group not found")]
    ParentNotFound,

    /// Field-level validation errors with detailed information.
    #[error("Validation failed")]
    ValidationErrors {
        /// Individual field validation errors.
        errors: Vec<FieldValidationError>,
    },
}

/// RFC 7807 Problem Details response format.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Field-level validation errors (present only for attribute validation failures).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<AttributeFieldError>>,
}

impl IntoResponse for ApiUsersError {
    fn into_response(self) -> Response {
        let (status, problem) = match &self {
            ApiUsersError::NotFound => (
                StatusCode::NOT_FOUND,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/not-found".to_string(),
                    title: "Not Found".to_string(),
                    status: 404,
                    detail: Some("User not found".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::EmailConflict => (
                StatusCode::CONFLICT,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/conflict".to_string(),
                    title: "Conflict".to_string(),
                    status: 409,
                    detail: Some("Email already exists in tenant".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/validation-error".to_string(),
                    title: "Validation Error".to_string(),
                    status: 400,
                    detail: Some(msg.clone()),
                    errors: None,
                },
            ),
            ApiUsersError::Forbidden => (
                StatusCode::FORBIDDEN,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/forbidden".to_string(),
                    title: "Forbidden".to_string(),
                    status: 403,
                    detail: Some("Admin role required for this operation".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/unauthorized".to_string(),
                    title: "Unauthorized".to_string(),
                    status: 401,
                    detail: Some("Missing or invalid authentication token".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ProblemDetails {
                        problem_type: "https://xavyo.net/problems/internal-error".to_string(),
                        title: "Internal Server Error".to_string(),
                        status: 500,
                        detail: Some("An internal error occurred".to_string()),
                        errors: None,
                    },
                )
            }
            ApiUsersError::Database(e) => {
                tracing::error!("Database error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ProblemDetails {
                        problem_type: "https://xavyo.net/problems/internal-error".to_string(),
                        title: "Internal Server Error".to_string(),
                        status: 500,
                        detail: Some("A database error occurred".to_string()),
                        errors: None,
                    },
                )
            }
            ApiUsersError::AttributeValidationFailed { errors } => (
                StatusCode::BAD_REQUEST,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/attribute-validation-error"
                        .to_string(),
                    title: "Attribute Validation Error".to_string(),
                    status: 400,
                    detail: Some(format!(
                        "{} attribute validation error(s)",
                        errors.len()
                    )),
                    errors: Some(errors.clone()),
                },
            ),
            ApiUsersError::AttributeDefinitionNotFound => (
                StatusCode::NOT_FOUND,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/not-found".to_string(),
                    title: "Not Found".to_string(),
                    status: 404,
                    detail: Some("Attribute definition not found".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::AttributeDefinitionConflict => (
                StatusCode::CONFLICT,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/conflict".to_string(),
                    title: "Conflict".to_string(),
                    status: 409,
                    detail: Some(
                        "An attribute definition with this name already exists in the tenant"
                            .to_string(),
                    ),
                    errors: None,
                },
            ),
            ApiUsersError::AttributeDefinitionInUse => (
                StatusCode::CONFLICT,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/attribute-in-use".to_string(),
                    title: "Attribute In Use".to_string(),
                    status: 409,
                    detail: Some(
                        "Cannot delete attribute definition: user data exists. Use force=true to delete anyway."
                            .to_string(),
                    ),
                    errors: None,
                },
            ),
            ApiUsersError::AttributeDefinitionLimitExceeded => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/limit-exceeded".to_string(),
                    title: "Limit Exceeded".to_string(),
                    status: 422,
                    detail: Some(
                        "Maximum number of attribute definitions per tenant (100) has been reached"
                            .to_string(),
                    ),
                    errors: None,
                },
            ),
            ApiUsersError::AttributeDataTypeChangeRejected => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/data-type-change-rejected".to_string(),
                    title: "Data Type Change Rejected".to_string(),
                    status: 422,
                    detail: Some(
                        "Cannot change the data type of an attribute definition when user data exists for this attribute"
                            .to_string(),
                    ),
                    errors: None,
                },
            ),
            ApiUsersError::MaxDepthExceeded => (
                StatusCode::BAD_REQUEST,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/max-depth-exceeded".to_string(),
                    title: "Max Depth Exceeded".to_string(),
                    status: 400,
                    detail: Some("Maximum hierarchy depth of 10 levels exceeded".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::CycleDetected => (
                StatusCode::BAD_REQUEST,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/cycle-detected".to_string(),
                    title: "Cycle Detected".to_string(),
                    status: 400,
                    detail: Some(
                        "Moving this group would create a circular reference in the hierarchy"
                            .to_string(),
                    ),
                    errors: None,
                },
            ),
            ApiUsersError::CrossTenantParent => (
                StatusCode::BAD_REQUEST,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/cross-tenant-parent".to_string(),
                    title: "Cross-Tenant Parent".to_string(),
                    status: 400,
                    detail: Some("Parent group belongs to a different tenant".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::HasChildren => (
                StatusCode::BAD_REQUEST,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/has-children".to_string(),
                    title: "Has Children".to_string(),
                    status: 400,
                    detail: Some(
                        "Cannot delete group because it has child groups. Remove or reassign children first."
                            .to_string(),
                    ),
                    errors: None,
                },
            ),
            ApiUsersError::GroupNotFound => (
                StatusCode::NOT_FOUND,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/group-not-found".to_string(),
                    title: "Group Not Found".to_string(),
                    status: 404,
                    detail: Some("The specified group was not found".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::GroupMemberNotFound => (
                StatusCode::NOT_FOUND,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/group-member-not-found".to_string(),
                    title: "Member Not Found".to_string(),
                    status: 404,
                    detail: Some("The specified user is not a member of this group".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::ParentNotFound => (
                StatusCode::NOT_FOUND,
                ProblemDetails {
                    problem_type: "https://xavyo.net/problems/parent-not-found".to_string(),
                    title: "Parent Not Found".to_string(),
                    status: 404,
                    detail: Some("The specified parent group was not found".to_string()),
                    errors: None,
                },
            ),
            ApiUsersError::ValidationErrors { errors } => {
                // Convert FieldValidationError to AttributeFieldError for response
                let attr_errors: Vec<AttributeFieldError> = errors
                    .iter()
                    .map(|e| AttributeFieldError {
                        attribute: e.field.clone(),
                        error: e.message.clone(),
                    })
                    .collect();
                (
                    StatusCode::BAD_REQUEST,
                    ProblemDetails {
                        problem_type: "https://xavyo.net/problems/validation-error".to_string(),
                        title: "Validation Error".to_string(),
                        status: 400,
                        detail: Some(format!(
                            "{} validation error(s)",
                            errors.len()
                        )),
                        errors: Some(attr_errors),
                    },
                )
            }
        };

        (status, Json(problem)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ApiUsersError::NotFound;
        assert_eq!(err.to_string(), "User not found");

        let err = ApiUsersError::Validation("Invalid email".to_string());
        assert_eq!(err.to_string(), "Validation error: Invalid email");
    }

    #[test]
    fn test_attribute_validation_error_display() {
        let err = ApiUsersError::AttributeValidationFailed {
            errors: vec![AttributeFieldError {
                attribute: "department".to_string(),
                error: "Required attribute is missing".to_string(),
            }],
        };
        assert_eq!(err.to_string(), "Attribute validation failed");
    }

    #[test]
    fn test_attribute_definition_errors() {
        assert_eq!(
            ApiUsersError::AttributeDefinitionNotFound.to_string(),
            "Attribute definition not found"
        );
        assert_eq!(
            ApiUsersError::AttributeDefinitionConflict.to_string(),
            "Attribute definition name already exists"
        );
        assert_eq!(
            ApiUsersError::AttributeDefinitionInUse.to_string(),
            "Attribute definition is in use by existing user data"
        );
        assert_eq!(
            ApiUsersError::AttributeDefinitionLimitExceeded.to_string(),
            "Maximum number of attribute definitions reached (100)"
        );
        assert_eq!(
            ApiUsersError::AttributeDataTypeChangeRejected.to_string(),
            "Cannot change data type when user data exists for this attribute"
        );
    }

    #[test]
    fn test_hierarchy_error_display() {
        assert_eq!(
            ApiUsersError::MaxDepthExceeded.to_string(),
            "Maximum hierarchy depth of 10 levels exceeded"
        );
        assert_eq!(
            ApiUsersError::CycleDetected.to_string(),
            "Moving this group would create a circular reference"
        );
        assert_eq!(
            ApiUsersError::CrossTenantParent.to_string(),
            "Parent group belongs to a different tenant"
        );
        assert_eq!(
            ApiUsersError::HasChildren.to_string(),
            "Cannot delete group because it has child groups"
        );
        assert_eq!(ApiUsersError::GroupNotFound.to_string(), "Group not found");
        assert_eq!(
            ApiUsersError::ParentNotFound.to_string(),
            "Parent group not found"
        );
    }
}
