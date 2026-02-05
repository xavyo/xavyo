//! Request and response models for bulk action endpoints (F-064).
//!
//! The Bulk Action Engine enables administrators to perform mass operations
//! on identities using expression-based filtering with preview mode, async
//! execution, and progress tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovBulkAction, GovBulkActionStatus, GovBulkActionType};

// ============================================================================
// Create Bulk Action Models
// ============================================================================

/// Request to create a new bulk action.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateBulkActionRequest {
    /// SQL-like filter expression to select target users.
    /// Supports AND, OR, NOT, =, !=, <, >, <=, >=, LIKE, IN operators.
    /// Example: "department = 'engineering' AND lifecycle_state = 'active'"
    #[validate(length(
        min = 1,
        max = 10000,
        message = "Filter expression must be between 1 and 10000 characters"
    ))]
    pub filter_expression: String,

    /// Type of action to perform on matched users.
    pub action_type: GovBulkActionType,

    /// Action-specific parameters (JSON object).
    /// - assign_role/revoke_role: {"role_id": "uuid"}
    /// - enable/disable: {} (no params required)
    /// - modify_attribute: {"attribute": "name", "value": "new_value"}
    pub action_params: serde_json::Value,

    /// Audit justification for the bulk action (min 10 characters).
    #[validate(length(
        min = 10,
        max = 2000,
        message = "Justification must be between 10 and 2000 characters"
    ))]
    pub justification: String,
}

// ============================================================================
// Bulk Action Response Models
// ============================================================================

/// Bulk action summary response (used in lists).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkActionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Filter expression used to select users.
    pub filter_expression: String,

    /// Type of action.
    pub action_type: GovBulkActionType,

    /// Action-specific parameters.
    pub action_params: serde_json::Value,

    /// Current status of the action.
    pub status: GovBulkActionStatus,

    /// Audit justification.
    pub justification: String,

    /// Total users matched by the filter.
    pub total_matched: i32,

    /// Number of users processed so far.
    pub processed_count: i32,

    /// Number of successful operations.
    pub success_count: i32,

    /// Number of failed operations.
    pub failure_count: i32,

    /// Number of skipped operations (no change needed).
    pub skipped_count: i32,

    /// User who created this bulk action.
    pub created_by: Uuid,

    /// When the bulk action was created.
    pub created_at: DateTime<Utc>,

    /// When execution started (null if not started).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,

    /// When execution completed (null if not completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

impl From<GovBulkAction> for BulkActionResponse {
    fn from(action: GovBulkAction) -> Self {
        Self {
            id: action.id,
            tenant_id: action.tenant_id,
            filter_expression: action.filter_expression,
            action_type: action.action_type,
            action_params: action.action_params,
            status: action.status,
            justification: action.justification,
            total_matched: action.total_matched,
            processed_count: action.processed_count,
            success_count: action.success_count,
            failure_count: action.failure_count,
            skipped_count: action.skipped_count,
            created_by: action.created_by,
            created_at: action.created_at,
            started_at: action.started_at,
            completed_at: action.completed_at,
        }
    }
}

/// Bulk action detail response (includes results and progress).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkActionDetailResponse {
    /// Core bulk action details.
    #[serde(flatten)]
    pub bulk_action: BulkActionResponse,

    /// Detailed results for each user (success/failure/skipped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<BulkActionResultItem>>,

    /// Progress percentage (0-100).
    pub progress_percent: i32,
}

impl BulkActionDetailResponse {
    /// Create detail response from a bulk action.
    pub fn from_action(action: GovBulkAction) -> Self {
        let progress = action.get_progress();
        let results = action
            .results
            .clone()
            .map(|r| serde_json::from_value::<Vec<BulkActionResultItem>>(r).unwrap_or_default());

        Self {
            bulk_action: BulkActionResponse::from(action),
            results,
            progress_percent: i32::from(progress.progress_percent),
        }
    }
}

/// Result for a single user in a bulk action.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkActionResultItem {
    /// User ID.
    pub user_id: Uuid,

    /// Whether the operation succeeded.
    pub success: bool,

    /// Whether the operation was skipped (no change needed).
    pub skipped: bool,

    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// List and Query Models
// ============================================================================

/// Query parameters for listing bulk actions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListBulkActionsQuery {
    /// Filter by status.
    pub status: Option<GovBulkActionStatus>,

    /// Filter by action type.
    pub action_type: Option<GovBulkActionType>,

    /// Filter by creator.
    pub created_by: Option<Uuid>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListBulkActionsQuery {
    fn default() -> Self {
        Self {
            status: None,
            action_type: None,
            created_by: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of bulk actions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkActionListResponse {
    /// List of bulk actions.
    pub items: Vec<BulkActionResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

// ============================================================================
// Preview Models
// ============================================================================

/// Query parameters for preview endpoint.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct PreviewBulkActionQuery {
    /// Maximum number of users to return (default: 100, max: 1000).
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<i64>,

    /// Number of users to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for PreviewBulkActionQuery {
    fn default() -> Self {
        Self {
            limit: Some(100),
            offset: Some(0),
        }
    }
}

/// Preview response showing which users would be affected.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkActionPreviewResponse {
    /// Total users matched by the filter expression.
    pub total_matched: i64,

    /// Number of users that would actually change.
    pub would_change_count: i64,

    /// Number of users where no change is needed.
    pub no_change_count: i64,

    /// List of matched users with change indication.
    pub users: Vec<PreviewUser>,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// A user in the preview results.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PreviewUser {
    /// User ID.
    pub id: Uuid,

    /// User email.
    pub email: String,

    /// User display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Whether the action would change this user.
    pub would_change: bool,

    /// Current value of the target attribute/role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_value: Option<serde_json::Value>,

    /// Value after action (null if no change).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<serde_json::Value>,
}

// ============================================================================
// Expression Validation Models
// ============================================================================

/// Request to validate a filter expression.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ValidateExpressionRequest {
    /// Filter expression to validate.
    #[validate(length(
        min = 1,
        max = 10000,
        message = "Expression must be between 1 and 10000 characters"
    ))]
    pub expression: String,
}

/// Response from expression validation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExpressionValidationResponse {
    /// Whether the expression is syntactically valid.
    pub valid: bool,

    /// Error message if invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// List of attributes referenced in the expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsed_attributes: Option<Vec<String>>,
}

// ============================================================================
// Error Response Model
// ============================================================================

/// Error response for bulk action operations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkActionErrorResponse {
    /// Error message.
    pub error: String,

    /// Additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_create_bulk_action_validation() {
        let valid = CreateBulkActionRequest {
            filter_expression: "department = 'engineering'".to_string(),
            action_type: GovBulkActionType::AssignRole,
            action_params: serde_json::json!({"role_id": "550e8400-e29b-41d4-a716-446655440000"}),
            justification: "Quarterly role assignment for engineering team".to_string(),
        };
        assert!(valid.validate().is_ok());

        // Test empty filter expression
        let invalid_expression = CreateBulkActionRequest {
            filter_expression: "".to_string(),
            ..valid.clone()
        };
        assert!(invalid_expression.validate().is_err());

        // Test short justification
        let invalid_justification = CreateBulkActionRequest {
            justification: "Short".to_string(),
            ..valid.clone()
        };
        assert!(invalid_justification.validate().is_err());
    }

    #[test]
    fn test_validate_expression_request() {
        let valid = ValidateExpressionRequest {
            expression: "active = true AND department LIKE 'eng%'".to_string(),
        };
        assert!(valid.validate().is_ok());

        let invalid = ValidateExpressionRequest {
            expression: "".to_string(),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_list_queries_defaults() {
        let query = ListBulkActionsQuery::default();
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.offset, Some(0));

        let preview_query = PreviewBulkActionQuery::default();
        assert_eq!(preview_query.limit, Some(100));
        assert_eq!(preview_query.offset, Some(0));
    }

    #[test]
    fn test_expression_validation_response_serialization() {
        let valid_response = ExpressionValidationResponse {
            valid: true,
            error: None,
            parsed_attributes: Some(vec!["department".to_string(), "active".to_string()]),
        };
        let json = serde_json::to_string(&valid_response).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("\"parsed_attributes\""));
        assert!(!json.contains("\"error\""));

        let invalid_response = ExpressionValidationResponse {
            valid: false,
            error: Some("Unexpected token at position 15".to_string()),
            parsed_attributes: None,
        };
        let json = serde_json::to_string(&invalid_response).unwrap();
        assert!(json.contains("\"valid\":false"));
        assert!(json.contains("\"error\""));
        assert!(!json.contains("\"parsed_attributes\""));
    }

    #[test]
    fn test_preview_user_serialization() {
        let user = PreviewUser {
            id: Uuid::new_v4(),
            email: "user@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            would_change: true,
            current_value: Some(serde_json::json!(false)),
            new_value: Some(serde_json::json!(true)),
        };
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("\"would_change\":true"));
        assert!(json.contains("\"current_value\":false"));
        assert!(json.contains("\"new_value\":true"));
    }

    #[test]
    fn test_bulk_action_result_item() {
        let success = BulkActionResultItem {
            user_id: Uuid::new_v4(),
            success: true,
            skipped: false,
            error: None,
        };
        let json = serde_json::to_string(&success).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(!json.contains("\"error\""));

        let failed = BulkActionResultItem {
            user_id: Uuid::new_v4(),
            success: false,
            skipped: false,
            error: Some("User already has role".to_string()),
        };
        let json = serde_json::to_string(&failed).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"error\""));

        let skipped = BulkActionResultItem {
            user_id: Uuid::new_v4(),
            success: true,
            skipped: true,
            error: None,
        };
        let json = serde_json::to_string(&skipped).unwrap();
        assert!(json.contains("\"skipped\":true"));
    }
}
