//! Action executors for the Bulk Action Engine (F-064).
//!
//! Each executor implements a specific action type (assign_role, revoke_role,
//! enable, disable, modify_attribute) and handles the actual execution against
//! a target user.

pub mod assign_role;
pub mod disable_user;
pub mod enable_user;
pub mod modify_attribute;
pub mod revoke_role;

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub use assign_role::AssignRoleExecutor;
pub use disable_user::DisableUserExecutor;
pub use enable_user::EnableUserExecutor;
pub use modify_attribute::ModifyAttributeExecutor;
pub use revoke_role::RevokeRoleExecutor;

/// Result of executing an action on a single user.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// Whether the operation was skipped (user already in target state).
    pub skipped: bool,

    /// Error message if failed.
    pub error: Option<String>,

    /// Value before the change (for audit logging).
    pub previous_value: Option<serde_json::Value>,

    /// Value after the change (for audit logging).
    pub new_value: Option<serde_json::Value>,
}

impl ExecutionResult {
    /// Create a successful result.
    pub fn success(previous_value: serde_json::Value, new_value: serde_json::Value) -> Self {
        Self {
            success: true,
            skipped: false,
            error: None,
            previous_value: Some(previous_value),
            new_value: Some(new_value),
        }
    }

    /// Create a skipped result (no change needed).
    pub fn skipped(current_value: serde_json::Value) -> Self {
        Self {
            success: true,
            skipped: true,
            error: None,
            previous_value: Some(current_value),
            new_value: None,
        }
    }

    /// Create a failed result.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            skipped: false,
            error: Some(error.into()),
            previous_value: None,
            new_value: None,
        }
    }
}

/// Context provided to action executors.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Tenant ID for the operation.
    pub tenant_id: Uuid,

    /// User ID who initiated the bulk action.
    pub initiated_by: Uuid,

    /// Bulk action ID for audit correlation.
    pub bulk_action_id: Uuid,

    /// Justification from the bulk action.
    pub justification: String,
}

/// Trait for action executors.
///
/// Each action type (assign_role, revoke_role, enable, disable, modify_attribute)
/// has a corresponding executor that implements this trait.
#[async_trait]
pub trait ActionExecutor: Send + Sync {
    /// Execute the action on a target user.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `ctx` - Execution context with tenant, initiator, and audit info
    /// * `target_user_id` - The user to execute the action on
    /// * `params` - Action-specific parameters (e.g., role_id, attribute name/value)
    ///
    /// # Returns
    /// * `ExecutionResult` with success/skipped/error status
    async fn execute(
        &self,
        pool: &PgPool,
        ctx: &ExecutionContext,
        target_user_id: Uuid,
        params: &serde_json::Value,
    ) -> ExecutionResult;

    /// Check if the action would change the user's state (for preview).
    ///
    /// Returns `(would_change, current_value, new_value)`.
    async fn would_change(
        &self,
        pool: &PgPool,
        ctx: &ExecutionContext,
        target_user_id: Uuid,
        params: &serde_json::Value,
    ) -> (bool, Option<serde_json::Value>, Option<serde_json::Value>);

    /// Get the action type name for logging.
    fn action_type(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result_success() {
        let result = ExecutionResult::success(serde_json::json!(false), serde_json::json!(true));
        assert!(result.success);
        assert!(!result.skipped);
        assert!(result.error.is_none());
        assert_eq!(result.previous_value, Some(serde_json::json!(false)));
        assert_eq!(result.new_value, Some(serde_json::json!(true)));
    }

    #[test]
    fn test_execution_result_skipped() {
        let result = ExecutionResult::skipped(serde_json::json!(true));
        assert!(result.success);
        assert!(result.skipped);
        assert!(result.error.is_none());
        assert_eq!(result.previous_value, Some(serde_json::json!(true)));
        assert!(result.new_value.is_none());
    }

    #[test]
    fn test_execution_result_failure() {
        let result = ExecutionResult::failure("Role not found");
        assert!(!result.success);
        assert!(!result.skipped);
        assert_eq!(result.error, Some("Role not found".to_string()));
    }
}
