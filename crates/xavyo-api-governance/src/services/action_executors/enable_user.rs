//! EnableUser action executor for F-064: Bulk Action Engine.
//!
//! Enables a disabled user account.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::{ActionExecutor, ExecutionContext, ExecutionResult};

/// Executor for enable action.
pub struct EnableUserExecutor;

impl EnableUserExecutor {
    /// Create a new enable user executor.
    pub fn new() -> Self {
        Self
    }

    /// Check if the user is currently active.
    async fn is_user_active(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result: Option<(bool,)> =
            sqlx::query_as("SELECT is_active FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_optional(pool)
                .await?;

        Ok(result.map(|(active,)| active).unwrap_or(false))
    }

    /// Enable the user.
    async fn enable_user(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE users SET is_active = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND is_active = false
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

impl Default for EnableUserExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ActionExecutor for EnableUserExecutor {
    async fn execute(
        &self,
        pool: &PgPool,
        ctx: &ExecutionContext,
        target_user_id: Uuid,
        _params: &serde_json::Value,
    ) -> ExecutionResult {
        let tenant_id = ctx.tenant_id;
        // Check current state
        match Self::is_user_active(pool, tenant_id, target_user_id).await {
            Ok(true) => {
                // User already active - skip
                return ExecutionResult::skipped(serde_json::json!({"is_active": true}));
            }
            Ok(false) => {
                // Proceed with enable
            }
            Err(e) => return ExecutionResult::failure(format!("Failed to check user status: {e}")),
        }

        // Enable the user
        match Self::enable_user(pool, tenant_id, target_user_id).await {
            Ok(true) => ExecutionResult::success(
                serde_json::json!({"is_active": false}),
                serde_json::json!({"is_active": true}),
            ),
            Ok(false) => {
                // Race condition or user not found
                ExecutionResult::skipped(serde_json::json!({"is_active": true}))
            }
            Err(e) => ExecutionResult::failure(format!("Failed to enable user: {e}")),
        }
    }

    async fn would_change(
        &self,
        pool: &PgPool,
        ctx: &ExecutionContext,
        target_user_id: Uuid,
        _params: &serde_json::Value,
    ) -> (bool, Option<serde_json::Value>, Option<serde_json::Value>) {
        match Self::is_user_active(pool, ctx.tenant_id, target_user_id).await {
            Ok(true) => (false, Some(serde_json::json!({"is_active": true})), None),
            Ok(false) => (
                true,
                Some(serde_json::json!({"is_active": false})),
                Some(serde_json::json!({"is_active": true})),
            ),
            Err(_) => (false, None, None),
        }
    }

    fn action_type(&self) -> &'static str {
        "enable"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_action_type() {
        let executor = EnableUserExecutor::new();
        assert_eq!(executor.action_type(), "enable");
    }
}
