//! DisableUser action executor for F-064: Bulk Action Engine.
//!
//! Disables an active user account and terminates their sessions.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::{ActionExecutor, ExecutionContext, ExecutionResult};

/// Executor for disable action.
pub struct DisableUserExecutor;

impl DisableUserExecutor {
    /// Create a new disable user executor.
    pub fn new() -> Self {
        Self
    }

    /// Check if the user is currently active.
    async fn is_user_active(pool: &PgPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
        let result: Option<(bool,)> = sqlx::query_as("SELECT is_active FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;

        Ok(result.map(|(active,)| active).unwrap_or(false))
    }

    /// Disable the user.
    async fn disable_user(pool: &PgPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE users SET is_active = false, updated_at = NOW()
            WHERE id = $1 AND is_active = true
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Terminate all active sessions for the user.
    async fn terminate_sessions(pool: &PgPool, user_id: Uuid) -> Result<i32, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE sessions SET revoked_at = NOW()
            WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() as i32)
    }
}

impl Default for DisableUserExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ActionExecutor for DisableUserExecutor {
    async fn execute(
        &self,
        pool: &PgPool,
        _ctx: &ExecutionContext,
        target_user_id: Uuid,
        _params: &serde_json::Value,
    ) -> ExecutionResult {
        // Check current state
        match Self::is_user_active(pool, target_user_id).await {
            Ok(false) => {
                // User already disabled - skip
                return ExecutionResult::skipped(serde_json::json!({"is_active": false}));
            }
            Ok(true) => {
                // Proceed with disable
            }
            Err(e) => return ExecutionResult::failure(format!("Failed to check user status: {e}")),
        }

        // Disable the user
        match Self::disable_user(pool, target_user_id).await {
            Ok(true) => {
                // Also terminate sessions
                let sessions_terminated = Self::terminate_sessions(pool, target_user_id)
                    .await
                    .unwrap_or(0);

                ExecutionResult::success(
                    serde_json::json!({"is_active": true}),
                    serde_json::json!({
                        "is_active": false,
                        "sessions_terminated": sessions_terminated
                    }),
                )
            }
            Ok(false) => {
                // Race condition or user not found
                ExecutionResult::skipped(serde_json::json!({"is_active": false}))
            }
            Err(e) => ExecutionResult::failure(format!("Failed to disable user: {e}")),
        }
    }

    async fn would_change(
        &self,
        pool: &PgPool,
        _ctx: &ExecutionContext,
        target_user_id: Uuid,
        _params: &serde_json::Value,
    ) -> (bool, Option<serde_json::Value>, Option<serde_json::Value>) {
        match Self::is_user_active(pool, target_user_id).await {
            Ok(false) => (false, Some(serde_json::json!({"is_active": false})), None),
            Ok(true) => (
                true,
                Some(serde_json::json!({"is_active": true})),
                Some(serde_json::json!({"is_active": false})),
            ),
            Err(_) => (false, None, None),
        }
    }

    fn action_type(&self) -> &'static str {
        "disable"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_action_type() {
        let executor = DisableUserExecutor::new();
        assert_eq!(executor.action_type(), "disable");
    }
}
