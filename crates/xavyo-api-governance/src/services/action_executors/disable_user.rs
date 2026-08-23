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

    /// Check if the user is currently active. `None` if the user is not in this tenant.
    async fn is_user_active(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<bool>, sqlx::Error> {
        let result: Option<(bool,)> =
            sqlx::query_as("SELECT is_active FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_optional(pool)
                .await?;

        Ok(result.map(|(active,)| active))
    }

    /// Disable the user.
    async fn disable_user(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE users SET is_active = false, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND is_active = true
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Terminate all active sessions for the user.
    async fn terminate_sessions(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i32, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE sessions SET revoked_at = NOW()
            WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
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
        ctx: &ExecutionContext,
        target_user_id: Uuid,
        _params: &serde_json::Value,
    ) -> ExecutionResult {
        let tenant_id = ctx.tenant_id;
        // Check current state
        match Self::is_user_active(pool, tenant_id, target_user_id).await {
            Ok(Some(false)) => {
                // User already disabled - skip
                return ExecutionResult::skipped(serde_json::json!({"is_active": false}));
            }
            Ok(Some(true)) => {
                // Proceed with disable
            }
            Ok(None) => return ExecutionResult::failure("User not found"),
            Err(e) => return ExecutionResult::failure(format!("Failed to check user status: {e}")),
        }

        // Disable the user
        match Self::disable_user(pool, tenant_id, target_user_id).await {
            Ok(true) => {
                // Also terminate sessions
                let sessions_terminated =
                    match Self::terminate_sessions(pool, tenant_id, target_user_id).await {
                        Ok(n) => n,
                        Err(e) => {
                            return ExecutionResult::failure(format!(
                                "Failed to terminate sessions after disable: {e}"
                            ));
                        }
                    };

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
        ctx: &ExecutionContext,
        target_user_id: Uuid,
        _params: &serde_json::Value,
    ) -> (bool, Option<serde_json::Value>, Option<serde_json::Value>) {
        match Self::is_user_active(pool, ctx.tenant_id, target_user_id).await {
            Ok(Some(false)) => (false, Some(serde_json::json!({"is_active": false})), None),
            Ok(Some(true)) => (
                true,
                Some(serde_json::json!({"is_active": true})),
                Some(serde_json::json!({"is_active": false})),
            ),
            Ok(None) | Err(_) => (false, None, None),
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

    #[test]
    fn disable_user_does_not_swallow_session_terminate() {
        let src = include_str!("disable_user.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("Failed to terminate sessions after disable: {e}"),
            "session terminate errors must fail the action"
        );
        assert!(
            !production.contains("unwrap_or(0)"),
            "must not treat session terminate errors as zero sessions"
        );
    }

    #[test]
    fn missing_user_is_not_treated_as_inactive() {
        let src = include_str!("disable_user.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("Ok(None) => return ExecutionResult::failure(\"User not found\")"),
            "missing users must fail, not skip as already disabled"
        );
        assert!(
            !production.contains("unwrap_or(false)"),
            "must not treat a missing user as inactive"
        );
    }
}
