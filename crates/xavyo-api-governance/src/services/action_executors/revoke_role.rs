//! RevokeRole action executor for F-064: Bulk Action Engine.
//!
//! Revokes a role from a target user, skipping if the user doesn't have the role.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::{ActionExecutor, ExecutionContext, ExecutionResult};

/// Executor for revoke_role action.
pub struct RevokeRoleExecutor;

impl RevokeRoleExecutor {
    /// Create a new revoke role executor.
    pub fn new() -> Self {
        Self
    }

    /// Get role name from gov_roles by role_id and tenant_id.
    async fn get_role_name(pool: &PgPool, tenant_id: Uuid, role_id: Uuid) -> Option<String> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT name FROM gov_roles WHERE id = $1 AND tenant_id = $2")
                .bind(role_id)
                .bind(tenant_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();

        result.map(|(name,)| name)
    }

    /// Check if the user has the specified role.
    async fn user_has_role(
        pool: &PgPool,
        user_id: Uuid,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM user_roles
            WHERE user_id = $1 AND role_name = $2
            "#,
        )
        .bind(user_id)
        .bind(role_name)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    /// Revoke the role from the user.
    async fn revoke_role(
        pool: &PgPool,
        user_id: Uuid,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM user_roles
            WHERE user_id = $1 AND role_name = $2
            "#,
        )
        .bind(user_id)
        .bind(role_name)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

impl Default for RevokeRoleExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ActionExecutor for RevokeRoleExecutor {
    async fn execute(
        &self,
        pool: &PgPool,
        ctx: &ExecutionContext,
        target_user_id: Uuid,
        params: &serde_json::Value,
    ) -> ExecutionResult {
        // Extract role_id from params
        let role_id = match params.get("role_id").and_then(|v| v.as_str()) {
            Some(id) => match Uuid::parse_str(id) {
                Ok(uuid) => uuid,
                Err(_) => return ExecutionResult::failure("Invalid role_id format"),
            },
            None => return ExecutionResult::failure("Missing role_id parameter"),
        };

        // Resolve role_id to role_name via gov_roles
        let role_name = match Self::get_role_name(pool, ctx.tenant_id, role_id).await {
            Some(name) => name,
            None => return ExecutionResult::failure("Role not found for the given tenant"),
        };

        // Check if user has the role
        match Self::user_has_role(pool, target_user_id, &role_name).await {
            Ok(false) => {
                return ExecutionResult::skipped(serde_json::json!({
                    "has_role": false,
                    "role_id": role_id.to_string(),
                    "role_name": role_name
                }));
            }
            Ok(true) => {
                // Proceed with revocation
            }
            Err(e) => return ExecutionResult::failure(format!("Failed to check role: {e}")),
        }

        // Revoke the role
        match Self::revoke_role(pool, target_user_id, &role_name).await {
            Ok(true) => ExecutionResult::success(
                serde_json::json!({
                    "has_role": true,
                    "role_id": role_id.to_string(),
                    "role_name": role_name
                }),
                serde_json::json!({
                    "has_role": false,
                    "role_id": role_id.to_string(),
                    "role_name": role_name
                }),
            ),
            Ok(false) => {
                // Race condition - role was already removed
                ExecutionResult::skipped(serde_json::json!({
                    "has_role": false,
                    "role_id": role_id.to_string()
                }))
            }
            Err(e) => ExecutionResult::failure(format!("Failed to revoke role: {e}")),
        }
    }

    async fn would_change(
        &self,
        pool: &PgPool,
        ctx: &ExecutionContext,
        target_user_id: Uuid,
        params: &serde_json::Value,
    ) -> (bool, Option<serde_json::Value>, Option<serde_json::Value>) {
        let role_id = match params.get("role_id").and_then(|v| v.as_str()) {
            Some(id) => match Uuid::parse_str(id) {
                Ok(uuid) => uuid,
                Err(_) => return (false, None, None),
            },
            None => return (false, None, None),
        };

        let role_name = match Self::get_role_name(pool, ctx.tenant_id, role_id).await {
            Some(name) => name,
            None => return (false, None, None),
        };

        match Self::user_has_role(pool, target_user_id, &role_name).await {
            Ok(true) => (
                true,
                Some(serde_json::json!({"has_role": true})),
                Some(serde_json::json!({"has_role": false})),
            ),
            Ok(false) => (false, Some(serde_json::json!({"has_role": false})), None),
            Err(_) => (false, None, None),
        }
    }

    fn action_type(&self) -> &'static str {
        "revoke_role"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_action_type() {
        let executor = RevokeRoleExecutor::new();
        assert_eq!(executor.action_type(), "revoke_role");
    }
}
