//! AssignRole action executor for F-064: Bulk Action Engine.
//!
//! Assigns a role to a target user, skipping if the user already has the role.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::{ActionExecutor, ExecutionContext, ExecutionResult};

/// Executor for assign_role action.
pub struct AssignRoleExecutor;

impl AssignRoleExecutor {
    /// Create a new assign role executor.
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

    /// Check if the user already has the specified role.
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

    /// Revoke all sessions for a user (force re-authentication after role change).
    async fn revoke_user_sessions(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = NOW(), revoked_reason = 'security' \
             WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL AND expires_at > NOW()",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        let count = result.rows_affected();
        if count > 0 {
            tracing::info!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                revoked_count = count,
                "Revoked sessions after role assignment"
            );
        }
        Ok(count)
    }

    /// Assign the role to the user.
    async fn assign_role(pool: &PgPool, user_id: Uuid, role_name: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO user_roles (user_id, role_name, created_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (user_id, role_name) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(role_name)
        .execute(pool)
        .await?;

        Ok(())
    }
}

impl Default for AssignRoleExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ActionExecutor for AssignRoleExecutor {
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

        // Check if user already has the role
        match Self::user_has_role(pool, target_user_id, &role_name).await {
            Ok(true) => {
                return ExecutionResult::skipped(serde_json::json!({
                    "has_role": true,
                    "role_id": role_id.to_string(),
                    "role_name": role_name
                }));
            }
            Ok(false) => {
                // Proceed with assignment
            }
            Err(e) => return ExecutionResult::failure(format!("Failed to check role: {e}")),
        }

        // Assign the role
        match Self::assign_role(pool, target_user_id, &role_name).await {
            Ok(()) => {
                // Invalidate all sessions for the user so they pick up new permissions
                if let Err(e) =
                    Self::revoke_user_sessions(pool, ctx.tenant_id, target_user_id).await
                {
                    tracing::warn!(
                        user_id = %target_user_id,
                        error = %e,
                        "Failed to revoke sessions after role assignment"
                    );
                }
                ExecutionResult::success(
                    serde_json::json!({
                        "has_role": false,
                        "role_id": role_id.to_string(),
                        "role_name": role_name
                    }),
                    serde_json::json!({
                        "has_role": true,
                        "role_id": role_id.to_string(),
                        "role_name": role_name
                    }),
                )
            }
            Err(e) => ExecutionResult::failure(format!("Failed to assign role: {e}")),
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
            Ok(true) => (false, Some(serde_json::json!({"has_role": true})), None),
            Ok(false) => (
                true,
                Some(serde_json::json!({"has_role": false})),
                Some(serde_json::json!({"has_role": true})),
            ),
            Err(_) => (false, None, None),
        }
    }

    fn action_type(&self) -> &'static str {
        "assign_role"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_action_type() {
        let executor = AssignRoleExecutor::new();
        assert_eq!(executor.action_type(), "assign_role");
    }
}
