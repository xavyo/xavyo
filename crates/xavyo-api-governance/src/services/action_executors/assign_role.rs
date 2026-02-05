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

    /// Check if the user already has the specified role.
    async fn user_has_role(
        pool: &PgPool,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM user_roles
            WHERE user_id = $1 AND role_id = $2
            "#,
        )
        .bind(user_id)
        .bind(role_id)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    /// Assign the role to the user.
    async fn assign_role(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        granted_by: Uuid,
        justification: &str,
    ) -> Result<(), sqlx::Error> {
        let assignment_id = Uuid::new_v4();

        sqlx::query(
            r#"
            INSERT INTO user_roles (id, tenant_id, user_id, role_id, granted_by, granted_at, justification, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), $6, NOW())
            ON CONFLICT (user_id, role_id) DO NOTHING
            "#,
        )
        .bind(assignment_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(role_id)
        .bind(granted_by)
        .bind(justification)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get role name for logging.
    async fn get_role_name(pool: &PgPool, role_id: Uuid) -> Option<String> {
        let result: Option<(String,)> = sqlx::query_as("SELECT name FROM gov_roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

        result.map(|(name,)| name)
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

        // Check if user already has the role
        match Self::user_has_role(pool, target_user_id, role_id).await {
            Ok(true) => {
                // User already has the role - skip
                let role_name = Self::get_role_name(pool, role_id).await;
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
        match Self::assign_role(
            pool,
            ctx.tenant_id,
            target_user_id,
            role_id,
            ctx.initiated_by,
            &ctx.justification,
        )
        .await
        {
            Ok(()) => {
                let role_name = Self::get_role_name(pool, role_id).await;
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
        _ctx: &ExecutionContext,
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

        match Self::user_has_role(pool, target_user_id, role_id).await {
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
