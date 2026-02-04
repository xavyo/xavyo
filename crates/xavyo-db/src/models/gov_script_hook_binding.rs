//! Script Hook Binding model (F066).
//! Links provisioning scripts to connectors with execution configuration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_script_types::{FailurePolicy, GovHookPhase, ScriptOperationType};

/// A binding that links a provisioning script to a connector with execution configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovScriptHookBinding {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this binding belongs to.
    pub tenant_id: Uuid,

    /// The provisioning script to execute.
    pub script_id: Uuid,

    /// The connector this binding applies to.
    pub connector_id: Uuid,

    /// When to execute relative to the provisioning operation.
    pub hook_phase: GovHookPhase,

    /// The provisioning operation type that triggers execution.
    pub operation_type: ScriptOperationType,

    /// Order of execution when multiple scripts are bound to the same hook.
    pub execution_order: i32,

    /// What to do when the script fails.
    pub failure_policy: FailurePolicy,

    /// Maximum number of retry attempts (when `failure_policy` is Retry).
    pub max_retries: i32,

    /// Maximum execution time in seconds before timeout.
    pub timeout_seconds: i32,

    /// Whether this binding is active.
    pub enabled: bool,

    /// When this binding was created.
    pub created_at: DateTime<Utc>,

    /// When this binding was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a script hook binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScriptHookBinding {
    pub tenant_id: Uuid,
    pub script_id: Uuid,
    pub connector_id: Uuid,
    pub hook_phase: GovHookPhase,
    pub operation_type: ScriptOperationType,
    pub execution_order: i32,
    pub failure_policy: FailurePolicy,
    pub max_retries: i32,
    pub timeout_seconds: i32,
}

/// Request to partially update a script hook binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateScriptHookBinding {
    pub execution_order: Option<i32>,
    pub failure_policy: Option<FailurePolicy>,
    pub max_retries: Option<i32>,
    pub timeout_seconds: Option<i32>,
    pub enabled: Option<bool>,
}

/// Filter options for listing bindings.
#[derive(Debug, Clone, Default)]
pub struct BindingFilter {
    pub connector_id: Option<Uuid>,
    pub script_id: Option<Uuid>,
    pub hook_phase: Option<GovHookPhase>,
    pub operation_type: Option<ScriptOperationType>,
    pub enabled: Option<bool>,
}

impl GovScriptHookBinding {
    /// Create a new script hook binding.
    pub async fn create(
        pool: &sqlx::PgPool,
        params: &CreateScriptHookBinding,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_script_hook_bindings (
                tenant_id, script_id, connector_id, hook_phase,
                operation_type, execution_order, failure_policy,
                max_retries, timeout_seconds
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            ",
        )
        .bind(params.tenant_id)
        .bind(params.script_id)
        .bind(params.connector_id)
        .bind(params.hook_phase)
        .bind(params.operation_type)
        .bind(params.execution_order)
        .bind(params.failure_policy)
        .bind(params.max_retries)
        .bind(params.timeout_seconds)
        .fetch_one(pool)
        .await
    }

    /// Find a binding by ID within a tenant.
    pub async fn get_by_id(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_script_hook_bindings
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List bindings for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &BindingFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_script_hook_bindings WHERE tenant_id = $1");
        let mut count_query =
            String::from("SELECT COUNT(*) FROM gov_script_hook_bindings WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.connector_id.is_some() {
            param_count += 1;
            let clause = format!(" AND connector_id = ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }
        if filter.script_id.is_some() {
            param_count += 1;
            let clause = format!(" AND script_id = ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }
        if filter.hook_phase.is_some() {
            param_count += 1;
            let clause = format!(" AND hook_phase = ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }
        if filter.operation_type.is_some() {
            param_count += 1;
            let clause = format!(" AND operation_type = ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }
        if filter.enabled.is_some() {
            param_count += 1;
            let clause = format!(" AND enabled = ${param_count}");
            query.push_str(&clause);
            count_query.push_str(&clause);
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        // Build and execute the count query.
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(connector_id) = filter.connector_id {
            cq = cq.bind(connector_id);
        }
        if let Some(script_id) = filter.script_id {
            cq = cq.bind(script_id);
        }
        if let Some(hook_phase) = filter.hook_phase {
            cq = cq.bind(hook_phase);
        }
        if let Some(operation_type) = filter.operation_type {
            cq = cq.bind(operation_type);
        }
        if let Some(enabled) = filter.enabled {
            cq = cq.bind(enabled);
        }
        let total = cq.fetch_one(pool).await?;

        // Build and execute the data query.
        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);
        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(script_id) = filter.script_id {
            q = q.bind(script_id);
        }
        if let Some(hook_phase) = filter.hook_phase {
            q = q.bind(hook_phase);
        }
        if let Some(operation_type) = filter.operation_type {
            q = q.bind(operation_type);
        }
        if let Some(enabled) = filter.enabled {
            q = q.bind(enabled);
        }
        let rows = q.bind(limit).bind(offset).fetch_all(pool).await?;

        Ok((rows, total))
    }

    /// List all bindings for a connector, ordered by `hook_phase`, `operation_type`, `execution_order`.
    pub async fn list_by_connector(
        pool: &sqlx::PgPool,
        connector_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_script_hook_bindings
            WHERE connector_id = $1 AND tenant_id = $2
            ORDER BY hook_phase, operation_type, execution_order
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List all bindings for a script.
    pub async fn list_by_script(
        pool: &sqlx::PgPool,
        script_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_script_hook_bindings
            WHERE script_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            ",
        )
        .bind(script_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get enabled bindings for a specific connector, hook phase, and operation type.
    ///
    /// This is the HOT PATH query used during provisioning execution.
    /// Returns bindings ordered by `execution_order` for sequential execution.
    pub async fn list_for_execution(
        pool: &sqlx::PgPool,
        connector_id: Uuid,
        hook_phase: GovHookPhase,
        operation_type: ScriptOperationType,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_script_hook_bindings
            WHERE connector_id = $1
              AND hook_phase = $2
              AND operation_type = $3
              AND tenant_id = $4
              AND enabled = true
            ORDER BY execution_order
            ",
        )
        .bind(connector_id)
        .bind(hook_phase)
        .bind(operation_type)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Partially update a script hook binding.
    pub async fn update(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
        params: &UpdateScriptHookBinding,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_script_hook_bindings
            SET
                execution_order = COALESCE($3, execution_order),
                failure_policy = COALESCE($4, failure_policy),
                max_retries = COALESCE($5, max_retries),
                timeout_seconds = COALESCE($6, timeout_seconds),
                enabled = COALESCE($7, enabled),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(params.execution_order)
        .bind(params.failure_policy)
        .bind(params.max_retries)
        .bind(params.timeout_seconds)
        .bind(params.enabled)
        .fetch_optional(pool)
        .await
    }

    /// Delete a binding. Returns true if a row was deleted.
    pub async fn delete(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_script_hook_bindings
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count bindings for a specific connector, hook phase, and operation type.
    ///
    /// Used to enforce the maximum bindings per hook limit.
    pub async fn count_by_connector_phase(
        pool: &sqlx::PgPool,
        connector_id: Uuid,
        hook_phase: GovHookPhase,
        operation_type: ScriptOperationType,
        tenant_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_script_hook_bindings
            WHERE connector_id = $1
              AND hook_phase = $2
              AND operation_type = $3
              AND tenant_id = $4
            ",
        )
        .bind(connector_id)
        .bind(hook_phase)
        .bind(operation_type)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Check if a script has any enabled bindings.
    pub async fn has_active_bindings(
        pool: &sqlx::PgPool,
        script_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_script_hook_bindings
            WHERE script_id = $1
              AND tenant_id = $2
              AND enabled = true
            ",
        )
        .bind(script_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_input() {
        let input = CreateScriptHookBinding {
            tenant_id: Uuid::new_v4(),
            script_id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            hook_phase: GovHookPhase::Before,
            operation_type: ScriptOperationType::Create,
            execution_order: 1,
            failure_policy: FailurePolicy::Abort,
            max_retries: 3,
            timeout_seconds: 30,
        };

        assert_eq!(input.hook_phase, GovHookPhase::Before);
        assert_eq!(input.operation_type, ScriptOperationType::Create);
        assert_eq!(input.failure_policy, FailurePolicy::Abort);
        assert_eq!(input.execution_order, 1);
        assert_eq!(input.max_retries, 3);
        assert_eq!(input.timeout_seconds, 30);
    }

    #[test]
    fn test_update_input_defaults() {
        let update = UpdateScriptHookBinding {
            execution_order: None,
            failure_policy: None,
            max_retries: None,
            timeout_seconds: None,
            enabled: None,
        };

        assert!(update.execution_order.is_none());
        assert!(update.failure_policy.is_none());
        assert!(update.enabled.is_none());
    }

    #[test]
    fn test_update_input_partial() {
        let update = UpdateScriptHookBinding {
            execution_order: Some(5),
            failure_policy: Some(FailurePolicy::Continue),
            max_retries: None,
            timeout_seconds: Some(60),
            enabled: Some(false),
        };

        assert_eq!(update.execution_order, Some(5));
        assert_eq!(update.failure_policy, Some(FailurePolicy::Continue));
        assert!(update.max_retries.is_none());
        assert_eq!(update.timeout_seconds, Some(60));
        assert_eq!(update.enabled, Some(false));
    }

    #[test]
    fn test_binding_filter_default() {
        let filter = BindingFilter::default();

        assert!(filter.connector_id.is_none());
        assert!(filter.script_id.is_none());
        assert!(filter.hook_phase.is_none());
        assert!(filter.operation_type.is_none());
        assert!(filter.enabled.is_none());
    }

    #[test]
    fn test_binding_filter_with_values() {
        let connector_id = Uuid::new_v4();
        let filter = BindingFilter {
            connector_id: Some(connector_id),
            script_id: None,
            hook_phase: Some(GovHookPhase::After),
            operation_type: Some(ScriptOperationType::Delete),
            enabled: Some(true),
        };

        assert_eq!(filter.connector_id, Some(connector_id));
        assert!(filter.script_id.is_none());
        assert_eq!(filter.hook_phase, Some(GovHookPhase::After));
        assert_eq!(filter.operation_type, Some(ScriptOperationType::Delete));
        assert_eq!(filter.enabled, Some(true));
    }
}
