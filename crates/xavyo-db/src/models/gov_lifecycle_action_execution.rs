//! Governance Lifecycle Action Execution model.
//!
//! Records the execution of entry/exit actions during state transitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of action trigger (entry or exit).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ActionTriggerType {
    /// Action triggered on state entry.
    #[default]
    Entry,
    /// Action triggered on state exit.
    Exit,
}

/// Status of action execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ActionExecutionStatus {
    /// Action is pending execution.
    #[default]
    Pending,
    /// Action executed successfully.
    Success,
    /// Action execution failed.
    Failed,
    /// Action was skipped.
    Skipped,
}

/// A governance lifecycle action execution record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLifecycleActionExecution {
    /// Unique identifier for the execution.
    pub id: Uuid,

    /// The tenant this execution belongs to.
    pub tenant_id: Uuid,

    /// The transition audit ID that triggered this action.
    pub transition_audit_id: Uuid,

    /// The state this action belongs to.
    pub state_id: Uuid,

    /// Type of action (e.g., disable_access, notify_manager).
    pub action_type: String,

    /// Action configuration.
    pub action_config: serde_json::Value,

    /// Whether this was an entry or exit action.
    pub trigger_type: String,

    /// Current status of the execution.
    pub status: String,

    /// When the action was executed.
    pub executed_at: Option<DateTime<Utc>>,

    /// Error message if execution failed.
    pub error_message: Option<String>,

    /// When the execution record was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new action execution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLifecycleActionExecution {
    pub transition_audit_id: Uuid,
    pub state_id: Uuid,
    pub action_type: String,
    pub action_config: serde_json::Value,
    pub trigger_type: ActionTriggerType,
}

/// Filter options for listing action executions.
#[derive(Debug, Clone, Default)]
pub struct ActionExecutionFilter {
    pub transition_audit_id: Option<Uuid>,
    pub state_id: Option<Uuid>,
    pub action_type: Option<String>,
    pub status: Option<String>,
}

impl GovLifecycleActionExecution {
    /// Find an execution by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_action_executions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List executions for a transition audit.
    pub async fn list_by_audit(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        transition_audit_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_action_executions
            WHERE transition_audit_id = $1 AND tenant_id = $2
            ORDER BY created_at ASC
            ",
        )
        .bind(transition_audit_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List executions for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ActionExecutionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_lifecycle_action_executions
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.transition_audit_id.is_some() {
            query.push_str(&format!(" AND transition_audit_id = ${param_num}"));
            param_num += 1;
        }

        if filter.state_id.is_some() {
            query.push_str(&format!(" AND state_id = ${param_num}"));
            param_num += 1;
        }

        if filter.action_type.is_some() {
            query.push_str(&format!(" AND action_type = ${param_num}"));
            param_num += 1;
        }

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_num}"));
            param_num += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_num,
            param_num + 1
        ));

        let mut db_query = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(transition_audit_id) = filter.transition_audit_id {
            db_query = db_query.bind(transition_audit_id);
        }

        if let Some(state_id) = filter.state_id {
            db_query = db_query.bind(state_id);
        }

        if let Some(action_type) = &filter.action_type {
            db_query = db_query.bind(action_type);
        }

        if let Some(status) = &filter.status {
            db_query = db_query.bind(status);
        }

        db_query.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Create a new action execution record.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateGovLifecycleActionExecution,
    ) -> Result<Self, sqlx::Error> {
        let trigger_type = match input.trigger_type {
            ActionTriggerType::Entry => "entry",
            ActionTriggerType::Exit => "exit",
        };

        sqlx::query_as(
            r"
            INSERT INTO gov_lifecycle_action_executions (
                tenant_id, transition_audit_id, state_id, action_type, action_config, trigger_type
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.transition_audit_id)
        .bind(input.state_id)
        .bind(&input.action_type)
        .bind(&input.action_config)
        .bind(trigger_type)
        .fetch_one(pool)
        .await
    }

    /// Mark an execution as successful.
    pub async fn mark_success(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_action_executions
            SET status = 'success', executed_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark an execution as failed.
    pub async fn mark_failed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_action_executions
            SET status = 'failed', executed_at = NOW(), error_message = $3
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error_message)
        .fetch_optional(pool)
        .await
    }

    /// Mark an execution as skipped.
    pub async fn mark_skipped(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        reason: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_action_executions
            SET status = 'skipped', executed_at = NOW(), error_message = $3
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(reason)
        .fetch_optional(pool)
        .await
    }

    /// Count pending executions for a tenant.
    pub async fn count_pending(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_lifecycle_action_executions
            WHERE tenant_id = $1 AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Check if action is pending.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }

    /// Check if action succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status == "success"
    }

    /// Check if action failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.status == "failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trigger_type_serialization() {
        let entry = ActionTriggerType::Entry;
        let json = serde_json::to_string(&entry).unwrap();
        assert_eq!(json, "\"entry\"");

        let exit = ActionTriggerType::Exit;
        let json = serde_json::to_string(&exit).unwrap();
        assert_eq!(json, "\"exit\"");
    }

    #[test]
    fn test_execution_status_serialization() {
        let pending = ActionExecutionStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let success = ActionExecutionStatus::Success;
        let json = serde_json::to_string(&success).unwrap();
        assert_eq!(json, "\"success\"");
    }
}
