//! Governance Lifecycle Action model.
//!
//! Records actions taken as result of lifecycle events (provision, revoke, schedule).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of lifecycle action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "lifecycle_action_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LifecycleActionType {
    /// Create new assignment.
    Provision,
    /// Immediate revocation.
    Revoke,
    /// Scheduled future revocation.
    ScheduleRevoke,
    /// Cancel scheduled revocation.
    CancelRevoke,
    /// Skipped (duplicate, already assigned).
    Skip,
}

impl LifecycleActionType {
    /// Check if this action type creates an assignment.
    #[must_use] 
    pub fn creates_assignment(&self) -> bool {
        matches!(self, Self::Provision)
    }

    /// Check if this action type removes an assignment.
    #[must_use] 
    pub fn removes_assignment(&self) -> bool {
        matches!(self, Self::Revoke)
    }

    /// Check if this action type is a scheduled action.
    #[must_use] 
    pub fn is_scheduled(&self) -> bool {
        matches!(self, Self::ScheduleRevoke)
    }

    /// Check if this action type can be cancelled.
    #[must_use] 
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::ScheduleRevoke)
    }
}

/// A governance lifecycle action.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLifecycleAction {
    /// Unique identifier for the action.
    pub id: Uuid,

    /// The tenant this action belongs to.
    pub tenant_id: Uuid,

    /// The event that triggered this action.
    pub event_id: Uuid,

    /// Type of action.
    pub action_type: LifecycleActionType,

    /// The assignment created/modified (if applicable).
    pub assignment_id: Option<Uuid>,

    /// The policy that triggered this action (if applicable).
    pub policy_id: Option<Uuid>,

    /// The target entitlement.
    pub entitlement_id: Uuid,

    /// When scheduled revocation should execute.
    pub scheduled_at: Option<DateTime<Utc>>,

    /// When action was executed.
    pub executed_at: Option<DateTime<Utc>>,

    /// When scheduled action was cancelled.
    pub cancelled_at: Option<DateTime<Utc>>,

    /// Error message if action failed.
    pub error_message: Option<String>,

    /// When the action was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new lifecycle action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLifecycleAction {
    pub event_id: Uuid,
    pub action_type: LifecycleActionType,
    pub assignment_id: Option<Uuid>,
    pub policy_id: Option<Uuid>,
    pub entitlement_id: Uuid,
    pub scheduled_at: Option<DateTime<Utc>>,
}

/// Filter options for listing lifecycle actions.
#[derive(Debug, Clone, Default)]
pub struct LifecycleActionFilter {
    pub event_id: Option<Uuid>,
    pub action_type: Option<LifecycleActionType>,
    pub assignment_id: Option<Uuid>,
    pub pending: Option<bool>,
}

impl GovLifecycleAction {
    /// Find an action by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_actions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List actions for an event.
    pub async fn list_by_event(
        pool: &sqlx::PgPool,
        event_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_actions
            WHERE event_id = $1
            ORDER BY created_at ASC
            ",
        )
        .bind(event_id)
        .fetch_all(pool)
        .await
    }

    /// List actions for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LifecycleActionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_lifecycle_actions
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.event_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_id = ${param_count}"));
        }
        if filter.action_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND action_type = ${param_count}"));
        }
        if filter.assignment_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assignment_id = ${param_count}"));
        }
        if let Some(pending) = filter.pending {
            if pending {
                query.push_str(" AND scheduled_at IS NOT NULL AND executed_at IS NULL AND cancelled_at IS NULL");
            }
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovLifecycleAction>(&query).bind(tenant_id);

        if let Some(event_id) = filter.event_id {
            q = q.bind(event_id);
        }
        if let Some(action_type) = filter.action_type {
            q = q.bind(action_type);
        }
        if let Some(assignment_id) = filter.assignment_id {
            q = q.bind(assignment_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count actions in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LifecycleActionFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_lifecycle_actions
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.event_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_id = ${param_count}"));
        }
        if filter.action_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND action_type = ${param_count}"));
        }
        if filter.assignment_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assignment_id = ${param_count}"));
        }
        if let Some(pending) = filter.pending {
            if pending {
                query.push_str(" AND scheduled_at IS NOT NULL AND executed_at IS NULL AND cancelled_at IS NULL");
            }
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(event_id) = filter.event_id {
            q = q.bind(event_id);
        }
        if let Some(action_type) = filter.action_type {
            q = q.bind(action_type);
        }
        if let Some(assignment_id) = filter.assignment_id {
            q = q.bind(assignment_id);
        }

        q.fetch_one(pool).await
    }

    /// List pending scheduled revocations that are due.
    pub async fn list_due_revocations(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        before: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_lifecycle_actions
            WHERE tenant_id = $1
              AND action_type = 'schedule_revoke'
              AND scheduled_at <= $2
              AND executed_at IS NULL
              AND cancelled_at IS NULL
            ORDER BY scheduled_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(before)
        .fetch_all(pool)
        .await
    }

    /// Create a new lifecycle action.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateLifecycleAction,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_lifecycle_actions (
                tenant_id, event_id, action_type, assignment_id, policy_id, entitlement_id, scheduled_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.event_id)
        .bind(input.action_type)
        .bind(input.assignment_id)
        .bind(input.policy_id)
        .bind(input.entitlement_id)
        .bind(input.scheduled_at)
        .fetch_one(pool)
        .await
    }

    /// Mark action as executed.
    pub async fn mark_executed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_actions
            SET executed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND executed_at IS NULL AND cancelled_at IS NULL
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Cancel a scheduled action.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_actions
            SET cancelled_at = NOW()
            WHERE id = $1 AND tenant_id = $2
              AND action_type = 'schedule_revoke'
              AND executed_at IS NULL
              AND cancelled_at IS NULL
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Record an error for the action.
    pub async fn record_error(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_lifecycle_actions
            SET error_message = $3
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

    /// Check if action is pending (scheduled but not executed/cancelled).
    #[must_use] 
    pub fn is_pending(&self) -> bool {
        self.scheduled_at.is_some() && self.executed_at.is_none() && self.cancelled_at.is_none()
    }

    /// Check if action is executed.
    #[must_use] 
    pub fn is_executed(&self) -> bool {
        self.executed_at.is_some()
    }

    /// Check if action is cancelled.
    #[must_use] 
    pub fn is_cancelled(&self) -> bool {
        self.cancelled_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type_methods() {
        assert!(LifecycleActionType::Provision.creates_assignment());
        assert!(!LifecycleActionType::Revoke.creates_assignment());

        assert!(LifecycleActionType::Revoke.removes_assignment());
        assert!(!LifecycleActionType::Provision.removes_assignment());

        assert!(LifecycleActionType::ScheduleRevoke.is_scheduled());
        assert!(!LifecycleActionType::Revoke.is_scheduled());

        assert!(LifecycleActionType::ScheduleRevoke.can_cancel());
        assert!(!LifecycleActionType::Revoke.can_cancel());
    }

    #[test]
    fn test_action_type_serialization() {
        let provision = LifecycleActionType::Provision;
        let json = serde_json::to_string(&provision).unwrap();
        assert_eq!(json, "\"provision\"");

        let schedule = LifecycleActionType::ScheduleRevoke;
        let json = serde_json::to_string(&schedule).unwrap();
        assert_eq!(json, "\"schedule_revoke\"");
    }
}
