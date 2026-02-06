//! Manual Provisioning Task model for semi-manual resources (F064).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_semi_manual_types::{ManualTaskOperation, ManualTaskStatus};

/// A manual provisioning task created when entitlements are assigned to semi-manual resources.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovManualProvisioningTask {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this task belongs to.
    pub tenant_id: Uuid,

    /// The assignment this task is for.
    pub assignment_id: Uuid,

    /// The semi-manual application.
    pub application_id: Uuid,

    /// User receiving access.
    pub user_id: Uuid,

    /// Entitlement being provisioned.
    pub entitlement_id: Uuid,

    /// Type of operation (grant, revoke, modify).
    pub operation_type: ManualTaskOperation,

    /// Current task status.
    pub status: ManualTaskStatus,

    /// Reference to external ticket (if created).
    pub external_ticket_id: Option<Uuid>,

    /// SLA deadline.
    pub sla_deadline: Option<DateTime<Utc>>,

    /// Whether SLA warning was sent.
    pub sla_warning_sent: bool,

    /// Whether SLA was breached.
    pub sla_breached: bool,

    /// IT staff assigned to this task.
    pub assignee_id: Option<Uuid>,

    /// Fulfillment notes.
    pub notes: Option<String>,

    /// Ticket creation retry count.
    pub retry_count: i32,

    /// When to retry ticket creation.
    pub next_retry_at: Option<DateTime<Utc>>,

    /// Last error message.
    pub error_message: Option<String>,

    /// When the task was created.
    pub created_at: DateTime<Utc>,

    /// When the task was last updated.
    pub updated_at: DateTime<Utc>,

    /// When the task was completed.
    pub completed_at: Option<DateTime<Utc>>,
}

/// Request to create a manual task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateManualTask {
    pub assignment_id: Uuid,
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub entitlement_id: Uuid,
    pub operation_type: ManualTaskOperation,
    pub sla_deadline: Option<DateTime<Utc>>,
}

/// Filter options for listing tasks.
#[derive(Debug, Clone, Default)]
pub struct ManualTaskFilter {
    pub status: Option<Vec<ManualTaskStatus>>,
    pub application_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub assignment_id: Option<Uuid>,
    pub sla_breached: Option<bool>,
    pub assignee_id: Option<Uuid>,
}

impl GovManualProvisioningTask {
    /// Calculate time remaining until SLA breach.
    #[must_use]
    pub fn time_remaining_seconds(&self, now: DateTime<Utc>) -> Option<i64> {
        self.sla_deadline
            .map(|deadline| (deadline - now).num_seconds())
    }

    /// Check if task is approaching SLA warning threshold.
    #[must_use]
    pub fn is_approaching_warning(&self, warning_time: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        if self.sla_warning_sent || self.status.is_terminal() {
            return false;
        }
        now >= warning_time
    }

    /// Find by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_manual_provisioning_tasks
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find by assignment ID.
    pub async fn find_by_assignment(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_manual_provisioning_tasks
            WHERE tenant_id = $1 AND assignment_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .fetch_optional(pool)
        .await
    }

    /// List tasks for a tenant with filtering.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ManualTaskFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_manual_provisioning_tasks
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.application_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND application_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.assignment_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assignment_id = ${param_count}"));
        }
        if filter.sla_breached.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND sla_breached = ${param_count}"));
        }
        if filter.assignee_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assignee_id = ${param_count}"));
        }
        // Note: status filtering with array is handled separately

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(application_id) = filter.application_id {
            q = q.bind(application_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(assignment_id) = filter.assignment_id {
            q = q.bind(assignment_id);
        }
        if let Some(sla_breached) = filter.sla_breached {
            q = q.bind(sla_breached);
        }
        if let Some(assignee_id) = filter.assignee_id {
            q = q.bind(assignee_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count tasks for a tenant.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ManualTaskFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_manual_provisioning_tasks
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.application_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND application_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.sla_breached.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND sla_breached = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(application_id) = filter.application_id {
            q = q.bind(application_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(sla_breached) = filter.sla_breached {
            q = q.bind(sla_breached);
        }

        q.fetch_one(pool).await
    }

    /// Create a new task.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateManualTask,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_manual_provisioning_tasks (
                tenant_id, assignment_id, application_id, user_id,
                entitlement_id, operation_type, sla_deadline
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.assignment_id)
        .bind(input.application_id)
        .bind(input.user_id)
        .bind(input.entitlement_id)
        .bind(input.operation_type)
        .bind(input.sla_deadline)
        .fetch_one(pool)
        .await
    }

    /// Update task status.
    pub async fn update_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: ManualTaskStatus,
    ) -> Result<Option<Self>, sqlx::Error> {
        let completed_at = if status.is_terminal() {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query_as(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET status = $3, completed_at = COALESCE($4, completed_at), updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .bind(completed_at)
        .fetch_optional(pool)
        .await
    }

    /// Set external ticket reference.
    pub async fn set_external_ticket(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        external_ticket_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET external_ticket_id = $3, status = 'ticket_created', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(external_ticket_id)
        .fetch_optional(pool)
        .await
    }

    /// Record ticket creation failure and schedule retry.
    pub async fn record_ticket_failure(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
        next_retry_at: Option<DateTime<Utc>>,
    ) -> Result<Option<Self>, sqlx::Error> {
        let new_status = if next_retry_at.is_some() {
            ManualTaskStatus::TicketFailed
        } else {
            ManualTaskStatus::FailedPermanent
        };

        sqlx::query_as(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET
                status = $3,
                retry_count = retry_count + 1,
                error_message = $4,
                next_retry_at = $5,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_status)
        .bind(error_message)
        .bind(next_retry_at)
        .fetch_optional(pool)
        .await
    }

    /// Confirm task completion.
    pub async fn confirm(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        notes: Option<&str>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET
                status = 'completed',
                notes = COALESCE($3, notes),
                completed_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(notes)
        .fetch_optional(pool)
        .await
    }

    /// Reject a task.
    pub async fn reject(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        reason: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET
                status = 'rejected',
                notes = $3,
                completed_at = NOW(),
                updated_at = NOW()
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

    /// Cancel a task.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        reason: Option<&str>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET
                status = 'cancelled',
                notes = COALESCE($3, notes),
                completed_at = NOW(),
                updated_at = NOW()
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

    /// Mark SLA warning as sent.
    pub async fn mark_sla_warning_sent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET sla_warning_sent = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark SLA as breached.
    pub async fn mark_sla_breached(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET sla_breached = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find tasks pending retry.
    pub async fn find_pending_retry(
        pool: &sqlx::PgPool,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_manual_provisioning_tasks
            WHERE status IN ('pending', 'pending_ticket', 'ticket_failed')
              AND (next_retry_at IS NULL OR next_retry_at <= $1)
            ORDER BY next_retry_at ASC NULLS FIRST
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            ",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find tasks needing SLA warning.
    pub async fn find_pending_sla_warning(
        pool: &sqlx::PgPool,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_manual_provisioning_tasks
            WHERE status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')
              AND sla_deadline IS NOT NULL
              AND sla_warning_sent = false
              AND sla_deadline > $1
            ORDER BY sla_deadline ASC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            ",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find tasks that have breached SLA.
    pub async fn find_sla_breached(
        pool: &sqlx::PgPool,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_manual_provisioning_tasks
            WHERE status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')
              AND sla_deadline IS NOT NULL
              AND sla_deadline <= $1
              AND sla_breached = false
            ORDER BY sla_deadline ASC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            ",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get dashboard metrics for a tenant.
    pub async fn get_dashboard_metrics(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<DashboardMetrics, sqlx::Error> {
        let row = sqlx::query_as::<_, DashboardMetricsRow>(
            r"
            SELECT
                COUNT(*) FILTER (WHERE status IN ('pending', 'pending_ticket', 'ticket_created', 'ticket_failed')) as pending_count,
                COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress_count,
                COUNT(*) FILTER (WHERE sla_warning_sent = true AND status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')) as sla_at_risk_count,
                COUNT(*) FILTER (WHERE sla_breached = true AND status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')) as sla_breached_count,
                COUNT(*) FILTER (WHERE status = 'completed' AND DATE(completed_at) = CURRENT_DATE) as completed_today,
                AVG(EXTRACT(EPOCH FROM (completed_at - created_at))) FILTER (WHERE status = 'completed' AND completed_at IS NOT NULL) as avg_completion_time
            FROM gov_manual_provisioning_tasks
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(DashboardMetrics {
            pending_count: row.pending_count.unwrap_or(0),
            in_progress_count: row.in_progress_count.unwrap_or(0),
            sla_at_risk_count: row.sla_at_risk_count.unwrap_or(0),
            sla_breached_count: row.sla_breached_count.unwrap_or(0),
            completed_today: row.completed_today.unwrap_or(0),
            average_completion_time_seconds: row.avg_completion_time,
        })
    }
}

/// Raw row for dashboard metrics query.
#[derive(Debug, FromRow)]
struct DashboardMetricsRow {
    pending_count: Option<i64>,
    in_progress_count: Option<i64>,
    sla_at_risk_count: Option<i64>,
    sla_breached_count: Option<i64>,
    completed_today: Option<i64>,
    avg_completion_time: Option<f64>,
}

/// Dashboard metrics for manual tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMetrics {
    pub pending_count: i64,
    pub in_progress_count: i64,
    pub sla_at_risk_count: i64,
    pub sla_breached_count: i64,
    pub completed_today: i64,
    pub average_completion_time_seconds: Option<f64>,
}

/// Item in the retry queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryQueueItem {
    pub task_id: Uuid,
    pub operation: ManualTaskOperation,
    pub retry_count: i32,
    pub next_retry_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_remaining_seconds() {
        let now = Utc::now();
        let deadline = now + chrono::Duration::hours(2);

        let task = GovManualProvisioningTask {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            assignment_id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            operation_type: ManualTaskOperation::Grant,
            status: ManualTaskStatus::Pending,
            external_ticket_id: None,
            sla_deadline: Some(deadline),
            sla_warning_sent: false,
            sla_breached: false,
            assignee_id: None,
            notes: None,
            retry_count: 0,
            next_retry_at: None,
            error_message: None,
            created_at: now,
            updated_at: now,
            completed_at: None,
        };

        let remaining = task.time_remaining_seconds(now);
        assert!(remaining.is_some());
        // Approximately 2 hours (7200 seconds)
        assert!(remaining.unwrap() > 7100 && remaining.unwrap() <= 7200);
    }

    #[test]
    fn test_create_input() {
        let input = CreateManualTask {
            assignment_id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            operation_type: ManualTaskOperation::Grant,
            sla_deadline: None,
        };

        assert_eq!(input.operation_type, ManualTaskOperation::Grant);
    }

    #[test]
    fn test_dashboard_metrics() {
        let metrics = DashboardMetrics {
            pending_count: 5,
            in_progress_count: 3,
            sla_at_risk_count: 2,
            sla_breached_count: 1,
            completed_today: 10,
            average_completion_time_seconds: Some(3600.0),
        };

        assert_eq!(metrics.pending_count, 5);
        assert_eq!(metrics.average_completion_time_seconds, Some(3600.0));
    }
}
