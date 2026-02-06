//! Governance Scheduled Transition model.
//!
//! Tracks scheduled transitions for future execution.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status of a scheduled lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_schedule_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovScheduleStatus {
    /// Schedule is pending execution.
    Pending,
    /// Schedule has been executed.
    Executed,
    /// Schedule was cancelled.
    Cancelled,
    /// Schedule execution failed.
    Failed,
}

/// A governance scheduled transition.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovScheduledTransition {
    /// Unique identifier for the schedule.
    pub id: Uuid,

    /// The tenant this schedule belongs to.
    pub tenant_id: Uuid,

    /// The associated transition request ID.
    pub transition_request_id: Uuid,

    /// When to execute the transition.
    pub scheduled_for: DateTime<Utc>,

    /// Current status of the schedule.
    pub status: GovScheduleStatus,

    /// When the transition was actually executed.
    pub executed_at: Option<DateTime<Utc>>,

    /// When the schedule was cancelled.
    pub cancelled_at: Option<DateTime<Utc>>,

    /// User who cancelled the schedule.
    pub cancelled_by: Option<Uuid>,

    /// Error message if failed.
    pub error_message: Option<String>,

    /// When the schedule was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new scheduled transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovScheduledTransition {
    pub transition_request_id: Uuid,
    pub scheduled_for: DateTime<Utc>,
}

/// Request to update a scheduled transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovScheduledTransition {
    pub status: Option<GovScheduleStatus>,
    pub scheduled_for: Option<DateTime<Utc>>,
    pub executed_at: Option<DateTime<Utc>>,
    pub cancelled_at: Option<DateTime<Utc>>,
    pub cancelled_by: Option<Uuid>,
    pub error_message: Option<String>,
}

/// Filter options for listing scheduled transitions.
#[derive(Debug, Clone, Default)]
pub struct ScheduledTransitionFilter {
    pub status: Option<GovScheduleStatus>,
    pub scheduled_before: Option<DateTime<Utc>>,
    pub scheduled_after: Option<DateTime<Utc>>,
}

impl GovScheduledTransition {
    /// Find a schedule by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_scheduled_transitions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a schedule by transition request ID.
    pub async fn find_by_request_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        transition_request_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_scheduled_transitions
            WHERE transition_request_id = $1 AND tenant_id = $2
            ",
        )
        .bind(transition_request_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find pending schedules that are due for execution (background job).
    pub async fn find_due_for_execution(
        pool: &sqlx::PgPool,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_scheduled_transitions
            WHERE status = 'pending' AND scheduled_for <= NOW()
            ORDER BY scheduled_for ASC
            LIMIT $1
            ",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// List schedules for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ScheduledTransitionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_scheduled_transitions
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_num}"));
            param_num += 1;
        }

        if filter.scheduled_before.is_some() {
            query.push_str(&format!(" AND scheduled_for <= ${param_num}"));
            param_num += 1;
        }

        if filter.scheduled_after.is_some() {
            query.push_str(&format!(" AND scheduled_for >= ${param_num}"));
            param_num += 1;
        }

        query.push_str(&format!(
            " ORDER BY scheduled_for ASC LIMIT ${} OFFSET ${}",
            param_num,
            param_num + 1
        ));

        let mut db_query = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            db_query = db_query.bind(status);
        }

        if let Some(scheduled_before) = filter.scheduled_before {
            db_query = db_query.bind(scheduled_before);
        }

        if let Some(scheduled_after) = filter.scheduled_after {
            db_query = db_query.bind(scheduled_after);
        }

        db_query.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count schedules for a tenant with optional filters.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ScheduledTransitionFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_scheduled_transitions
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_num}"));
            param_num += 1;
        }

        if filter.scheduled_before.is_some() {
            query.push_str(&format!(" AND scheduled_for <= ${param_num}"));
            param_num += 1;
        }

        if filter.scheduled_after.is_some() {
            query.push_str(&format!(" AND scheduled_for >= ${param_num}"));
        }

        let mut db_query = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            db_query = db_query.bind(status);
        }

        if let Some(scheduled_before) = filter.scheduled_before {
            db_query = db_query.bind(scheduled_before);
        }

        if let Some(scheduled_after) = filter.scheduled_after {
            db_query = db_query.bind(scheduled_after);
        }

        db_query.fetch_one(pool).await
    }

    /// Count pending schedules for a tenant.
    pub async fn count_pending(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_scheduled_transitions
            WHERE tenant_id = $1 AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new scheduled transition.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateGovScheduledTransition,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_scheduled_transitions (
                tenant_id, transition_request_id, scheduled_for
            )
            VALUES ($1, $2, $3)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.transition_request_id)
        .bind(input.scheduled_for)
        .fetch_one(pool)
        .await
    }

    /// Update a scheduled transition.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateGovScheduledTransition,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_scheduled_transitions
            SET
                status = COALESCE($3, status),
                scheduled_for = COALESCE($4, scheduled_for),
                executed_at = COALESCE($5, executed_at),
                cancelled_at = COALESCE($6, cancelled_at),
                cancelled_by = COALESCE($7, cancelled_by),
                error_message = COALESCE($8, error_message)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.status)
        .bind(input.scheduled_for)
        .bind(input.executed_at)
        .bind(input.cancelled_at)
        .bind(input.cancelled_by)
        .bind(&input.error_message)
        .fetch_optional(pool)
        .await
    }

    /// Mark a schedule as executed.
    pub async fn mark_executed(pool: &sqlx::PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_scheduled_transitions
            SET status = 'executed', executed_at = NOW()
            WHERE id = $1 AND status = 'pending'
            ",
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark a schedule as failed.
    pub async fn mark_failed(
        pool: &sqlx::PgPool,
        id: Uuid,
        error_message: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_scheduled_transitions
            SET status = 'failed', error_message = $2
            WHERE id = $1 AND status = 'pending'
            ",
        )
        .bind(id)
        .bind(error_message)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Cancel a schedule.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        cancelled_by: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_scheduled_transitions
            SET status = 'cancelled', cancelled_at = NOW(), cancelled_by = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(cancelled_by)
        .fetch_optional(pool)
        .await
    }

    /// Reschedule a pending schedule to a new time.
    pub async fn reschedule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_scheduled_for: DateTime<Utc>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_scheduled_transitions
            SET scheduled_for = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_scheduled_for)
        .fetch_optional(pool)
        .await
    }

    /// Delete a scheduled transition (only for cancelled).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_scheduled_transitions
            WHERE id = $1 AND tenant_id = $2 AND status = 'cancelled'
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Find pending schedules that are due for execution for a specific tenant.
    pub async fn find_due_for_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_scheduled_transitions
            WHERE tenant_id = $1 AND status = 'pending' AND scheduled_for <= NOW()
            ORDER BY scheduled_for ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get all tenant IDs that have due scheduled transitions.
    pub async fn get_tenants_with_due_schedules(
        pool: &sqlx::PgPool,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT DISTINCT tenant_id FROM gov_scheduled_transitions
            WHERE status = 'pending' AND scheduled_for <= NOW()
            ",
        )
        .fetch_all(pool)
        .await
    }

    /// Find pending scheduled transitions for a specific object.
    ///
    /// Joins with `gov_state_transition_requests` to filter by `object_id`.
    pub async fn find_pending_for_object(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        object_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT s.*
            FROM gov_scheduled_transitions s
            JOIN gov_state_transition_requests r
              ON s.transition_request_id = r.id
              AND r.tenant_id = s.tenant_id
            WHERE s.tenant_id = $1
              AND r.object_id = $2
              AND s.status = 'pending'
            ORDER BY s.scheduled_for ASC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(object_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}
