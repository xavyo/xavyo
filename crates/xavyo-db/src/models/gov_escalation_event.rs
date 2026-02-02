//! Governance Escalation Event model (F054).
//!
//! Represents audit trail of escalation occurrences.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{EscalationReason, EscalationTargetType};

/// Audit record of an escalation occurrence.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovEscalationEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The access request that was escalated.
    pub request_id: Uuid,

    /// The approval step that was escalated.
    pub step_order: i32,

    /// The escalation level number (1, 2, 3...).
    pub escalation_level: i32,

    /// The original approver before escalation.
    pub original_approver_id: Option<Uuid>,

    /// Type of escalation target.
    pub escalation_target_type: EscalationTargetType,

    /// Resolved target user IDs.
    pub escalation_target_ids: Vec<Uuid>,

    /// Reason for escalation.
    pub reason: EscalationReason,

    /// Deadline that was exceeded.
    pub previous_deadline: Option<DateTime<Utc>>,

    /// New deadline after escalation.
    pub new_deadline: Option<DateTime<Utc>>,

    /// Additional context as JSON.
    pub metadata: Option<serde_json::Value>,

    /// When the escalation occurred.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new escalation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEscalationEvent {
    pub request_id: Uuid,
    pub step_order: i32,
    pub escalation_level: i32,
    pub original_approver_id: Option<Uuid>,
    pub escalation_target_type: EscalationTargetType,
    pub escalation_target_ids: Vec<Uuid>,
    pub reason: EscalationReason,
    pub previous_deadline: Option<DateTime<Utc>>,
    pub new_deadline: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}

/// Filter options for listing escalation events.
#[derive(Debug, Clone, Default)]
pub struct EscalationEventFilter {
    pub request_id: Option<Uuid>,
    pub original_approver_id: Option<Uuid>,
    pub escalation_target_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub reason: Option<EscalationReason>,
}

impl GovEscalationEvent {
    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_escalation_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find all events for a request (escalation history).
    pub async fn find_by_request(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        request_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_escalation_events
            WHERE tenant_id = $1 AND request_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_all(pool)
        .await
    }

    /// List events with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &EscalationEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_escalation_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.request_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND request_id = ${}", param_count));
        }
        if filter.original_approver_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND original_approver_id = ${}", param_count));
        }
        if filter.escalation_target_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND ${} = ANY(escalation_target_ids)",
                param_count
            ));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }
        if filter.reason.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND reason = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(request_id) = filter.request_id {
            q = q.bind(request_id);
        }
        if let Some(approver_id) = filter.original_approver_id {
            q = q.bind(approver_id);
        }
        if let Some(target_id) = filter.escalation_target_id {
            q = q.bind(target_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }
        if let Some(reason) = filter.reason {
            q = q.bind(reason);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count events with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &EscalationEventFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_escalation_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.request_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND request_id = ${}", param_count));
        }
        if filter.original_approver_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND original_approver_id = ${}", param_count));
        }
        if filter.escalation_target_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND ${} = ANY(escalation_target_ids)",
                param_count
            ));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }
        if filter.reason.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND reason = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(request_id) = filter.request_id {
            q = q.bind(request_id);
        }
        if let Some(approver_id) = filter.original_approver_id {
            q = q.bind(approver_id);
        }
        if let Some(target_id) = filter.escalation_target_id {
            q = q.bind(target_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }
        if let Some(reason) = filter.reason {
            q = q.bind(reason);
        }

        q.fetch_one(pool).await
    }

    /// Create a new escalation event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateEscalationEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_escalation_events (
                tenant_id, request_id, step_order, escalation_level,
                original_approver_id, escalation_target_type, escalation_target_ids,
                reason, previous_deadline, new_deadline, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.request_id)
        .bind(input.step_order)
        .bind(input.escalation_level)
        .bind(input.original_approver_id)
        .bind(input.escalation_target_type)
        .bind(&input.escalation_target_ids)
        .bind(input.reason)
        .bind(input.previous_deadline)
        .bind(input.new_deadline)
        .bind(&input.metadata)
        .fetch_one(pool)
        .await
    }

    /// Get escalation statistics for a tenant.
    pub async fn get_stats(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        from_date: DateTime<Utc>,
        to_date: DateTime<Utc>,
    ) -> Result<EscalationStats, sqlx::Error> {
        let row: (i64, i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE reason = 'timeout') as timeout_count,
                COUNT(*) FILTER (WHERE reason = 'manual_escalation') as manual_count,
                COUNT(*) FILTER (WHERE reason = 'target_unavailable') as unavailable_count
            FROM gov_escalation_events
            WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
            "#,
        )
        .bind(tenant_id)
        .bind(from_date)
        .bind(to_date)
        .fetch_one(pool)
        .await?;

        Ok(EscalationStats {
            total: row.0,
            timeout_count: row.1,
            manual_count: row.2,
            unavailable_count: row.3,
        })
    }

    /// Get most frequently escalated approvers.
    pub async fn get_top_escalated_approvers(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        from_date: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<(Uuid, i64)>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT original_approver_id, COUNT(*) as count
            FROM gov_escalation_events
            WHERE tenant_id = $1
              AND created_at >= $2
              AND original_approver_id IS NOT NULL
            GROUP BY original_approver_id
            ORDER BY count DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(from_date)
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

/// Statistics about escalation events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationStats {
    pub total: i64,
    pub timeout_count: i64,
    pub manual_count: i64,
    pub unavailable_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_escalation_event() {
        let input = CreateEscalationEvent {
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 1,
            original_approver_id: Some(Uuid::new_v4()),
            escalation_target_type: EscalationTargetType::Manager,
            escalation_target_ids: vec![Uuid::new_v4()],
            reason: EscalationReason::Timeout,
            previous_deadline: Some(Utc::now()),
            new_deadline: Some(Utc::now() + chrono::Duration::hours(24)),
            metadata: None,
        };

        assert_eq!(input.escalation_level, 1);
        assert_eq!(input.reason, EscalationReason::Timeout);
    }

    #[test]
    fn test_filter_default() {
        let filter = EscalationEventFilter::default();
        assert!(filter.request_id.is_none());
        assert!(filter.from_date.is_none());
    }
}
