//! Governance Micro-certification Event model (F055).
//!
//! Represents audit trail for micro-certification lifecycle events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::MicroCertEventType;

/// Audit record of a micro-certification event.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMicroCertEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// Parent certification.
    pub micro_certification_id: Uuid,

    /// Type of event.
    pub event_type: MicroCertEventType,

    /// User who performed action (NULL for system).
    pub actor_id: Option<Uuid>,

    /// Event-specific details.
    pub details: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new micro-certification event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMicroCertEvent {
    pub micro_certification_id: Uuid,
    pub event_type: MicroCertEventType,
    pub actor_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
}

/// Filter options for listing micro-certification events.
#[derive(Debug, Clone, Default)]
pub struct MicroCertEventFilter {
    pub micro_certification_id: Option<Uuid>,
    pub event_type: Option<MicroCertEventType>,
    pub actor_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

/// Event counts by type for analytics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCertEventStats {
    pub total: i64,
    pub created: i64,
    pub reminder_sent: i64,
    pub escalated: i64,
    pub approved: i64,
    pub rejected: i64,
    pub flagged_for_review: i64,
    pub delegated: i64,
    pub auto_revoked: i64,
    pub expired: i64,
    pub skipped: i64,
}

impl GovMicroCertEvent {
    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_micro_cert_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find all events for a certification (audit trail).
    pub async fn find_by_certification(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_micro_cert_events
            WHERE tenant_id = $1 AND micro_certification_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(micro_certification_id)
        .fetch_all(pool)
        .await
    }

    /// List events with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MicroCertEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_micro_cert_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.micro_certification_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND micro_certification_id = ${}", param_count));
        }
        if filter.event_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${}", param_count));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND actor_id = ${}", param_count));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(cert_id) = filter.micro_certification_id {
            q = q.bind(cert_id);
        }
        if let Some(event_type) = filter.event_type {
            q = q.bind(event_type);
        }
        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count events with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MicroCertEventFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_micro_cert_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.micro_certification_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND micro_certification_id = ${}", param_count));
        }
        if filter.event_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${}", param_count));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND actor_id = ${}", param_count));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(cert_id) = filter.micro_certification_id {
            q = q.bind(cert_id);
        }
        if let Some(event_type) = filter.event_type {
            q = q.bind(event_type);
        }
        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.fetch_one(pool).await
    }

    /// Get event statistics for a tenant.
    pub async fn get_stats(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        from_date: DateTime<Utc>,
        to_date: DateTime<Utc>,
    ) -> Result<MicroCertEventStats, sqlx::Error> {
        let row: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE event_type = 'created') as created,
                COUNT(*) FILTER (WHERE event_type = 'reminder_sent') as reminder_sent,
                COUNT(*) FILTER (WHERE event_type = 'escalated') as escalated,
                COUNT(*) FILTER (WHERE event_type = 'approved') as approved,
                COUNT(*) FILTER (WHERE event_type = 'rejected') as rejected,
                COUNT(*) FILTER (WHERE event_type = 'flagged_for_review') as flagged_for_review,
                COUNT(*) FILTER (WHERE event_type = 'delegated') as delegated,
                COUNT(*) FILTER (WHERE event_type = 'auto_revoked') as auto_revoked,
                COUNT(*) FILTER (WHERE event_type = 'expired') as expired,
                COUNT(*) FILTER (WHERE event_type = 'skipped') as skipped
            FROM gov_micro_cert_events
            WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
            "#,
        )
        .bind(tenant_id)
        .bind(from_date)
        .bind(to_date)
        .fetch_one(pool)
        .await?;

        Ok(MicroCertEventStats {
            total: row.0,
            created: row.1,
            reminder_sent: row.2,
            escalated: row.3,
            approved: row.4,
            rejected: row.5,
            flagged_for_review: row.6,
            delegated: row.7,
            auto_revoked: row.8,
            expired: row.9,
            skipped: row.10,
        })
    }

    /// Create a new event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateMicroCertEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_micro_cert_events (
                tenant_id, micro_certification_id, event_type, actor_id, details
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.micro_certification_id)
        .bind(input.event_type)
        .bind(input.actor_id)
        .bind(&input.details)
        .fetch_one(pool)
        .await
    }

    /// Create a "created" event.
    pub async fn record_created(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        trigger_rule_id: Uuid,
        triggering_event_id: Uuid,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::Created,
                actor_id: None,
                details: Some(serde_json::json!({
                    "trigger_rule_id": trigger_rule_id,
                    "triggering_event_id": triggering_event_id
                })),
            },
        )
        .await
    }

    /// Create a "reminder_sent" event.
    pub async fn record_reminder_sent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        reviewer_id: Uuid,
        deadline: DateTime<Utc>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::ReminderSent,
                actor_id: None,
                details: Some(serde_json::json!({
                    "reviewer_id": reviewer_id,
                    "deadline": deadline
                })),
            },
        )
        .await
    }

    /// Create an "escalated" event.
    pub async fn record_escalated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        original_reviewer_id: Uuid,
        backup_reviewer_id: Uuid,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::Escalated,
                actor_id: None,
                details: Some(serde_json::json!({
                    "original_reviewer_id": original_reviewer_id,
                    "backup_reviewer_id": backup_reviewer_id
                })),
            },
        )
        .await
    }

    /// Create an "approved" event.
    pub async fn record_approved(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        decided_by: Uuid,
        comment: Option<String>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::Approved,
                actor_id: Some(decided_by),
                details: comment.map(|c| serde_json::json!({ "comment": c })),
            },
        )
        .await
    }

    /// Create a "rejected" event.
    pub async fn record_rejected(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        decided_by: Uuid,
        comment: Option<String>,
        revoked_assignment_id: Option<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        let details = serde_json::json!({
            "comment": comment,
            "revoked_assignment_id": revoked_assignment_id
        });

        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::Rejected,
                actor_id: Some(decided_by),
                details: Some(details),
            },
        )
        .await
    }

    /// Create a "flagged_for_review" event (Reduce decision).
    pub async fn record_flagged_for_review(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        decided_by: Uuid,
        comment: Option<String>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::FlaggedForReview,
                actor_id: Some(decided_by),
                details: comment.map(|c| serde_json::json!({ "comment": c })),
            },
        )
        .await
    }

    /// Create a "delegated" event.
    pub async fn record_delegated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        delegated_by: Uuid,
        delegate_to: Uuid,
        comment: Option<String>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::Delegated,
                actor_id: Some(delegated_by),
                details: Some(serde_json::json!({
                    "delegate_to": delegate_to,
                    "comment": comment
                })),
            },
        )
        .await
    }

    /// Create an "auto_revoked" event.
    pub async fn record_auto_revoked(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        deadline: DateTime<Utc>,
        revoked_assignment_id: Option<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::AutoRevoked,
                actor_id: None,
                details: Some(serde_json::json!({
                    "deadline": deadline,
                    "revoked_assignment_id": revoked_assignment_id
                })),
            },
        )
        .await
    }

    /// Create an "expired" event.
    pub async fn record_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        deadline: DateTime<Utc>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::Expired,
                actor_id: None,
                details: Some(serde_json::json!({ "deadline": deadline })),
            },
        )
        .await
    }

    /// Create a "skipped" event.
    pub async fn record_skipped(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        reason: String,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::Skipped,
                actor_id: None,
                details: Some(serde_json::json!({ "reason": reason })),
            },
        )
        .await
    }

    /// Create an "assignment_revoked" event.
    pub async fn record_assignment_revoked(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        micro_certification_id: Uuid,
        assignment_id: Uuid,
        reason: String,
        revoked_by: Option<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateMicroCertEvent {
                micro_certification_id,
                event_type: MicroCertEventType::AssignmentRevoked,
                actor_id: revoked_by,
                details: Some(serde_json::json!({
                    "assignment_id": assignment_id,
                    "reason": reason
                })),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_micro_cert_event() {
        let input = CreateMicroCertEvent {
            micro_certification_id: Uuid::new_v4(),
            event_type: MicroCertEventType::Created,
            actor_id: None,
            details: Some(serde_json::json!({"trigger_rule_id": Uuid::new_v4()})),
        };

        assert_eq!(input.event_type, MicroCertEventType::Created);
        assert!(input.actor_id.is_none());
    }

    #[test]
    fn test_filter_default() {
        let filter = MicroCertEventFilter::default();
        assert!(filter.micro_certification_id.is_none());
        assert!(filter.event_type.is_none());
    }

    #[test]
    fn test_event_stats() {
        let stats = MicroCertEventStats {
            total: 100,
            created: 50,
            reminder_sent: 10,
            escalated: 5,
            approved: 20,
            rejected: 5,
            flagged_for_review: 3,
            delegated: 2,
            auto_revoked: 3,
            expired: 2,
            skipped: 5,
        };

        assert_eq!(stats.total, 100);
        assert_eq!(stats.approved, 20);
        assert_eq!(stats.flagged_for_review, 3);
        assert_eq!(stats.delegated, 2);
    }
}
