//! Manual Task Audit Event model for semi-manual resources (F064).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Audit event types for manual tasks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualTaskEventType {
    /// Task was created.
    TaskCreated,
    /// Ticket was created in external system.
    TicketCreated,
    /// Ticket creation failed.
    TicketCreationFailed,
    /// Ticket creation was retried.
    TicketRetried,
    /// Ticket status was updated from external system.
    TicketStatusUpdated,
    /// Task was confirmed manually.
    TaskConfirmed,
    /// Task was rejected.
    TaskRejected,
    /// Task was cancelled.
    TaskCancelled,
    /// SLA warning was sent.
    SlaWarningSent,
    /// SLA was breached.
    SlaBreached,
    /// Task status changed.
    StatusChanged,
    /// Webhook callback received.
    WebhookReceived,
}

impl ManualTaskEventType {
    /// Get the string representation for storage.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TaskCreated => "task_created",
            Self::TicketCreated => "ticket_created",
            Self::TicketCreationFailed => "ticket_creation_failed",
            Self::TicketRetried => "ticket_retried",
            Self::TicketStatusUpdated => "ticket_status_updated",
            Self::TaskConfirmed => "task_confirmed",
            Self::TaskRejected => "task_rejected",
            Self::TaskCancelled => "task_cancelled",
            Self::SlaWarningSent => "sla_warning_sent",
            Self::SlaBreached => "sla_breached",
            Self::StatusChanged => "status_changed",
            Self::WebhookReceived => "webhook_received",
        }
    }
}

impl std::fmt::Display for ManualTaskEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An audit event for manual task operations.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovManualTaskAuditEvent {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The task this event is for.
    pub task_id: Uuid,

    /// Type of event.
    pub event_type: String,

    /// Who performed the action (if applicable).
    pub actor_id: Option<Uuid>,

    /// Additional event details.
    pub details: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Request to create an audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateManualTaskAuditEvent {
    pub task_id: Uuid,
    pub event_type: ManualTaskEventType,
    pub actor_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
}

impl GovManualTaskAuditEvent {
    /// Get the typed event type.
    #[must_use]
    pub fn typed_event_type(&self) -> Option<ManualTaskEventType> {
        match self.event_type.as_str() {
            "task_created" => Some(ManualTaskEventType::TaskCreated),
            "ticket_created" => Some(ManualTaskEventType::TicketCreated),
            "ticket_creation_failed" => Some(ManualTaskEventType::TicketCreationFailed),
            "ticket_retried" => Some(ManualTaskEventType::TicketRetried),
            "ticket_status_updated" => Some(ManualTaskEventType::TicketStatusUpdated),
            "task_confirmed" => Some(ManualTaskEventType::TaskConfirmed),
            "task_rejected" => Some(ManualTaskEventType::TaskRejected),
            "task_cancelled" => Some(ManualTaskEventType::TaskCancelled),
            "sla_warning_sent" => Some(ManualTaskEventType::SlaWarningSent),
            "sla_breached" => Some(ManualTaskEventType::SlaBreached),
            "status_changed" => Some(ManualTaskEventType::StatusChanged),
            "webhook_received" => Some(ManualTaskEventType::WebhookReceived),
            _ => None,
        }
    }

    /// Create a new audit event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateManualTaskAuditEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_manual_task_audit_events (
                tenant_id, task_id, event_type, actor_id, details
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.task_id)
        .bind(input.event_type.as_str())
        .bind(input.actor_id)
        .bind(&input.details)
        .fetch_one(pool)
        .await
    }

    /// List events for a task.
    pub async fn list_by_task(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_manual_task_audit_events
            WHERE tenant_id = $1 AND task_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(task_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count events for a task.
    pub async fn count_by_task(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_manual_task_audit_events
            WHERE tenant_id = $1 AND task_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(task_id)
        .fetch_one(pool)
        .await
    }

    /// Helper: Log task created event.
    pub async fn log_task_created(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
        actor_id: Option<Uuid>,
        details: Option<serde_json::Value>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::TaskCreated,
                actor_id,
                details,
            },
        )
        .await
    }

    /// Helper: Log ticket created event.
    pub async fn log_ticket_created(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
        external_reference: &str,
        external_url: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        let details = serde_json::json!({
            "external_reference": external_reference,
            "external_url": external_url,
        });

        Self::create(
            pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::TicketCreated,
                actor_id: None,
                details: Some(details),
            },
        )
        .await
    }

    /// Helper: Log ticket creation failure.
    pub async fn log_ticket_creation_failed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
        error: &str,
        retry_count: i32,
    ) -> Result<Self, sqlx::Error> {
        let details = serde_json::json!({
            "error": error,
            "retry_count": retry_count,
        });

        Self::create(
            pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::TicketCreationFailed,
                actor_id: None,
                details: Some(details),
            },
        )
        .await
    }

    /// Helper: Log task confirmed event.
    pub async fn log_task_confirmed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
        actor_id: Uuid,
        notes: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        let details = notes.map(|n| serde_json::json!({ "notes": n }));

        Self::create(
            pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::TaskConfirmed,
                actor_id: Some(actor_id),
                details,
            },
        )
        .await
    }

    /// Helper: Log task rejected event.
    pub async fn log_task_rejected(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
        actor_id: Uuid,
        reason: &str,
    ) -> Result<Self, sqlx::Error> {
        let details = serde_json::json!({ "reason": reason });

        Self::create(
            pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::TaskRejected,
                actor_id: Some(actor_id),
                details: Some(details),
            },
        )
        .await
    }

    /// Helper: Log SLA warning sent.
    pub async fn log_sla_warning(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
        time_remaining_seconds: i64,
    ) -> Result<Self, sqlx::Error> {
        let details = serde_json::json!({
            "time_remaining_seconds": time_remaining_seconds,
        });

        Self::create(
            pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::SlaWarningSent,
                actor_id: None,
                details: Some(details),
            },
        )
        .await
    }

    /// Helper: Log SLA breach.
    pub async fn log_sla_breached(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        task_id: Uuid,
        overdue_seconds: i64,
    ) -> Result<Self, sqlx::Error> {
        let details = serde_json::json!({
            "overdue_seconds": overdue_seconds,
        });

        Self::create(
            pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::SlaBreached,
                actor_id: None,
                details: Some(details),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_as_str() {
        assert_eq!(ManualTaskEventType::TaskCreated.as_str(), "task_created");
        assert_eq!(
            ManualTaskEventType::TicketCreated.as_str(),
            "ticket_created"
        );
        assert_eq!(ManualTaskEventType::SlaBreached.as_str(), "sla_breached");
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(ManualTaskEventType::TaskCreated.to_string(), "task_created");
    }

    #[test]
    fn test_create_input() {
        let input = CreateManualTaskAuditEvent {
            task_id: Uuid::new_v4(),
            event_type: ManualTaskEventType::TaskCreated,
            actor_id: Some(Uuid::new_v4()),
            details: Some(serde_json::json!({"key": "value"})),
        };

        assert_eq!(input.event_type, ManualTaskEventType::TaskCreated);
    }
}
