//! Governance Template Event model (F058).
//!
//! Audit trail for template modifications.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::TemplateEventType;

/// An audit event for template modifications.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovTemplateEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The template this event relates to (may be NULL if template was deleted).
    pub template_id: Option<Uuid>,

    /// Type of event.
    pub event_type: TemplateEventType,

    /// User who triggered the event (may be NULL for system events).
    pub actor_id: Option<Uuid>,

    /// Details of the changes made.
    pub changes: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new template event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovTemplateEvent {
    pub template_id: Option<Uuid>,
    pub event_type: TemplateEventType,
    pub actor_id: Option<Uuid>,
    pub changes: Option<serde_json::Value>,
}

/// Filter options for listing template events.
#[derive(Debug, Clone, Default)]
pub struct TemplateChangeEventFilter {
    pub template_id: Option<Uuid>,
    pub event_type: Option<TemplateEventType>,
    pub actor_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

impl GovTemplateEvent {
    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_template_events
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all events for a template ordered by time (most recent first).
    pub async fn list_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_template_events
            WHERE tenant_id = $1 AND template_id = $2
            ORDER BY created_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_all(pool)
        .await
    }

    /// List events with filtering and pagination.
    pub async fn list_with_filter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &TemplateChangeEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_template_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.template_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND template_id = ${param_count}"));
        }
        if filter.event_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${param_count}"));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND actor_id = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(template_id) = filter.template_id {
            q = q.bind(template_id);
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

    /// List recent events for a tenant.
    pub async fn list_recent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_template_events
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Create a new template event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovTemplateEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_template_events (
                tenant_id, template_id, event_type, actor_id, changes
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.template_id)
        .bind(input.event_type)
        .bind(input.actor_id)
        .bind(&input.changes)
        .fetch_one(pool)
        .await
    }

    /// Helper to create a "created" event.
    pub async fn record_created(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
        changes: Option<serde_json::Value>,
    ) -> Result<Self, sqlx::Error> {
        let input = CreateGovTemplateEvent {
            template_id: Some(template_id),
            event_type: TemplateEventType::Created,
            actor_id: Some(actor_id),
            changes,
        };
        Self::create(pool, tenant_id, input).await
    }

    /// Helper to create an "updated" event.
    pub async fn record_updated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
        changes: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        let input = CreateGovTemplateEvent {
            template_id: Some(template_id),
            event_type: TemplateEventType::Updated,
            actor_id: Some(actor_id),
            changes: Some(changes),
        };
        Self::create(pool, tenant_id, input).await
    }

    /// Helper to create an "activated" event.
    pub async fn record_activated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
    ) -> Result<Self, sqlx::Error> {
        let input = CreateGovTemplateEvent {
            template_id: Some(template_id),
            event_type: TemplateEventType::Activated,
            actor_id: Some(actor_id),
            changes: None,
        };
        Self::create(pool, tenant_id, input).await
    }

    /// Helper to create a "disabled" event.
    pub async fn record_disabled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
    ) -> Result<Self, sqlx::Error> {
        let input = CreateGovTemplateEvent {
            template_id: Some(template_id),
            event_type: TemplateEventType::Disabled,
            actor_id: Some(actor_id),
            changes: None,
        };
        Self::create(pool, tenant_id, input).await
    }

    /// Helper to create a "deleted" event.
    pub async fn record_deleted(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
        changes: Option<serde_json::Value>,
    ) -> Result<Self, sqlx::Error> {
        let input = CreateGovTemplateEvent {
            template_id: Some(template_id),
            event_type: TemplateEventType::Deleted,
            actor_id: Some(actor_id),
            changes,
        };
        Self::create(pool, tenant_id, input).await
    }

    /// Helper to create a "`version_created`" event.
    pub async fn record_version_created(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
        version_number: i32,
    ) -> Result<Self, sqlx::Error> {
        let input = CreateGovTemplateEvent {
            template_id: Some(template_id),
            event_type: TemplateEventType::VersionCreated,
            actor_id: Some(actor_id),
            changes: Some(serde_json::json!({ "version_number": version_number })),
        };
        Self::create(pool, tenant_id, input).await
    }

    /// Helper to create a "`rule_added`" event.
    pub async fn record_rule_added(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
        rule_id: Uuid,
        rule_details: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        let input = CreateGovTemplateEvent {
            template_id: Some(template_id),
            event_type: TemplateEventType::RuleAdded,
            actor_id: Some(actor_id),
            changes: Some(serde_json::json!({
                "rule_id": rule_id,
                "details": rule_details
            })),
        };
        Self::create(pool, tenant_id, input).await
    }

    /// Helper to create a "`rule_removed`" event.
    pub async fn record_rule_removed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
        rule_id: Uuid,
    ) -> Result<Self, sqlx::Error> {
        let input = CreateGovTemplateEvent {
            template_id: Some(template_id),
            event_type: TemplateEventType::RuleRemoved,
            actor_id: Some(actor_id),
            changes: Some(serde_json::json!({ "rule_id": rule_id })),
        };
        Self::create(pool, tenant_id, input).await
    }

    /// Count events for a template.
    pub async fn count_by_template(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_template_events
            WHERE tenant_id = $1 AND template_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(template_id)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_event() {
        let template_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let input = CreateGovTemplateEvent {
            template_id: Some(template_id),
            event_type: TemplateEventType::Created,
            actor_id: Some(actor_id),
            changes: None,
        };

        assert_eq!(input.template_id, Some(template_id));
        assert_eq!(input.event_type, TemplateEventType::Created);
        assert_eq!(input.actor_id, Some(actor_id));
    }

    #[test]
    fn test_filter_default() {
        let filter = TemplateChangeEventFilter::default();
        assert!(filter.template_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.actor_id.is_none());
        assert!(filter.from_date.is_none());
        assert!(filter.to_date.is_none());
    }
}
