//! Governance Lifecycle Event model.
//!
//! Records HR lifecycle events (joiner, mover, leaver) for JML workflow automation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "lifecycle_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEventType {
    /// New user created/hired.
    Joiner,
    /// User attributes changed (department, role, etc.).
    Mover,
    /// User deactivated/terminated.
    Leaver,
}

impl LifecycleEventType {
    /// Check if this event type requires attributes_before.
    pub fn requires_attributes_before(&self) -> bool {
        matches!(self, Self::Mover)
    }

    /// Check if this event type requires attributes_after.
    pub fn requires_attributes_after(&self) -> bool {
        matches!(self, Self::Joiner | Self::Mover)
    }
}

/// A governance lifecycle event.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLifecycleEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The user this event affects.
    pub user_id: Uuid,

    /// Type of lifecycle event.
    pub event_type: LifecycleEventType,

    /// User attributes before the change (for mover events).
    pub attributes_before: Option<serde_json::Value>,

    /// User attributes after the change (for joiner/mover events).
    pub attributes_after: Option<serde_json::Value>,

    /// Source of the event (api, scim, trigger, webhook).
    pub source: String,

    /// When the event was fully processed.
    pub processed_at: Option<DateTime<Utc>>,

    /// When the event was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new lifecycle event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLifecycleEvent {
    pub user_id: Uuid,
    pub event_type: LifecycleEventType,
    pub attributes_before: Option<serde_json::Value>,
    pub attributes_after: Option<serde_json::Value>,
    pub source: Option<String>,
}

/// Filter options for listing lifecycle events.
#[derive(Debug, Clone, Default)]
pub struct LifecycleEventFilter {
    pub user_id: Option<Uuid>,
    pub event_type: Option<LifecycleEventType>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub processed: Option<bool>,
}

impl GovLifecycleEvent {
    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_lifecycle_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List events for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LifecycleEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_lifecycle_events
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.event_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${}", param_count));
        }
        if filter.from.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.to.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }
        if let Some(processed) = filter.processed {
            if processed {
                query.push_str(" AND processed_at IS NOT NULL");
            } else {
                query.push_str(" AND processed_at IS NULL");
            }
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovLifecycleEvent>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(event_type) = filter.event_type {
            q = q.bind(event_type);
        }
        if let Some(from) = filter.from {
            q = q.bind(from);
        }
        if let Some(to) = filter.to {
            q = q.bind(to);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count events in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &LifecycleEventFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_lifecycle_events
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${}", param_count));
        }
        if filter.event_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${}", param_count));
        }
        if filter.from.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.to.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${}", param_count));
        }
        if let Some(processed) = filter.processed {
            if processed {
                query.push_str(" AND processed_at IS NOT NULL");
            } else {
                query.push_str(" AND processed_at IS NULL");
            }
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(event_type) = filter.event_type {
            q = q.bind(event_type);
        }
        if let Some(from) = filter.from {
            q = q.bind(from);
        }
        if let Some(to) = filter.to {
            q = q.bind(to);
        }

        q.fetch_one(pool).await
    }

    /// Create a new lifecycle event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateLifecycleEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_lifecycle_events (
                tenant_id, user_id, event_type, attributes_before, attributes_after, source
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.user_id)
        .bind(input.event_type)
        .bind(&input.attributes_before)
        .bind(&input.attributes_after)
        .bind(input.source.unwrap_or_else(|| "api".to_string()))
        .fetch_one(pool)
        .await
    }

    /// Mark event as processed.
    pub async fn mark_processed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_lifecycle_events
            SET processed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND processed_at IS NULL
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if event is processed.
    pub fn is_processed(&self) -> bool {
        self.processed_at.is_some()
    }

    /// Validate the event data.
    pub fn validate(&self) -> Result<(), String> {
        if self.event_type.requires_attributes_before() && self.attributes_before.is_none() {
            return Err("Mover event requires attributes_before".to_string());
        }
        if self.event_type.requires_attributes_after() && self.attributes_after.is_none() {
            return Err("Joiner/mover event requires attributes_after".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_requirements() {
        assert!(!LifecycleEventType::Joiner.requires_attributes_before());
        assert!(LifecycleEventType::Joiner.requires_attributes_after());

        assert!(LifecycleEventType::Mover.requires_attributes_before());
        assert!(LifecycleEventType::Mover.requires_attributes_after());

        assert!(!LifecycleEventType::Leaver.requires_attributes_before());
        assert!(!LifecycleEventType::Leaver.requires_attributes_after());
    }

    #[test]
    fn test_event_type_serialization() {
        let joiner = LifecycleEventType::Joiner;
        let json = serde_json::to_string(&joiner).unwrap();
        assert_eq!(json, "\"joiner\"");

        let mover = LifecycleEventType::Mover;
        let json = serde_json::to_string(&mover).unwrap();
        assert_eq!(json, "\"mover\"");

        let leaver = LifecycleEventType::Leaver;
        let json = serde_json::to_string(&leaver).unwrap();
        assert_eq!(json, "\"leaver\"");
    }

    #[test]
    fn test_create_event_request() {
        let request = CreateLifecycleEvent {
            user_id: Uuid::new_v4(),
            event_type: LifecycleEventType::Joiner,
            attributes_before: None,
            attributes_after: Some(serde_json::json!({"department": "Engineering"})),
            source: Some("api".to_string()),
        };

        assert_eq!(request.event_type, LifecycleEventType::Joiner);
        assert!(request.attributes_after.is_some());
    }
}
