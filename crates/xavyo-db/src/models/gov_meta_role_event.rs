//! Governance Meta-role Event model (F056).
//!
//! Represents audit events for meta-role operations.

#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::MetaRoleEventType;

/// An audit event for meta-role operations.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMetaRoleEvent {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this belongs to.
    pub tenant_id: Uuid,

    /// The related meta-role (NULL for cascade events).
    pub meta_role_id: Option<Uuid>,

    /// Type of event.
    pub event_type: MetaRoleEventType,

    /// User who triggered the event (NULL for system events).
    pub actor_id: Option<Uuid>,

    /// Before/after state changes (JSON format).
    pub changes: Option<serde_json::Value>,

    /// List of affected role IDs (JSON format).
    pub affected_roles: Option<serde_json::Value>,

    /// Additional context (JSON format).
    pub metadata: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovMetaRoleEvent {
    pub meta_role_id: Option<Uuid>,
    pub event_type: MetaRoleEventType,
    pub actor_id: Option<Uuid>,
    pub changes: Option<serde_json::Value>,
    pub affected_roles: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

/// Filter options for listing events.
#[derive(Debug, Clone, Default)]
pub struct MetaRoleEventFilter {
    pub meta_role_id: Option<Uuid>,
    pub event_type: Option<MetaRoleEventType>,
    pub actor_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

/// Summary statistics for meta-role events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRoleEventStats {
    pub total: i64,
    pub created: i64,
    pub updated: i64,
    pub deleted: i64,
    pub disabled: i64,
    pub enabled: i64,
    pub inheritance_applied: i64,
    pub inheritance_removed: i64,
    pub conflict_detected: i64,
    pub conflict_resolved: i64,
    pub cascade_started: i64,
    pub cascade_completed: i64,
    pub cascade_failed: i64,
}

impl GovMetaRoleEvent {
    /// Find by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List events for a meta-role.
    pub async fn list_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_meta_role_events
            WHERE tenant_id = $1 AND meta_role_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List events with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MetaRoleEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_meta_role_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.meta_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND meta_role_id = ${}", param_count));
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

        if let Some(meta_role_id) = filter.meta_role_id {
            q = q.bind(meta_role_id);
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
        filter: &MetaRoleEventFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_meta_role_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.meta_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND meta_role_id = ${}", param_count));
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

        if let Some(meta_role_id) = filter.meta_role_id {
            q = q.bind(meta_role_id);
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

    /// Get statistics for a tenant.
    pub async fn get_stats(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<MetaRoleEventStats, sqlx::Error> {
        let row: (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE event_type = 'created') as created,
                COUNT(*) FILTER (WHERE event_type = 'updated') as updated,
                COUNT(*) FILTER (WHERE event_type = 'deleted') as deleted,
                COUNT(*) FILTER (WHERE event_type = 'disabled') as disabled,
                COUNT(*) FILTER (WHERE event_type = 'enabled') as enabled,
                COUNT(*) FILTER (WHERE event_type = 'inheritance_applied') as inheritance_applied,
                COUNT(*) FILTER (WHERE event_type = 'inheritance_removed') as inheritance_removed,
                COUNT(*) FILTER (WHERE event_type = 'conflict_detected') as conflict_detected,
                COUNT(*) FILTER (WHERE event_type = 'conflict_resolved') as conflict_resolved,
                COUNT(*) FILTER (WHERE event_type = 'cascade_started') as cascade_started,
                COUNT(*) FILTER (WHERE event_type = 'cascade_completed') as cascade_completed,
                COUNT(*) FILTER (WHERE event_type = 'cascade_failed') as cascade_failed
            FROM gov_meta_role_events
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(MetaRoleEventStats {
            total: row.0,
            created: row.1,
            updated: row.2,
            deleted: row.3,
            disabled: row.4,
            enabled: row.5,
            inheritance_applied: row.6,
            inheritance_removed: row.7,
            conflict_detected: row.8,
            conflict_resolved: row.9,
            cascade_started: row.10,
            cascade_completed: row.11,
            cascade_failed: row.12,
        })
    }

    /// Create a new event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovMetaRoleEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_meta_role_events (
                tenant_id, meta_role_id, event_type, actor_id,
                changes, affected_roles, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.meta_role_id)
        .bind(input.event_type)
        .bind(input.actor_id)
        .bind(&input.changes)
        .bind(&input.affected_roles)
        .bind(&input.metadata)
        .fetch_one(pool)
        .await
    }

    // =========================================================================
    // Helper methods for creating specific event types
    // =========================================================================

    /// Record meta-role created event.
    pub async fn record_created(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        actor_id: Uuid,
        meta_role_data: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::Created,
                actor_id: Some(actor_id),
                changes: Some(serde_json::json!({ "after": meta_role_data })),
                affected_roles: None,
                metadata: None,
            },
        )
        .await
    }

    /// Record meta-role updated event.
    pub async fn record_updated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        actor_id: Uuid,
        before: serde_json::Value,
        after: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::Updated,
                actor_id: Some(actor_id),
                changes: Some(serde_json::json!({ "before": before, "after": after })),
                affected_roles: None,
                metadata: None,
            },
        )
        .await
    }

    /// Record meta-role deleted event.
    pub async fn record_deleted(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        actor_id: Uuid,
        meta_role_data: serde_json::Value,
        affected_role_ids: Vec<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::Deleted,
                actor_id: Some(actor_id),
                changes: Some(serde_json::json!({ "before": meta_role_data })),
                affected_roles: Some(serde_json::json!(affected_role_ids)),
                metadata: None,
            },
        )
        .await
    }

    /// Record inheritance applied event.
    pub async fn record_inheritance_applied(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        child_role_id: Uuid,
        match_reason: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::InheritanceApplied,
                actor_id: None,
                changes: None,
                affected_roles: Some(serde_json::json!([child_role_id])),
                metadata: Some(serde_json::json!({ "match_reason": match_reason })),
            },
        )
        .await
    }

    /// Record cascade started event.
    pub async fn record_cascade_started(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        trigger: &str,
        expected_count: i64,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::CascadeStarted,
                actor_id: None,
                changes: None,
                affected_roles: None,
                metadata: Some(
                    serde_json::json!({ "trigger": trigger, "expected_count": expected_count }),
                ),
            },
        )
        .await
    }

    /// Record cascade completed event.
    pub async fn record_cascade_completed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        success_count: i64,
        failure_count: i64,
        duration_ms: i64,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::CascadeCompleted,
                actor_id: None,
                changes: None,
                affected_roles: None,
                metadata: Some(serde_json::json!({
                    "success_count": success_count,
                    "failure_count": failure_count,
                    "duration_ms": duration_ms
                })),
            },
        )
        .await
    }

    /// Record meta-role disabled event (T083).
    pub async fn record_disabled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        actor_id: Uuid,
        reason: Option<String>,
        affected_role_count: i64,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::Disabled,
                actor_id: Some(actor_id),
                changes: None,
                affected_roles: None,
                metadata: Some(serde_json::json!({
                    "reason": reason,
                    "affected_role_count": affected_role_count
                })),
            },
        )
        .await
    }

    /// Record meta-role enabled event (T084).
    pub async fn record_enabled(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        actor_id: Uuid,
        reactivated_role_count: i64,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::Enabled,
                actor_id: Some(actor_id),
                changes: None,
                affected_roles: None,
                metadata: Some(serde_json::json!({
                    "reactivated_role_count": reactivated_role_count
                })),
            },
        )
        .await
    }

    /// Record inheritance removed event (T086).
    pub async fn record_inheritance_removed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        child_role_id: Uuid,
        reason: &str,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::InheritanceRemoved,
                actor_id: None,
                changes: None,
                affected_roles: Some(serde_json::json!([child_role_id])),
                metadata: Some(serde_json::json!({ "reason": reason })),
            },
        )
        .await
    }

    /// Record conflict detected event (T087).
    pub async fn record_conflict_detected(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        conflict_id: Uuid,
        meta_role_a_id: Uuid,
        meta_role_b_id: Uuid,
        affected_role_id: Uuid,
        conflict_type: &str,
        conflicting_items: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_a_id),
                event_type: MetaRoleEventType::ConflictDetected,
                actor_id: None,
                changes: None,
                affected_roles: Some(serde_json::json!([affected_role_id])),
                metadata: Some(serde_json::json!({
                    "conflict_id": conflict_id,
                    "meta_role_a_id": meta_role_a_id,
                    "meta_role_b_id": meta_role_b_id,
                    "conflict_type": conflict_type,
                    "conflicting_items": conflicting_items
                })),
            },
        )
        .await
    }

    /// Record conflict resolved event (T088).
    pub async fn record_conflict_resolved(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        conflict_id: Uuid,
        meta_role_id: Uuid,
        actor_id: Uuid,
        resolution_status: &str,
        resolution_choice: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type: MetaRoleEventType::ConflictResolved,
                actor_id: Some(actor_id),
                changes: None,
                affected_roles: None,
                metadata: Some(serde_json::json!({
                    "conflict_id": conflict_id,
                    "resolution_status": resolution_status,
                    "resolution_choice": resolution_choice
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
    fn test_create_event() {
        let input = CreateGovMetaRoleEvent {
            meta_role_id: Some(Uuid::new_v4()),
            event_type: MetaRoleEventType::Created,
            actor_id: Some(Uuid::new_v4()),
            changes: Some(serde_json::json!({ "name": "Test" })),
            affected_roles: None,
            metadata: None,
        };

        assert_eq!(input.event_type, MetaRoleEventType::Created);
    }

    #[test]
    fn test_filter_default() {
        let filter = MetaRoleEventFilter::default();
        assert!(filter.meta_role_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.actor_id.is_none());
        assert!(filter.from_date.is_none());
        assert!(filter.to_date.is_none());
    }
}
