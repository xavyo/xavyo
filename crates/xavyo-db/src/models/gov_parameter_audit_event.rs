//! Parameter Audit Event model (F057).
//!
//! Represents audit trail entries for parameter value changes.

#![allow(clippy::too_many_arguments)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_role_parameter_types::ParameterEventType;

/// An audit event for parameter changes.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovParameterAuditEvent {
    /// Unique identifier for the audit event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The assignment the event relates to.
    pub assignment_id: Uuid,

    /// Type of parameter event.
    pub event_type: ParameterEventType,

    /// The user who triggered the event (null for system events).
    pub actor_id: Option<Uuid>,

    /// Previous parameter values (JSONB).
    pub old_values: Option<serde_json::Value>,

    /// New parameter values (JSONB).
    pub new_values: Option<serde_json::Value>,

    /// Additional metadata (JSONB).
    pub metadata: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Filter options for querying audit events.
#[derive(Debug, Clone, Default)]
pub struct ParameterAuditFilter {
    pub assignment_id: Option<Uuid>,
    pub event_type: Option<ParameterEventType>,
    pub actor_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

impl GovParameterAuditEvent {
    /// Find an audit event by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_parameter_audit_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all audit events for an assignment.
    pub async fn list_by_assignment(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_parameter_audit_events
            WHERE tenant_id = $1 AND assignment_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .fetch_all(pool)
        .await
    }

    /// List recent audit events for a tenant.
    pub async fn list_recent(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_parameter_audit_events
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Query audit events with filtering.
    pub async fn query(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ParameterAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query =
            String::from("SELECT * FROM gov_parameter_audit_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.assignment_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assignment_id = ${}", param_count));
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

        if let Some(assignment_id) = filter.assignment_id {
            q = q.bind(assignment_id);
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

    /// Count audit events with filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ParameterAuditFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_parameter_audit_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.assignment_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assignment_id = ${}", param_count));
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

        if let Some(assignment_id) = filter.assignment_id {
            q = q.bind(assignment_id);
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

    /// Create a new audit event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        event_type: ParameterEventType,
        actor_id: Option<Uuid>,
        old_values: Option<serde_json::Value>,
        new_values: Option<serde_json::Value>,
        metadata: Option<serde_json::Value>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_parameter_audit_events (
                tenant_id, assignment_id, event_type, actor_id,
                old_values, new_values, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .bind(event_type)
        .bind(actor_id)
        .bind(&old_values)
        .bind(&new_values)
        .bind(&metadata)
        .fetch_one(pool)
        .await
    }

    /// Record a parameters_set event.
    pub async fn record_parameters_set(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        actor_id: Uuid,
        values: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            assignment_id,
            ParameterEventType::ParametersSet,
            Some(actor_id),
            None,
            Some(values),
            None,
        )
        .await
    }

    /// Record a parameters_updated event.
    pub async fn record_parameters_updated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        actor_id: Uuid,
        old_values: serde_json::Value,
        new_values: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            assignment_id,
            ParameterEventType::ParametersUpdated,
            Some(actor_id),
            Some(old_values),
            Some(new_values),
            None,
        )
        .await
    }

    /// Record a validation_failed event.
    pub async fn record_validation_failed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        actor_id: Option<Uuid>,
        attempted_values: serde_json::Value,
        validation_errors: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            assignment_id,
            ParameterEventType::ValidationFailed,
            actor_id,
            None,
            Some(attempted_values),
            Some(validation_errors),
        )
        .await
    }

    /// Record a schema_violation_flagged event.
    pub async fn record_schema_violation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        assignment_id: Uuid,
        current_values: serde_json::Value,
        violations: serde_json::Value,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            assignment_id,
            ParameterEventType::SchemaViolationFlagged,
            None, // System-triggered
            Some(current_values),
            None,
            Some(violations),
        )
        .await
    }

    /// Delete old audit events (for cleanup/retention).
    pub async fn delete_before(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        before: DateTime<Utc>,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_parameter_audit_events
            WHERE tenant_id = $1 AND created_at < $2
            "#,
        )
        .bind(tenant_id)
        .bind(before)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_default() {
        let filter = ParameterAuditFilter::default();
        assert!(filter.assignment_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.actor_id.is_none());
        assert!(filter.from_date.is_none());
        assert!(filter.to_date.is_none());
    }

    #[test]
    fn test_filter_with_values() {
        let assignment_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let filter = ParameterAuditFilter {
            assignment_id: Some(assignment_id),
            event_type: Some(ParameterEventType::ParametersSet),
            actor_id: Some(actor_id),
            from_date: None,
            to_date: None,
        };

        assert_eq!(filter.assignment_id, Some(assignment_id));
        assert_eq!(filter.event_type, Some(ParameterEventType::ParametersSet));
        assert_eq!(filter.actor_id, Some(actor_id));
    }

    #[test]
    fn test_values_serialization() {
        let old_values = serde_json::json!({
            "database_name": "old_db",
            "access_level": "read"
        });
        let new_values = serde_json::json!({
            "database_name": "new_db",
            "access_level": "write"
        });

        assert!(old_values.is_object());
        assert!(new_values.is_object());
        assert_eq!(old_values["database_name"], "old_db");
        assert_eq!(new_values["access_level"], "write");
    }
}
