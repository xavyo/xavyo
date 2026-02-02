//! Script Audit Event model (F066).
//! Immutable audit trail for script lifecycle actions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::gov_script_types::ScriptAuditAction;

/// An immutable audit event recording a script lifecycle action.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovScriptAuditEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The script involved (nullable - scripts can be deleted).
    pub script_id: Option<Uuid>,

    /// The action performed.
    pub action: ScriptAuditAction,

    /// Who performed the action.
    pub actor_id: Uuid,

    /// Additional details as JSONB.
    pub details: Option<serde_json::Value>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new script audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScriptAuditEvent {
    pub tenant_id: Uuid,
    pub script_id: Option<Uuid>,
    pub action: ScriptAuditAction,
    pub actor_id: Uuid,
    pub details: Option<serde_json::Value>,
}

/// Filter options for listing script audit events.
#[derive(Debug, Clone, Default)]
pub struct ScriptAuditFilter {
    pub script_id: Option<Uuid>,
    pub action: Option<ScriptAuditAction>,
    pub actor_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

impl GovScriptAuditEvent {
    /// Create a new script audit event (immutable, insert only).
    pub async fn create(
        pool: &sqlx::PgPool,
        params: &CreateScriptAuditEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_script_audit_events (
                tenant_id, script_id, action, actor_id, details
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(params.tenant_id)
        .bind(params.script_id)
        .bind(params.action)
        .bind(params.actor_id)
        .bind(&params.details)
        .fetch_one(pool)
        .await
    }

    /// List audit events for a tenant with filtering and pagination.
    ///
    /// Returns a tuple of (events, total_count).
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ScriptAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let mut base_where = String::from(" FROM gov_script_audit_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.script_id.is_some() {
            param_count += 1;
            base_where.push_str(&format!(" AND script_id = ${}", param_count));
        }
        if filter.action.is_some() {
            param_count += 1;
            base_where.push_str(&format!(" AND action = ${}", param_count));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            base_where.push_str(&format!(" AND actor_id = ${}", param_count));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            base_where.push_str(&format!(" AND created_at >= ${}", param_count));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            base_where.push_str(&format!(" AND created_at <= ${}", param_count));
        }

        // Count query
        let count_query = format!("SELECT COUNT(*){}", base_where);
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(script_id) = filter.script_id {
            count_q = count_q.bind(script_id);
        }
        if let Some(action) = filter.action {
            count_q = count_q.bind(action);
        }
        if let Some(actor_id) = filter.actor_id {
            count_q = count_q.bind(actor_id);
        }
        if let Some(from_date) = filter.from_date {
            count_q = count_q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            count_q = count_q.bind(to_date);
        }

        let total = count_q.fetch_one(pool).await?;

        // Data query
        let data_query = format!(
            "SELECT *{} ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            base_where,
            param_count + 1,
            param_count + 2
        );
        let mut data_q = sqlx::query_as::<_, Self>(&data_query).bind(tenant_id);

        if let Some(script_id) = filter.script_id {
            data_q = data_q.bind(script_id);
        }
        if let Some(action) = filter.action {
            data_q = data_q.bind(action);
        }
        if let Some(actor_id) = filter.actor_id {
            data_q = data_q.bind(actor_id);
        }
        if let Some(from_date) = filter.from_date {
            data_q = data_q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            data_q = data_q.bind(to_date);
        }

        let events = data_q.bind(limit).bind(offset).fetch_all(pool).await?;

        Ok((events, total))
    }

    /// List audit events for a specific script with pagination.
    ///
    /// Returns a tuple of (events, total_count).
    pub async fn list_by_script(
        pool: &sqlx::PgPool,
        script_id: Uuid,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_script_audit_events
            WHERE tenant_id = $1 AND script_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(script_id)
        .fetch_one(pool)
        .await?;

        let events = sqlx::query_as(
            r#"
            SELECT * FROM gov_script_audit_events
            WHERE tenant_id = $1 AND script_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(script_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok((events, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_script_audit_event_request() {
        let input = CreateScriptAuditEvent {
            tenant_id: Uuid::new_v4(),
            script_id: Some(Uuid::new_v4()),
            action: ScriptAuditAction::Created,
            actor_id: Uuid::new_v4(),
            details: Some(serde_json::json!({"name": "my_script"})),
        };

        assert!(input.script_id.is_some());
        assert_eq!(input.action, ScriptAuditAction::Created);
    }

    #[test]
    fn test_create_script_audit_event_without_script() {
        let input = CreateScriptAuditEvent {
            tenant_id: Uuid::new_v4(),
            script_id: None,
            action: ScriptAuditAction::Deleted,
            actor_id: Uuid::new_v4(),
            details: None,
        };

        assert!(input.script_id.is_none());
        assert!(input.details.is_none());
        assert_eq!(input.action, ScriptAuditAction::Deleted);
    }

    #[test]
    fn test_filter_default() {
        let filter = ScriptAuditFilter::default();
        assert!(filter.script_id.is_none());
        assert!(filter.action.is_none());
        assert!(filter.actor_id.is_none());
        assert!(filter.from_date.is_none());
        assert!(filter.to_date.is_none());
    }

    #[test]
    fn test_filter_with_values() {
        let script_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let now = Utc::now();

        let filter = ScriptAuditFilter {
            script_id: Some(script_id),
            action: Some(ScriptAuditAction::Activated),
            actor_id: Some(actor_id),
            from_date: Some(now - chrono::Duration::days(7)),
            to_date: Some(now),
        };

        assert_eq!(filter.script_id, Some(script_id));
        assert_eq!(filter.action, Some(ScriptAuditAction::Activated));
        assert_eq!(filter.actor_id, Some(actor_id));
        assert!(filter.from_date.is_some());
        assert!(filter.to_date.is_some());
    }

    #[test]
    fn test_details_serialization() {
        let details = serde_json::json!({
            "previous_status": "draft",
            "new_status": "active",
            "version": 3
        });

        assert!(details.is_object());
        assert_eq!(details["previous_status"], "draft");
        assert_eq!(details["new_status"], "active");
        assert_eq!(details["version"], 3);
    }
}
