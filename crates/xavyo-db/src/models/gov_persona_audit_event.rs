//! Governance Persona Audit Event model (F063).
//!
//! Immutable audit trail for all persona-related actions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::PersonaAuditEventType;

/// A persona audit event - immutable record of persona actions.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovPersonaAuditEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// Related persona (NULL for archetype-only events).
    pub persona_id: Option<Uuid>,

    /// Related archetype (NULL for persona-only events).
    pub archetype_id: Option<Uuid>,

    /// Type of event.
    pub event_type: PersonaAuditEventType,

    /// User who performed the action.
    pub actor_id: Uuid,

    /// Event-specific details.
    pub event_data: serde_json::Value,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Request to create an audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePersonaAuditEvent {
    pub persona_id: Option<Uuid>,
    pub archetype_id: Option<Uuid>,
    pub event_type: PersonaAuditEventType,
    pub actor_id: Uuid,
    pub event_data: serde_json::Value,
}

/// Filter options for listing audit events.
#[derive(Debug, Clone, Default)]
pub struct PersonaAuditEventFilter {
    pub persona_id: Option<Uuid>,
    pub archetype_id: Option<Uuid>,
    pub event_type: Option<PersonaAuditEventType>,
    pub actor_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

/// Event data for persona_created event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaCreatedEventData {
    pub persona_id: Uuid,
    pub archetype_id: Uuid,
    pub physical_user_id: Uuid,
    pub persona_name: String,
    pub initial_attributes: serde_json::Value,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
}

/// Event data for context_switched event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSwitchedEventData {
    pub session_id: Uuid,
    pub from_persona_id: Option<Uuid>,
    pub to_persona_id: Option<Uuid>,
    pub from_persona_name: Option<String>,
    pub to_persona_name: Option<String>,
    pub switch_reason: Option<String>,
    pub new_jwt_issued: bool,
}

/// Event data for attributes_propagated event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributesPropagatedEventData {
    pub physical_user_id: Uuid,
    pub persona_id: Uuid,
    pub changed_attributes: serde_json::Map<String, serde_json::Value>,
    pub trigger: String,
}

/// Event data for archetype events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchetypeEventData {
    pub archetype_id: Uuid,
    pub name: String,
    pub changes: Option<serde_json::Value>,
}

impl GovPersonaAuditEvent {
    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_audit_events
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List audit events with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PersonaAuditEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_persona_audit_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.persona_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND persona_id = ${}", param_count));
        }
        if filter.archetype_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND archetype_id = ${}", param_count));
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

        if let Some(persona_id) = filter.persona_id {
            q = q.bind(persona_id);
        }
        if let Some(archetype_id) = filter.archetype_id {
            q = q.bind(archetype_id);
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
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PersonaAuditEventFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_persona_audit_events WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.persona_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND persona_id = ${}", param_count));
        }
        if filter.archetype_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND archetype_id = ${}", param_count));
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

        if let Some(persona_id) = filter.persona_id {
            q = q.bind(persona_id);
        }
        if let Some(archetype_id) = filter.archetype_id {
            q = q.bind(archetype_id);
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

    /// List events for a specific persona.
    pub async fn find_by_persona(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        persona_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_audit_events
            WHERE tenant_id = $1 AND persona_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(persona_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List events for a specific archetype.
    pub async fn find_by_archetype(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        archetype_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_audit_events
            WHERE tenant_id = $1 AND archetype_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(archetype_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Create a new audit event (immutable, insert only).
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreatePersonaAuditEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_persona_audit_events (
                tenant_id, persona_id, archetype_id, event_type, actor_id, event_data
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.persona_id)
        .bind(input.archetype_id)
        .bind(input.event_type)
        .bind(input.actor_id)
        .bind(&input.event_data)
        .fetch_one(pool)
        .await
    }

    // Helper methods to create specific event types

    /// Create a persona_created audit event.
    pub async fn log_persona_created(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        actor_id: Uuid,
        data: PersonaCreatedEventData,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreatePersonaAuditEvent {
                persona_id: Some(data.persona_id),
                archetype_id: Some(data.archetype_id),
                event_type: PersonaAuditEventType::PersonaCreated,
                actor_id,
                event_data: serde_json::to_value(&data).unwrap_or_default(),
            },
        )
        .await
    }

    /// Create a context_switched audit event.
    pub async fn log_context_switched(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        actor_id: Uuid,
        data: ContextSwitchedEventData,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreatePersonaAuditEvent {
                persona_id: data.to_persona_id,
                archetype_id: None,
                event_type: PersonaAuditEventType::ContextSwitched,
                actor_id,
                event_data: serde_json::to_value(&data).unwrap_or_default(),
            },
        )
        .await
    }

    /// Create a context_switched_back audit event.
    pub async fn log_context_switched_back(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        actor_id: Uuid,
        data: ContextSwitchedEventData,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreatePersonaAuditEvent {
                persona_id: data.from_persona_id,
                archetype_id: None,
                event_type: PersonaAuditEventType::ContextSwitchedBack,
                actor_id,
                event_data: serde_json::to_value(&data).unwrap_or_default(),
            },
        )
        .await
    }

    /// Create an attributes_propagated audit event.
    pub async fn log_attributes_propagated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        actor_id: Uuid,
        data: AttributesPropagatedEventData,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreatePersonaAuditEvent {
                persona_id: Some(data.persona_id),
                archetype_id: None,
                event_type: PersonaAuditEventType::AttributesPropagated,
                actor_id,
                event_data: serde_json::to_value(&data).unwrap_or_default(),
            },
        )
        .await
    }

    /// Create an archetype event.
    pub async fn log_archetype_event(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        actor_id: Uuid,
        event_type: PersonaAuditEventType,
        data: ArchetypeEventData,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreatePersonaAuditEvent {
                persona_id: None,
                archetype_id: Some(data.archetype_id),
                event_type,
                actor_id,
                event_data: serde_json::to_value(&data).unwrap_or_default(),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_persona_audit_event_request() {
        let input = CreatePersonaAuditEvent {
            persona_id: Some(Uuid::new_v4()),
            archetype_id: Some(Uuid::new_v4()),
            event_type: PersonaAuditEventType::PersonaCreated,
            actor_id: Uuid::new_v4(),
            event_data: serde_json::json!({"test": "data"}),
        };

        assert!(input.persona_id.is_some());
        assert!(input.archetype_id.is_some());
        assert_eq!(input.event_type, PersonaAuditEventType::PersonaCreated);
    }

    #[test]
    fn test_persona_created_event_data_serialization() {
        let data = PersonaCreatedEventData {
            persona_id: Uuid::new_v4(),
            archetype_id: Uuid::new_v4(),
            physical_user_id: Uuid::new_v4(),
            persona_name: "admin.john.doe".to_string(),
            initial_attributes: serde_json::json!({"surname": "Doe"}),
            valid_from: Utc::now(),
            valid_until: Some(Utc::now() + chrono::Duration::days(365)),
        };

        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"persona_name\":\"admin.john.doe\""));
    }

    #[test]
    fn test_context_switched_event_data_serialization() {
        let data = ContextSwitchedEventData {
            session_id: Uuid::new_v4(),
            from_persona_id: None,
            to_persona_id: Some(Uuid::new_v4()),
            from_persona_name: None,
            to_persona_name: Some("admin.john.doe".to_string()),
            switch_reason: Some("Administrative task".to_string()),
            new_jwt_issued: true,
        };

        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"new_jwt_issued\":true"));
    }

    #[test]
    fn test_filter_default() {
        let filter = PersonaAuditEventFilter::default();
        assert!(filter.persona_id.is_none());
        assert!(filter.archetype_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.actor_id.is_none());
        assert!(filter.from_date.is_none());
        assert!(filter.to_date.is_none());
    }
}
