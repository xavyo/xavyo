//! Power of Attorney Audit Event model.
//!
//! Tracks all audit events related to Power of Attorney operations.
//! Part of F-061 Power of Attorney / Identity Assumption feature.
//!
//! This model follows an INSERT-ONLY pattern for audit integrity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use std::net::IpAddr;
use uuid::Uuid;

/// Event types for PoA audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "poa_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PoaEventType {
    /// PoA grant was created.
    GrantCreated,
    /// PoA grant was extended.
    GrantExtended,
    /// PoA grant was revoked.
    GrantRevoked,
    /// PoA grant expired.
    GrantExpired,
    /// Identity was assumed by attorney.
    IdentityAssumed,
    /// Identity was dropped by attorney.
    IdentityDropped,
    /// Action performed while assuming identity.
    ActionPerformed,
}

impl std::fmt::Display for PoaEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoaEventType::GrantCreated => write!(f, "grant_created"),
            PoaEventType::GrantExtended => write!(f, "grant_extended"),
            PoaEventType::GrantRevoked => write!(f, "grant_revoked"),
            PoaEventType::GrantExpired => write!(f, "grant_expired"),
            PoaEventType::IdentityAssumed => write!(f, "identity_assumed"),
            PoaEventType::IdentityDropped => write!(f, "identity_dropped"),
            PoaEventType::ActionPerformed => write!(f, "action_performed"),
        }
    }
}

/// An audit event for Power of Attorney operations.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PoaAuditEvent {
    /// Unique identifier for the event.
    pub id: Uuid,

    /// The tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The PoA grant this event relates to.
    pub poa_id: Uuid,

    /// Type of event.
    pub event_type: PoaEventType,

    /// User who performed the action.
    pub actor_id: Uuid,

    /// User affected by the action (if different from actor).
    pub affected_user_id: Option<Uuid>,

    /// Additional event details as JSON.
    pub details: Option<JsonValue>,

    /// Client IP address (stored as String, INET type maps to String in SQLx).
    pub ip_address: Option<String>,

    /// Client user agent.
    pub user_agent: Option<String>,

    /// Immutable timestamp.
    pub created_at: DateTime<Utc>,
}

impl PoaAuditEvent {
    /// Get the IP address as parsed `IpAddr` (if present and valid).
    #[must_use]
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip_address.as_ref().and_then(|s| s.parse().ok())
    }
}

/// Request to create a new audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePoaAuditEvent {
    pub poa_id: Uuid,
    pub event_type: PoaEventType,
    pub actor_id: Uuid,
    pub affected_user_id: Option<Uuid>,
    pub details: Option<JsonValue>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Filter options for listing audit events.
#[derive(Debug, Clone, Default)]
pub struct PoaAuditEventFilter {
    /// Filter by PoA ID.
    pub poa_id: Option<Uuid>,
    /// Filter by event type.
    pub event_type: Option<PoaEventType>,
    /// Filter by actor ID.
    pub actor_id: Option<Uuid>,
    /// Filter by affected user ID.
    pub affected_user_id: Option<Uuid>,
    /// Filter by events after this time.
    pub after: Option<DateTime<Utc>>,
    /// Filter by events before this time.
    pub before: Option<DateTime<Utc>>,
}

impl PoaAuditEvent {
    /// Find an event by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM poa_audit_events
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List events for a specific PoA.
    pub async fn list_by_poa(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        poa_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM poa_audit_events
            WHERE tenant_id = $1 AND poa_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(poa_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List events with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PoaAuditEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM poa_audit_events
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.poa_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND poa_id = ${param_count}"));
        }
        if filter.event_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${param_count}"));
        }
        if filter.actor_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND actor_id = ${param_count}"));
        }
        if filter.affected_user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND affected_user_id = ${param_count}"));
        }
        if filter.after.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.before.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, PoaAuditEvent>(&query).bind(tenant_id);

        if let Some(poa_id) = filter.poa_id {
            q = q.bind(poa_id);
        }
        if let Some(event_type) = filter.event_type {
            q = q.bind(event_type);
        }
        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }
        if let Some(affected_user_id) = filter.affected_user_id {
            q = q.bind(affected_user_id);
        }
        if let Some(after) = filter.after {
            q = q.bind(after);
        }
        if let Some(before) = filter.before {
            q = q.bind(before);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Create a new audit event (INSERT-ONLY - no updates or deletes).
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreatePoaAuditEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO poa_audit_events (
                tenant_id, poa_id, event_type, actor_id, affected_user_id,
                details, ip_address, user_agent
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.poa_id)
        .bind(input.event_type)
        .bind(input.actor_id)
        .bind(input.affected_user_id)
        .bind(input.details)
        .bind(input.ip_address)
        .bind(input.user_agent)
        .fetch_one(pool)
        .await
    }

    /// Count events for a specific PoA.
    pub async fn count_by_poa(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        poa_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM poa_audit_events
            WHERE tenant_id = $1 AND poa_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(poa_id)
        .fetch_one(pool)
        .await
    }

    /// Count events by type for a specific PoA.
    pub async fn count_by_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        poa_id: Uuid,
        event_type: PoaEventType,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM poa_audit_events
            WHERE tenant_id = $1 AND poa_id = $2 AND event_type = $3
            ",
        )
        .bind(tenant_id)
        .bind(poa_id)
        .bind(event_type)
        .fetch_one(pool)
        .await
    }

    /// List recent events for an actor (attorney or donor).
    pub async fn list_recent_for_actor(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        actor_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM poa_audit_events
            WHERE tenant_id = $1 AND actor_id = $2
            ORDER BY created_at DESC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(actor_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Helper to create a grant_created event.
    pub fn grant_created_event(
        poa_id: Uuid,
        donor_id: Uuid,
        attorney_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> CreatePoaAuditEvent {
        CreatePoaAuditEvent {
            poa_id,
            event_type: PoaEventType::GrantCreated,
            actor_id: donor_id,
            affected_user_id: Some(attorney_id),
            details: None,
            ip_address,
            user_agent,
        }
    }

    /// Helper to create a grant_revoked event.
    pub fn grant_revoked_event(
        poa_id: Uuid,
        revoked_by: Uuid,
        reason: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> CreatePoaAuditEvent {
        let details = reason.map(|r| serde_json::json!({ "reason": r }));
        CreatePoaAuditEvent {
            poa_id,
            event_type: PoaEventType::GrantRevoked,
            actor_id: revoked_by,
            affected_user_id: None,
            details,
            ip_address,
            user_agent,
        }
    }

    /// Helper to create an identity_assumed event.
    pub fn identity_assumed_event(
        poa_id: Uuid,
        attorney_id: Uuid,
        donor_id: Uuid,
        session_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> CreatePoaAuditEvent {
        CreatePoaAuditEvent {
            poa_id,
            event_type: PoaEventType::IdentityAssumed,
            actor_id: attorney_id,
            affected_user_id: Some(donor_id),
            details: Some(serde_json::json!({ "session_id": session_id })),
            ip_address,
            user_agent,
        }
    }

    /// Helper to create an identity_dropped event.
    pub fn identity_dropped_event(
        poa_id: Uuid,
        attorney_id: Uuid,
        donor_id: Uuid,
        session_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> CreatePoaAuditEvent {
        CreatePoaAuditEvent {
            poa_id,
            event_type: PoaEventType::IdentityDropped,
            actor_id: attorney_id,
            affected_user_id: Some(donor_id),
            details: Some(serde_json::json!({ "session_id": session_id })),
            ip_address,
            user_agent,
        }
    }

    /// Helper to create an action_performed event.
    pub fn action_performed_event(
        poa_id: Uuid,
        attorney_id: Uuid,
        donor_id: Uuid,
        action_type: &str,
        resource_id: Option<&str>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> CreatePoaAuditEvent {
        let mut details = serde_json::json!({ "action_type": action_type });
        if let Some(res_id) = resource_id {
            details["resource_id"] = serde_json::json!(res_id);
        }
        CreatePoaAuditEvent {
            poa_id,
            event_type: PoaEventType::ActionPerformed,
            actor_id: attorney_id,
            affected_user_id: Some(donor_id),
            details: Some(details),
            ip_address,
            user_agent,
        }
    }

    /// Helper to create a grant_extended event.
    pub fn grant_extended_event(
        poa_id: Uuid,
        donor_id: Uuid,
        old_ends_at: DateTime<Utc>,
        new_ends_at: DateTime<Utc>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> CreatePoaAuditEvent {
        CreatePoaAuditEvent {
            poa_id,
            event_type: PoaEventType::GrantExtended,
            actor_id: donor_id,
            affected_user_id: None,
            details: Some(serde_json::json!({
                "old_ends_at": old_ends_at,
                "new_ends_at": new_ends_at,
            })),
            ip_address,
            user_agent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_display() {
        assert_eq!(PoaEventType::GrantCreated.to_string(), "grant_created");
        assert_eq!(PoaEventType::GrantExtended.to_string(), "grant_extended");
        assert_eq!(PoaEventType::GrantRevoked.to_string(), "grant_revoked");
        assert_eq!(PoaEventType::GrantExpired.to_string(), "grant_expired");
        assert_eq!(
            PoaEventType::IdentityAssumed.to_string(),
            "identity_assumed"
        );
        assert_eq!(
            PoaEventType::IdentityDropped.to_string(),
            "identity_dropped"
        );
        assert_eq!(
            PoaEventType::ActionPerformed.to_string(),
            "action_performed"
        );
    }

    #[test]
    fn test_create_audit_event_request() {
        let poa_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let event = CreatePoaAuditEvent {
            poa_id,
            event_type: PoaEventType::GrantCreated,
            actor_id,
            affected_user_id: Some(Uuid::new_v4()),
            details: Some(serde_json::json!({"key": "value"})),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Test Agent".to_string()),
        };

        assert_eq!(event.poa_id, poa_id);
        assert_eq!(event.event_type, PoaEventType::GrantCreated);
        assert_eq!(event.actor_id, actor_id);
    }

    #[test]
    fn test_filter_default() {
        let filter = PoaAuditEventFilter::default();
        assert!(filter.poa_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.actor_id.is_none());
        assert!(filter.affected_user_id.is_none());
        assert!(filter.after.is_none());
        assert!(filter.before.is_none());
    }

    #[test]
    fn test_helper_grant_created_event() {
        let poa_id = Uuid::new_v4();
        let donor_id = Uuid::new_v4();
        let attorney_id = Uuid::new_v4();

        let event = PoaAuditEvent::grant_created_event(poa_id, donor_id, attorney_id, None, None);

        assert_eq!(event.poa_id, poa_id);
        assert_eq!(event.event_type, PoaEventType::GrantCreated);
        assert_eq!(event.actor_id, donor_id);
        assert_eq!(event.affected_user_id, Some(attorney_id));
    }

    #[test]
    fn test_helper_identity_assumed_event() {
        let poa_id = Uuid::new_v4();
        let attorney_id = Uuid::new_v4();
        let donor_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let event = PoaAuditEvent::identity_assumed_event(
            poa_id,
            attorney_id,
            donor_id,
            session_id,
            None,
            None,
        );

        assert_eq!(event.event_type, PoaEventType::IdentityAssumed);
        assert_eq!(event.actor_id, attorney_id);
        assert_eq!(event.affected_user_id, Some(donor_id));
        assert!(event.details.is_some());
    }

    #[test]
    fn test_helper_action_performed_event() {
        let poa_id = Uuid::new_v4();
        let attorney_id = Uuid::new_v4();
        let donor_id = Uuid::new_v4();

        let event = PoaAuditEvent::action_performed_event(
            poa_id,
            attorney_id,
            donor_id,
            "access_request_submit",
            Some("req-123"),
            None,
            None,
        );

        assert_eq!(event.event_type, PoaEventType::ActionPerformed);
        let details = event.details.unwrap();
        assert_eq!(details["action_type"], "access_request_submit");
        assert_eq!(details["resource_id"], "req-123");
    }
}
