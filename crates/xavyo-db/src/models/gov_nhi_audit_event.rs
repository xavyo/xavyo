//! NHI Audit Event model.
//!
//! Complete audit trail for NHI lifecycle events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::net::IpAddr;
use uuid::Uuid;

// Note: IP addresses are stored as String in PostgreSQL INET columns
// because sqlx maps INET to String. Use ip_addr() helper for parsing.

/// Type of NHI audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_nhi_audit_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum NhiAuditEventType {
    /// NHI was created.
    Created,
    /// NHI metadata was updated.
    Updated,
    /// Credentials were rotated.
    CredentialsRotated,
    /// A specific credential was revoked.
    CredentialRevoked,
    /// NHI was suspended.
    Suspended,
    /// NHI was reactivated.
    Reactivated,
    /// Ownership was transferred.
    OwnershipTransferred,
    /// NHI was certified.
    Certified,
    /// NHI expired.
    Expired,
    /// NHI was deleted.
    Deleted,
    /// NHI was emergency suspended.
    EmergencySuspended,
}

/// Reason why an NHI was suspended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_nhi_suspension_reason", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum NhiSuspensionReason {
    /// NHI expired (past expiration date).
    Expired,
    /// NHI was inactive beyond threshold.
    Inactive,
    /// Certification was revoked.
    CertificationRevoked,
    /// Emergency suspension (security incident).
    Emergency,
    /// Manual suspension by administrator.
    Manual,
}

/// An NHI audit event record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovNhiAuditEvent {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this event belongs to.
    pub tenant_id: Uuid,

    /// The NHI this event is for.
    pub nhi_id: Uuid,

    /// Type of event.
    pub event_type: NhiAuditEventType,

    /// Who performed the action (None for system actions).
    pub actor_id: Option<Uuid>,

    /// When the event occurred.
    pub timestamp: DateTime<Utc>,

    /// Before/after values for changes.
    pub changes: Option<serde_json::Value>,

    /// Additional context/metadata.
    pub metadata: Option<serde_json::Value>,

    /// IP address of the actor (stored as String, INET in DB).
    pub source_ip: Option<String>,
}

/// Request to create an audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovNhiAuditEvent {
    pub nhi_id: Uuid,
    pub event_type: NhiAuditEventType,
    pub actor_id: Option<Uuid>,
    pub changes: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub source_ip: Option<String>,
}

/// Filter options for listing audit events.
#[derive(Debug, Clone, Default)]
pub struct NhiAuditEventFilter {
    pub nhi_id: Option<Uuid>,
    pub event_type: Option<NhiAuditEventType>,
    pub actor_id: Option<Uuid>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

impl GovNhiAuditEvent {
    /// Get the source IP as parsed IpAddr (if present and valid).
    #[must_use]
    pub fn source_ip_addr(&self) -> Option<IpAddr> {
        self.source_ip.as_ref().and_then(|s| s.parse().ok())
    }

    /// Record an audit event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: CreateGovNhiAuditEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_nhi_audit_events (
                tenant_id, nhi_id, event_type, actor_id,
                changes, metadata, source_ip
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(data.nhi_id)
        .bind(data.event_type)
        .bind(data.actor_id)
        .bind(&data.changes)
        .bind(&data.metadata)
        .bind(data.source_ip)
        .fetch_one(pool)
        .await
    }

    /// List audit events with filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiAuditEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_nhi_audit_events
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;

        if filter.nhi_id.is_some() {
            query.push_str(&format!(" AND nhi_id = ${}", param_idx));
            param_idx += 1;
        }

        if filter.event_type.is_some() {
            query.push_str(&format!(" AND event_type = ${}", param_idx));
            param_idx += 1;
        }

        if filter.actor_id.is_some() {
            query.push_str(&format!(" AND actor_id = ${}", param_idx));
            param_idx += 1;
        }

        if filter.start_date.is_some() {
            query.push_str(&format!(" AND timestamp >= ${}", param_idx));
            param_idx += 1;
        }

        if filter.end_date.is_some() {
            query.push_str(&format!(" AND timestamp <= ${}", param_idx));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY timestamp DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(nhi_id) = filter.nhi_id {
            q = q.bind(nhi_id);
        }

        if let Some(event_type) = filter.event_type {
            q = q.bind(event_type);
        }

        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }

        if let Some(start) = filter.start_date {
            q = q.bind(start);
        }

        if let Some(end) = filter.end_date {
            q = q.bind(end);
        }

        q = q.bind(limit).bind(offset);

        q.fetch_all(pool).await
    }

    /// Count audit events with filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiAuditEventFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_nhi_audit_events
            WHERE tenant_id = $1
            "#,
        );

        let mut param_idx = 2;

        if filter.nhi_id.is_some() {
            query.push_str(&format!(" AND nhi_id = ${}", param_idx));
            param_idx += 1;
        }

        if filter.event_type.is_some() {
            query.push_str(&format!(" AND event_type = ${}", param_idx));
            param_idx += 1;
        }

        if filter.actor_id.is_some() {
            query.push_str(&format!(" AND actor_id = ${}", param_idx));
            param_idx += 1;
        }

        if filter.start_date.is_some() {
            query.push_str(&format!(" AND timestamp >= ${}", param_idx));
            param_idx += 1;
        }

        if filter.end_date.is_some() {
            query.push_str(&format!(" AND timestamp <= ${}", param_idx));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(nhi_id) = filter.nhi_id {
            q = q.bind(nhi_id);
        }

        if let Some(event_type) = filter.event_type {
            q = q.bind(event_type);
        }

        if let Some(actor_id) = filter.actor_id {
            q = q.bind(actor_id);
        }

        if let Some(start) = filter.start_date {
            q = q.bind(start);
        }

        if let Some(end) = filter.end_date {
            q = q.bind(end);
        }

        q.fetch_one(pool).await
    }

    /// Get most recent events for an NHI.
    pub async fn get_recent_for_nhi(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_nhi_audit_events
            WHERE tenant_id = $1 AND nhi_id = $2
            ORDER BY timestamp DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Helper to create a "created" audit event.
    pub async fn log_created(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        actor_id: Option<Uuid>,
        source_ip: Option<IpAddr>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovNhiAuditEvent {
                nhi_id,
                event_type: NhiAuditEventType::Created,
                actor_id,
                changes: None,
                metadata: None,
                source_ip: source_ip.map(|ip| ip.to_string()),
            },
        )
        .await
    }

    /// Helper to create an "updated" audit event with changes.
    pub async fn log_updated(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        actor_id: Option<Uuid>,
        changes: serde_json::Value,
        source_ip: Option<IpAddr>,
    ) -> Result<Self, sqlx::Error> {
        Self::create(
            pool,
            tenant_id,
            CreateGovNhiAuditEvent {
                nhi_id,
                event_type: NhiAuditEventType::Updated,
                actor_id,
                changes: Some(changes),
                metadata: None,
                source_ip: source_ip.map(|ip| ip.to_string()),
            },
        )
        .await
    }

    /// Helper to create a "suspended" audit event.
    pub async fn log_suspended(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        actor_id: Option<Uuid>,
        reason: NhiSuspensionReason,
        source_ip: Option<IpAddr>,
    ) -> Result<Self, sqlx::Error> {
        let metadata = serde_json::json!({
            "reason": reason
        });

        Self::create(
            pool,
            tenant_id,
            CreateGovNhiAuditEvent {
                nhi_id,
                event_type: if reason == NhiSuspensionReason::Emergency {
                    NhiAuditEventType::EmergencySuspended
                } else {
                    NhiAuditEventType::Suspended
                },
                actor_id,
                changes: None,
                metadata: Some(metadata),
                source_ip: source_ip.map(|ip| ip.to_string()),
            },
        )
        .await
    }

    /// Helper to create an "ownership transferred" audit event.
    #[allow(clippy::too_many_arguments)]
    pub async fn log_ownership_transferred(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        actor_id: Option<Uuid>,
        from_owner: Uuid,
        to_owner: Uuid,
        reason: Option<String>,
        source_ip: Option<IpAddr>,
    ) -> Result<Self, sqlx::Error> {
        let changes = serde_json::json!({
            "from_owner": from_owner,
            "to_owner": to_owner,
            "reason": reason
        });

        Self::create(
            pool,
            tenant_id,
            CreateGovNhiAuditEvent {
                nhi_id,
                event_type: NhiAuditEventType::OwnershipTransferred,
                actor_id,
                changes: Some(changes),
                metadata: None,
                source_ip: source_ip.map(|ip| ip.to_string()),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_type_serialization() {
        let created = NhiAuditEventType::Created;
        let json = serde_json::to_string(&created).unwrap();
        assert_eq!(json, "\"created\"");

        let rotated = NhiAuditEventType::CredentialsRotated;
        let json = serde_json::to_string(&rotated).unwrap();
        assert_eq!(json, "\"credentials_rotated\"");

        let emergency = NhiAuditEventType::EmergencySuspended;
        let json = serde_json::to_string(&emergency).unwrap();
        assert_eq!(json, "\"emergency_suspended\"");
    }

    #[test]
    fn test_suspension_reason_serialization() {
        let expired = NhiSuspensionReason::Expired;
        let json = serde_json::to_string(&expired).unwrap();
        assert_eq!(json, "\"expired\"");

        let inactive = NhiSuspensionReason::Inactive;
        let json = serde_json::to_string(&inactive).unwrap();
        assert_eq!(json, "\"inactive\"");

        let emergency = NhiSuspensionReason::Emergency;
        let json = serde_json::to_string(&emergency).unwrap();
        assert_eq!(json, "\"emergency\"");
    }
}
