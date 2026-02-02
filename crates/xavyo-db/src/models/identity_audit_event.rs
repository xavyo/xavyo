//! Identity Audit Event model for Workload Identity Federation (F121).
//!
//! Immutable audit log for all IAM operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Type of identity audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAuditEventType {
    /// Agent requested cloud credentials.
    CredentialRequested,
    /// Credentials successfully issued.
    CredentialIssued,
    /// Credential request denied.
    CredentialDenied,
    /// Kubernetes token verified.
    TokenVerified,
    /// Kubernetes token rejected.
    TokenRejected,
    /// Provider configuration created.
    ProviderCreated,
    /// Provider configuration updated.
    ProviderUpdated,
    /// Provider configuration deleted.
    ProviderDeleted,
    /// Role mapping created.
    MappingCreated,
    /// Role mapping updated.
    MappingUpdated,
    /// Role mapping deleted.
    MappingDeleted,
    /// Provider health check performed.
    HealthCheck,
}

impl std::fmt::Display for IdentityAuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityAuditEventType::CredentialRequested => write!(f, "credential_requested"),
            IdentityAuditEventType::CredentialIssued => write!(f, "credential_issued"),
            IdentityAuditEventType::CredentialDenied => write!(f, "credential_denied"),
            IdentityAuditEventType::TokenVerified => write!(f, "token_verified"),
            IdentityAuditEventType::TokenRejected => write!(f, "token_rejected"),
            IdentityAuditEventType::ProviderCreated => write!(f, "provider_created"),
            IdentityAuditEventType::ProviderUpdated => write!(f, "provider_updated"),
            IdentityAuditEventType::ProviderDeleted => write!(f, "provider_deleted"),
            IdentityAuditEventType::MappingCreated => write!(f, "mapping_created"),
            IdentityAuditEventType::MappingUpdated => write!(f, "mapping_updated"),
            IdentityAuditEventType::MappingDeleted => write!(f, "mapping_deleted"),
            IdentityAuditEventType::HealthCheck => write!(f, "health_check"),
        }
    }
}

/// Outcome of an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum IdentityAuditOutcome {
    /// Operation succeeded.
    Success,
    /// Operation failed.
    Failure,
}

impl std::fmt::Display for IdentityAuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityAuditOutcome::Success => write!(f, "success"),
            IdentityAuditOutcome::Failure => write!(f, "failure"),
        }
    }
}

/// Identity audit event record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct IdentityAuditEvent {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant this event belongs to.
    pub tenant_id: Uuid,
    /// Type of event.
    pub event_type: String,
    /// Agent ID if applicable.
    pub agent_id: Option<Uuid>,
    /// User ID if admin action.
    pub user_id: Option<Uuid>,
    /// Provider type (aws, gcp, azure, kubernetes).
    pub provider_type: Option<String>,
    /// Specific operation.
    pub operation: String,
    /// Type of resource affected.
    pub resource_type: Option<String>,
    /// ID of resource affected.
    pub resource_id: Option<Uuid>,
    /// Event-specific details (JSONB).
    pub details: serde_json::Value,
    /// Outcome of the operation.
    pub outcome: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Request to create an identity audit event.
#[derive(Debug, Clone)]
pub struct CreateIdentityAuditEvent {
    /// Type of event.
    pub event_type: IdentityAuditEventType,
    /// Agent ID if applicable.
    pub agent_id: Option<Uuid>,
    /// User ID if admin action.
    pub user_id: Option<Uuid>,
    /// Provider type.
    pub provider_type: Option<String>,
    /// Specific operation.
    pub operation: String,
    /// Type of resource affected.
    pub resource_type: Option<String>,
    /// ID of resource affected.
    pub resource_id: Option<Uuid>,
    /// Event-specific details.
    pub details: serde_json::Value,
    /// Outcome of the operation.
    pub outcome: IdentityAuditOutcome,
}

/// Filter for listing identity audit events.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IdentityAuditEventFilter {
    /// Filter by event type.
    pub event_type: Option<String>,
    /// Filter by agent ID.
    pub agent_id: Option<Uuid>,
    /// Filter by user ID.
    pub user_id: Option<Uuid>,
    /// Filter by provider type.
    pub provider_type: Option<String>,
    /// Filter by outcome.
    pub outcome: Option<IdentityAuditOutcome>,
    /// Filter by start time.
    pub from: Option<DateTime<Utc>>,
    /// Filter by end time.
    pub to: Option<DateTime<Utc>>,
    /// Maximum number of results.
    pub limit: Option<i64>,
    /// Offset for pagination.
    pub offset: Option<i64>,
}

impl IdentityAuditEvent {
    /// Create a new identity audit event.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        request: &CreateIdentityAuditEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            INSERT INTO identity_audit_events (
                tenant_id, event_type, agent_id, user_id, provider_type,
                operation, resource_type, resource_id, details, outcome
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING
                id, tenant_id, event_type, agent_id, user_id, provider_type,
                operation, resource_type, resource_id, details, outcome, created_at
            "#,
            tenant_id,
            request.event_type.to_string(),
            request.agent_id,
            request.user_id,
            request.provider_type.as_ref(),
            &request.operation,
            request.resource_type.as_ref(),
            request.resource_id,
            request.details,
            request.outcome.to_string(),
        )
        .fetch_one(pool)
        .await
    }

    /// List identity audit events for a tenant.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &IdentityAuditEventFilter,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = filter.limit.unwrap_or(100);
        let offset = filter.offset.unwrap_or(0);

        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, event_type, agent_id, user_id, provider_type,
                operation, resource_type, resource_id, details, outcome, created_at
            FROM identity_audit_events
            WHERE tenant_id = $1
                AND ($2::text IS NULL OR event_type = $2)
                AND ($3::uuid IS NULL OR agent_id = $3)
                AND ($4::uuid IS NULL OR user_id = $4)
                AND ($5::text IS NULL OR provider_type = $5)
                AND ($6::text IS NULL OR outcome = $6)
                AND ($7::timestamptz IS NULL OR created_at >= $7)
                AND ($8::timestamptz IS NULL OR created_at <= $8)
            ORDER BY created_at DESC
            LIMIT $9 OFFSET $10
            "#,
            tenant_id,
            filter.event_type.as_ref(),
            filter.agent_id,
            filter.user_id,
            filter.provider_type.as_ref(),
            filter.outcome.map(|o| o.to_string()),
            filter.from,
            filter.to,
            limit,
            offset,
        )
        .fetch_all(pool)
        .await
    }

    /// Count identity audit events matching filter.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &IdentityAuditEventFilter,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM identity_audit_events
            WHERE tenant_id = $1
                AND ($2::text IS NULL OR event_type = $2)
                AND ($3::uuid IS NULL OR agent_id = $3)
                AND ($4::uuid IS NULL OR user_id = $4)
                AND ($5::text IS NULL OR provider_type = $5)
                AND ($6::text IS NULL OR outcome = $6)
                AND ($7::timestamptz IS NULL OR created_at >= $7)
                AND ($8::timestamptz IS NULL OR created_at <= $8)
            "#,
            tenant_id,
            filter.event_type.as_ref(),
            filter.agent_id,
            filter.user_id,
            filter.provider_type.as_ref(),
            filter.outcome.map(|o| o.to_string()),
            filter.from,
            filter.to,
        )
        .fetch_one(pool)
        .await
    }

    /// Get a single audit event by ID.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, event_type, agent_id, user_id, provider_type,
                operation, resource_type, resource_id, details, outcome, created_at
            FROM identity_audit_events
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id,
        )
        .fetch_optional(pool)
        .await
    }
}
