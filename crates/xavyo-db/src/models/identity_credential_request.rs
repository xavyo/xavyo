//! Identity Credential Request model for Workload Identity Federation (F121).
//!
//! Tracks credential requests for audit and rate limiting.
//!
//! Note: IP addresses are stored as String in PostgreSQL INET columns
//! because sqlx maps INET to String. Use source_ip_addr() helper for parsing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::net::IpAddr;
use uuid::Uuid;

/// Outcome of a credential request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum IdentityCredentialOutcome {
    /// Credentials issued successfully.
    Success,
    /// Request denied (no permission, no mapping).
    Denied,
    /// Rate limited.
    RateLimited,
    /// Error from provider.
    Error,
}

impl std::fmt::Display for IdentityCredentialOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityCredentialOutcome::Success => write!(f, "success"),
            IdentityCredentialOutcome::Denied => write!(f, "denied"),
            IdentityCredentialOutcome::RateLimited => write!(f, "rate_limited"),
            IdentityCredentialOutcome::Error => write!(f, "error"),
        }
    }
}

/// Identity credential request record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct IdentityCredentialRequest {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant this request belongs to.
    pub tenant_id: Uuid,
    /// Agent that made the request.
    pub agent_id: Uuid,
    /// Identity provider configuration used.
    pub provider_config_id: Uuid,
    /// Role mapping used (NULL if denied before mapping resolution).
    pub role_mapping_id: Option<Uuid>,
    /// TTL requested by the agent.
    pub requested_ttl_seconds: i32,
    /// TTL actually granted.
    pub granted_ttl_seconds: Option<i32>,
    /// Outcome of the request.
    pub outcome: String,
    /// Error code if failed.
    pub error_code: Option<String>,
    /// Error message if failed.
    pub error_message: Option<String>,
    /// Request duration in milliseconds.
    pub duration_ms: i32,
    /// Source IP address (stored as String, INET in DB).
    pub source_ip: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Request to create a credential request record.
#[derive(Debug, Clone)]
pub struct CreateIdentityCredentialRequest {
    /// Agent that made the request.
    pub agent_id: Uuid,
    /// Identity provider configuration used.
    pub provider_config_id: Uuid,
    /// Role mapping used.
    pub role_mapping_id: Option<Uuid>,
    /// TTL requested by the agent.
    pub requested_ttl_seconds: i32,
    /// TTL actually granted.
    pub granted_ttl_seconds: Option<i32>,
    /// Outcome of the request.
    pub outcome: IdentityCredentialOutcome,
    /// Error code if failed.
    pub error_code: Option<String>,
    /// Error message if failed.
    pub error_message: Option<String>,
    /// Request duration in milliseconds.
    pub duration_ms: i32,
    /// Source IP address (stored as String for DB compatibility).
    pub source_ip: Option<String>,
}

/// Filter for listing credential requests.
#[derive(Debug, Clone, Default)]
pub struct IdentityCredentialRequestFilter {
    /// Filter by agent ID.
    pub agent_id: Option<Uuid>,
    /// Filter by provider config ID.
    pub provider_config_id: Option<Uuid>,
    /// Filter by outcome.
    pub outcome: Option<IdentityCredentialOutcome>,
    /// Filter by start time.
    pub from: Option<DateTime<Utc>>,
    /// Filter by end time.
    pub to: Option<DateTime<Utc>>,
    /// Maximum number of results.
    pub limit: Option<i64>,
    /// Offset for pagination.
    pub offset: Option<i64>,
}

impl IdentityCredentialRequest {
    /// Get the source IP as parsed IpAddr (if present and valid).
    pub fn source_ip_addr(&self) -> Option<IpAddr> {
        self.source_ip.as_ref().and_then(|s| s.parse().ok())
    }

    /// Create a new credential request record.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        request: &CreateIdentityCredentialRequest,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO identity_credential_requests (
                tenant_id, agent_id, provider_config_id, role_mapping_id,
                requested_ttl_seconds, granted_ttl_seconds, outcome,
                error_code, error_message, duration_ms, source_ip
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::inet)
            RETURNING
                id, tenant_id, agent_id, provider_config_id, role_mapping_id,
                requested_ttl_seconds, granted_ttl_seconds, outcome,
                error_code, error_message, duration_ms, source_ip::text, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(request.agent_id)
        .bind(request.provider_config_id)
        .bind(request.role_mapping_id)
        .bind(request.requested_ttl_seconds)
        .bind(request.granted_ttl_seconds)
        .bind(request.outcome.to_string())
        .bind(&request.error_code)
        .bind(&request.error_message)
        .bind(request.duration_ms)
        .bind(&request.source_ip)
        .fetch_one(pool)
        .await
    }

    /// List credential requests for a tenant.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &IdentityCredentialRequestFilter,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = filter.limit.unwrap_or(100);
        let offset = filter.offset.unwrap_or(0);

        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, agent_id, provider_config_id, role_mapping_id,
                requested_ttl_seconds, granted_ttl_seconds, outcome,
                error_code, error_message, duration_ms, source_ip::text, created_at
            FROM identity_credential_requests
            WHERE tenant_id = $1
                AND ($2::uuid IS NULL OR agent_id = $2)
                AND ($3::uuid IS NULL OR provider_config_id = $3)
                AND ($4::text IS NULL OR outcome = $4)
                AND ($5::timestamptz IS NULL OR created_at >= $5)
                AND ($6::timestamptz IS NULL OR created_at <= $6)
            ORDER BY created_at DESC
            LIMIT $7 OFFSET $8
            "#,
            tenant_id,
            filter.agent_id,
            filter.provider_config_id,
            filter.outcome.map(|o| o.to_string()),
            filter.from,
            filter.to,
            limit,
            offset,
        )
        .fetch_all(pool)
        .await
    }

    /// Count credential requests matching filter.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &IdentityCredentialRequestFilter,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM identity_credential_requests
            WHERE tenant_id = $1
                AND ($2::uuid IS NULL OR agent_id = $2)
                AND ($3::uuid IS NULL OR provider_config_id = $3)
                AND ($4::text IS NULL OR outcome = $4)
                AND ($5::timestamptz IS NULL OR created_at >= $5)
                AND ($6::timestamptz IS NULL OR created_at <= $6)
            "#,
            tenant_id,
            filter.agent_id,
            filter.provider_config_id,
            filter.outcome.map(|o| o.to_string()),
            filter.from,
            filter.to,
        )
        .fetch_one(pool)
        .await
    }

    /// Count requests for rate limiting (within last hour).
    pub async fn count_recent_for_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        provider_config_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM identity_credential_requests
            WHERE tenant_id = $1
                AND agent_id = $2
                AND provider_config_id = $3
                AND outcome = 'success'
                AND created_at > now() - interval '1 hour'
            "#,
            tenant_id,
            agent_id,
            provider_config_id,
        )
        .fetch_one(pool)
        .await
    }

    /// Get statistics for a time range.
    pub async fn get_stats(
        pool: &PgPool,
        tenant_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<IdentityCredentialStats, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE outcome = 'success') as "success_count!",
                COUNT(*) FILTER (WHERE outcome = 'denied') as "denied_count!",
                COUNT(*) FILTER (WHERE outcome = 'rate_limited') as "rate_limited_count!",
                COUNT(*) FILTER (WHERE outcome = 'error') as "error_count!",
                AVG(duration_ms) FILTER (WHERE outcome = 'success') as "avg_duration_ms"
            FROM identity_credential_requests
            WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
            "#,
            tenant_id,
            from,
            to,
        )
        .fetch_one(pool)
        .await?;

        Ok(IdentityCredentialStats {
            success_count: row.success_count,
            denied_count: row.denied_count,
            rate_limited_count: row.rate_limited_count,
            error_count: row.error_count,
            avg_duration_ms: row
                .avg_duration_ms
                .and_then(|d| d.to_string().parse::<f64>().ok().map(|f| f as i32)),
        })
    }
}

/// Statistics for credential requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityCredentialStats {
    /// Number of successful requests.
    pub success_count: i64,
    /// Number of denied requests.
    pub denied_count: i64,
    /// Number of rate limited requests.
    pub rate_limited_count: i64,
    /// Number of error requests.
    pub error_count: i64,
    /// Average duration in milliseconds for successful requests.
    pub avg_duration_ms: Option<i32>,
}
