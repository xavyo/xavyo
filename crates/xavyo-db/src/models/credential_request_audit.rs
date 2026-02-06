//! Credential Request Audit model for dynamic secrets provisioning.
//!
//! Immutable audit log of all credential requests for compliance
//! and security monitoring.
//! Part of the `SecretlessAI` feature (F120).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use std::net::IpAddr;
use uuid::Uuid;

// NOTE: PostgreSQL INET type maps to String in sqlx.
// Use source_ip_addr() helper for parsing to IpAddr when needed.

/// Outcome of a credential request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRequestOutcome {
    /// Request succeeded, credentials issued.
    Success,
    /// Request denied (no permission, agent suspended, etc.).
    Denied,
    /// Request denied due to rate limiting.
    RateLimited,
    /// Request failed due to an error.
    Error,
}

impl std::fmt::Display for CredentialRequestOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialRequestOutcome::Success => write!(f, "success"),
            CredentialRequestOutcome::Denied => write!(f, "denied"),
            CredentialRequestOutcome::RateLimited => write!(f, "rate_limited"),
            CredentialRequestOutcome::Error => write!(f, "error"),
        }
    }
}

impl std::str::FromStr for CredentialRequestOutcome {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "success" => Ok(CredentialRequestOutcome::Success),
            "denied" => Ok(CredentialRequestOutcome::Denied),
            "rate_limited" => Ok(CredentialRequestOutcome::RateLimited),
            "error" => Ok(CredentialRequestOutcome::Error),
            _ => Err(format!("Invalid credential request outcome: {s}")),
        }
    }
}

/// Error codes for credential requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrorCode {
    /// Agent not found.
    AgentNotFound,
    /// Agent is suspended.
    AgentSuspended,
    /// Agent has expired.
    AgentExpired,
    /// Secret type not found.
    SecretTypeNotFound,
    /// Secret type is disabled.
    SecretTypeDisabled,
    /// Agent lacks permission for this secret type.
    PermissionDenied,
    /// Permission has expired.
    PermissionExpired,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Provider unavailable.
    ProviderUnavailable,
    /// Provider timeout.
    ProviderTimeout,
    /// Provider authentication failed.
    ProviderAuthFailed,
    /// Invalid TTL requested.
    InvalidTtl,
    /// Internal error.
    InternalError,
}

impl std::fmt::Display for CredentialErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialErrorCode::AgentNotFound => write!(f, "agent_not_found"),
            CredentialErrorCode::AgentSuspended => write!(f, "agent_suspended"),
            CredentialErrorCode::AgentExpired => write!(f, "agent_expired"),
            CredentialErrorCode::SecretTypeNotFound => write!(f, "secret_type_not_found"),
            CredentialErrorCode::SecretTypeDisabled => write!(f, "secret_type_disabled"),
            CredentialErrorCode::PermissionDenied => write!(f, "permission_denied"),
            CredentialErrorCode::PermissionExpired => write!(f, "permission_expired"),
            CredentialErrorCode::RateLimitExceeded => write!(f, "rate_limit_exceeded"),
            CredentialErrorCode::ProviderUnavailable => write!(f, "provider_unavailable"),
            CredentialErrorCode::ProviderTimeout => write!(f, "provider_timeout"),
            CredentialErrorCode::ProviderAuthFailed => write!(f, "provider_auth_failed"),
            CredentialErrorCode::InvalidTtl => write!(f, "invalid_ttl"),
            CredentialErrorCode::InternalError => write!(f, "internal_error"),
        }
    }
}

/// Audit record for a credential request.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CredentialRequestAudit {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this audit record belongs to.
    pub tenant_id: Uuid,

    /// Agent that made the request.
    pub agent_id: Uuid,

    /// Secret type requested.
    pub secret_type: String,

    /// Outcome of the request.
    pub outcome: String,

    /// TTL granted (if successful).
    pub ttl_granted: Option<i32>,

    /// Error code (if denied/error).
    pub error_code: Option<String>,

    /// Source IP of the request (stored as string, use `source_ip_addr()` for parsing).
    pub source_ip: Option<String>,

    /// User agent string.
    pub user_agent: Option<String>,

    /// Request processing latency in milliseconds.
    pub latency_ms: f32,

    /// Additional context (`conversation_id`, `session_id`, etc.).
    pub context: Option<JsonValue>,

    /// When the request was made.
    pub created_at: DateTime<Utc>,
}

impl CredentialRequestAudit {
    /// Parse the outcome as an enum.
    pub fn outcome_enum(&self) -> Result<CredentialRequestOutcome, String> {
        self.outcome.parse()
    }

    /// Check if the request was successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.outcome == "success"
    }

    /// Parse the source IP as an `IpAddr`.
    #[must_use]
    pub fn source_ip_addr(&self) -> Option<IpAddr> {
        self.source_ip.as_ref().and_then(|s| s.parse().ok())
    }
}

/// Request to create a new audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCredentialRequestAudit {
    /// Agent that made the request.
    pub agent_id: Uuid,

    /// Secret type requested.
    pub secret_type: String,

    /// Outcome of the request.
    pub outcome: CredentialRequestOutcome,

    /// TTL granted (if successful).
    pub ttl_granted: Option<i32>,

    /// Error code (if denied/error).
    pub error_code: Option<CredentialErrorCode>,

    /// Source IP of the request (as string).
    pub source_ip: Option<String>,

    /// User agent string.
    pub user_agent: Option<String>,

    /// Request processing latency in milliseconds.
    pub latency_ms: f32,

    /// Additional context.
    pub context: Option<JsonValue>,
}

/// Filter options for listing audit records.
#[derive(Debug, Clone, Default)]
pub struct CredentialRequestAuditFilter {
    /// Filter by agent ID.
    pub agent_id: Option<Uuid>,

    /// Filter by secret type.
    pub secret_type: Option<String>,

    /// Filter by outcome.
    pub outcome: Option<String>,

    /// Filter by start time (inclusive).
    pub from_time: Option<DateTime<Utc>>,

    /// Filter by end time (exclusive).
    pub to_time: Option<DateTime<Utc>>,
}

/// Audit context for credential requests.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CredentialRequestContext {
    /// Conversation ID (for tracing).
    pub conversation_id: Option<Uuid>,

    /// Session ID (for tracing).
    pub session_id: Option<Uuid>,

    /// User instruction that triggered the request.
    pub user_instruction: Option<String>,
}

impl CredentialRequestAudit {
    /// Insert a new audit record (append-only).
    pub async fn insert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateCredentialRequestAudit,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO credential_request_audit (
                tenant_id, agent_id, secret_type, outcome, ttl_granted,
                error_code, source_ip, user_agent, latency_ms, context
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.agent_id)
        .bind(&input.secret_type)
        .bind(input.outcome.to_string())
        .bind(input.ttl_granted)
        .bind(input.error_code.map(|c| c.to_string()))
        .bind(input.source_ip)
        .bind(&input.user_agent)
        .bind(input.latency_ms)
        .bind(&input.context)
        .fetch_one(pool)
        .await
    }

    /// Find an audit record by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM credential_request_audit
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List audit records for a tenant with filtering.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CredentialRequestAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM credential_request_audit
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.agent_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND agent_id = ${param_count}"));
        }

        if filter.secret_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND secret_type = ${param_count}"));
        }

        if filter.outcome.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND outcome = ${param_count}"));
        }

        if filter.from_time.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }

        if filter.to_time.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at < ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, CredentialRequestAudit>(&query).bind(tenant_id);

        if let Some(agent_id) = filter.agent_id {
            q = q.bind(agent_id);
        }
        if let Some(ref secret_type) = filter.secret_type {
            q = q.bind(secret_type);
        }
        if let Some(ref outcome) = filter.outcome {
            q = q.bind(outcome);
        }
        if let Some(from_time) = filter.from_time {
            q = q.bind(from_time);
        }
        if let Some(to_time) = filter.to_time {
            q = q.bind(to_time);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count audit records for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CredentialRequestAuditFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM credential_request_audit
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.agent_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND agent_id = ${param_count}"));
        }

        if filter.secret_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND secret_type = ${param_count}"));
        }

        if filter.outcome.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND outcome = ${param_count}"));
        }

        if filter.from_time.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }

        if filter.to_time.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at < ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(agent_id) = filter.agent_id {
            q = q.bind(agent_id);
        }
        if let Some(ref secret_type) = filter.secret_type {
            q = q.bind(secret_type);
        }
        if let Some(ref outcome) = filter.outcome {
            q = q.bind(outcome);
        }
        if let Some(from_time) = filter.from_time {
            q = q.bind(from_time);
        }
        if let Some(to_time) = filter.to_time {
            q = q.bind(to_time);
        }

        q.fetch_one(pool).await
    }

    /// Count requests for an agent within a time window (for rate limiting).
    pub async fn count_requests_in_window(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        secret_type: &str,
        window_start: DateTime<Utc>,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM credential_request_audit
            WHERE tenant_id = $1 AND agent_id = $2 AND secret_type = $3
            AND created_at >= $4 AND outcome = 'success'
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(secret_type)
        .bind(window_start)
        .fetch_one(pool)
        .await
    }

    /// Get audit statistics for an agent.
    pub async fn get_agent_stats(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<AuditStats, sqlx::Error> {
        let row = sqlx::query_as::<_, AuditStatsRow>(
            r"
            SELECT
                COUNT(*) as total_requests,
                COUNT(*) FILTER (WHERE outcome = 'success') as successful_requests,
                COUNT(*) FILTER (WHERE outcome = 'denied') as denied_requests,
                COUNT(*) FILTER (WHERE outcome = 'rate_limited') as rate_limited_requests,
                COUNT(*) FILTER (WHERE outcome = 'error') as error_requests,
                COALESCE(AVG(latency_ms), 0) as avg_latency_ms
            FROM credential_request_audit
            WHERE tenant_id = $1 AND agent_id = $2 AND created_at >= $3
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(AuditStats {
            total_requests: row.total_requests,
            successful_requests: row.successful_requests,
            denied_requests: row.denied_requests,
            rate_limited_requests: row.rate_limited_requests,
            error_requests: row.error_requests,
            avg_latency_ms: row.avg_latency_ms,
        })
    }
}

#[derive(Debug, Clone, FromRow)]
struct AuditStatsRow {
    total_requests: i64,
    successful_requests: i64,
    denied_requests: i64,
    rate_limited_requests: i64,
    error_requests: i64,
    avg_latency_ms: f64,
}

/// Aggregated audit statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditStats {
    /// Total number of requests.
    pub total_requests: i64,

    /// Number of successful requests.
    pub successful_requests: i64,

    /// Number of denied requests.
    pub denied_requests: i64,

    /// Number of rate-limited requests.
    pub rate_limited_requests: i64,

    /// Number of error requests.
    pub error_requests: i64,

    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outcome_display() {
        assert_eq!(CredentialRequestOutcome::Success.to_string(), "success");
        assert_eq!(CredentialRequestOutcome::Denied.to_string(), "denied");
        assert_eq!(
            CredentialRequestOutcome::RateLimited.to_string(),
            "rate_limited"
        );
        assert_eq!(CredentialRequestOutcome::Error.to_string(), "error");
    }

    #[test]
    fn test_outcome_from_str() {
        assert_eq!(
            "success".parse::<CredentialRequestOutcome>().unwrap(),
            CredentialRequestOutcome::Success
        );
        assert_eq!(
            "DENIED".parse::<CredentialRequestOutcome>().unwrap(),
            CredentialRequestOutcome::Denied
        );
        assert!("invalid".parse::<CredentialRequestOutcome>().is_err());
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(
            CredentialErrorCode::AgentNotFound.to_string(),
            "agent_not_found"
        );
        assert_eq!(
            CredentialErrorCode::RateLimitExceeded.to_string(),
            "rate_limit_exceeded"
        );
        assert_eq!(
            CredentialErrorCode::ProviderUnavailable.to_string(),
            "provider_unavailable"
        );
    }

    #[test]
    fn test_audit_is_success() {
        let audit = CredentialRequestAudit {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "test-type".to_string(),
            outcome: "success".to_string(),
            ttl_granted: Some(300),
            error_code: None,
            source_ip: None,
            user_agent: None,
            latency_ms: 50.0,
            context: None,
            created_at: Utc::now(),
        };

        assert!(audit.is_success());
        assert_eq!(
            audit.outcome_enum().unwrap(),
            CredentialRequestOutcome::Success
        );

        let denied = CredentialRequestAudit {
            outcome: "denied".to_string(),
            ..audit
        };
        assert!(!denied.is_success());
    }
}
