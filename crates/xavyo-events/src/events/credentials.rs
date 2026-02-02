//! Credential events for Dynamic Secrets Provisioning (F120).
//!
//! Events related to ephemeral credential lifecycle:
//! - Credential requested
//! - Credential issued
//! - Credential denied
//! - Credential revoked
//! - Credential expired

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::event::Event;

/// Event emitted when an AI agent requests credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequested {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// AI Agent ID.
    pub agent_id: Uuid,
    /// Secret type requested.
    pub secret_type: String,
    /// Requested TTL in seconds.
    pub requested_ttl_seconds: Option<i32>,
    /// Conversation context.
    pub conversation_id: Option<String>,
    /// Session context.
    pub session_id: Option<String>,
    /// Source IP address.
    pub source_ip: Option<String>,
    /// Request timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Event for CredentialRequested {
    const TOPIC: &'static str = "xavyo.credentials.requested";
    const EVENT_TYPE: &'static str = "xavyo.credentials.requested";
}

/// Event emitted when credentials are successfully issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIssued {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// AI Agent ID.
    pub agent_id: Uuid,
    /// Credential ID.
    pub credential_id: Uuid,
    /// Secret type.
    pub secret_type: String,
    /// Provider type used (openbao, infisical, internal).
    pub provider_type: String,
    /// TTL granted in seconds.
    pub ttl_seconds: i32,
    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,
    /// Issue timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Event for CredentialIssued {
    const TOPIC: &'static str = "xavyo.credentials.issued";
    const EVENT_TYPE: &'static str = "xavyo.credentials.issued";
}

/// Reason for credential denial.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialDenialReason {
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
    /// Permission denied.
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

/// Event emitted when a credential request is denied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDenied {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// AI Agent ID.
    pub agent_id: Uuid,
    /// Secret type requested.
    pub secret_type: String,
    /// Denial reason.
    pub reason: CredentialDenialReason,
    /// Error message.
    pub error_message: String,
    /// Denial timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Event for CredentialDenied {
    const TOPIC: &'static str = "xavyo.credentials.denied";
    const EVENT_TYPE: &'static str = "xavyo.credentials.denied";
}

/// Event emitted when credentials are revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRevoked {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// AI Agent ID.
    pub agent_id: Uuid,
    /// Credential ID.
    pub credential_id: Uuid,
    /// Secret type.
    pub secret_type: String,
    /// Revocation reason (optional).
    pub reason: Option<String>,
    /// Who revoked (user_id or "system").
    pub revoked_by: String,
    /// Revocation timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Event for CredentialRevoked {
    const TOPIC: &'static str = "xavyo.credentials.revoked";
    const EVENT_TYPE: &'static str = "xavyo.credentials.revoked";
}

/// Event emitted when credentials expire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialExpired {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// AI Agent ID.
    pub agent_id: Uuid,
    /// Credential ID.
    pub credential_id: Uuid,
    /// Secret type.
    pub secret_type: String,
    /// Original TTL in seconds.
    pub ttl_seconds: i32,
    /// Issue timestamp.
    pub issued_at: DateTime<Utc>,
    /// Expiration timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Event for CredentialExpired {
    const TOPIC: &'static str = "xavyo.credentials.expired";
    const EVENT_TYPE: &'static str = "xavyo.credentials.expired";
}

/// Event emitted when rate limit is hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRateLimited {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// AI Agent ID.
    pub agent_id: Uuid,
    /// Secret type.
    pub secret_type: String,
    /// Current request count.
    pub current_count: i32,
    /// Rate limit.
    pub limit: i32,
    /// When the rate limit resets.
    pub reset_at: DateTime<Utc>,
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Event for CredentialRateLimited {
    const TOPIC: &'static str = "xavyo.credentials.rate_limited";
    const EVENT_TYPE: &'static str = "xavyo.credentials.rate_limited";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_events_have_topics() {
        assert!(!CredentialRequested::TOPIC.is_empty());
        assert!(!CredentialIssued::TOPIC.is_empty());
        assert!(!CredentialDenied::TOPIC.is_empty());
        assert!(!CredentialRevoked::TOPIC.is_empty());
        assert!(!CredentialExpired::TOPIC.is_empty());
        assert!(!CredentialRateLimited::TOPIC.is_empty());
    }

    #[test]
    fn test_credential_events_follow_convention() {
        assert!(CredentialRequested::TOPIC.starts_with("xavyo."));
        assert!(CredentialIssued::TOPIC.starts_with("xavyo."));
        assert!(CredentialDenied::TOPIC.starts_with("xavyo."));
        assert!(CredentialRevoked::TOPIC.starts_with("xavyo."));
        assert!(CredentialExpired::TOPIC.starts_with("xavyo."));
        assert!(CredentialRateLimited::TOPIC.starts_with("xavyo."));
    }

    #[test]
    fn test_credential_requested_serialization() {
        let event = CredentialRequested {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "postgres-readonly".to_string(),
            requested_ttl_seconds: Some(300),
            conversation_id: Some("conv-123".to_string()),
            session_id: Some("sess-456".to_string()),
            source_ip: Some("192.168.1.1".to_string()),
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("postgres-readonly"));
        assert!(json.contains("conv-123"));
    }

    #[test]
    fn test_credential_denial_reason_serialization() {
        let event = CredentialDenied {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "api-key".to_string(),
            reason: CredentialDenialReason::RateLimitExceeded,
            error_message: "Rate limit exceeded".to_string(),
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("rate_limit_exceeded"));
    }
}
