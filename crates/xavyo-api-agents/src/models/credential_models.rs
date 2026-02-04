//! Request and response models for Dynamic Secrets Provisioning (F120).
//!
//! Defines the API models for requesting and receiving ephemeral credentials.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request context for credential audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CredentialRequestContext {
    /// Conversation ID for audit tracking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<Uuid>,

    /// Session ID for audit tracking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,

    /// User instruction that triggered the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_instruction: Option<String>,
}

/// Request to obtain ephemeral credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CredentialRequest {
    /// Type of secret to request (e.g., "postgres-readonly").
    pub secret_type: String,

    /// Requested TTL in seconds (will not exceed `max_ttl` for type).
    /// If not specified, uses the `default_ttl` for the secret type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i32>,

    /// Request context for audit trail.
    #[serde(default)]
    pub context: CredentialRequestContext,
}

/// Issued credential response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CredentialResponse {
    /// Unique credential identifier (for revocation/audit).
    pub credential_id: Uuid,

    /// The actual credentials (structure depends on secret type).
    pub credentials: serde_json::Value,

    /// When the credential was issued.
    pub issued_at: DateTime<Utc>,

    /// When the credential expires.
    pub expires_at: DateTime<Utc>,

    /// Actual TTL granted (may be less than requested).
    pub ttl_seconds: i32,

    /// Provider that issued the credential.
    pub provider: String,
}

/// Rate limit information header values.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Remaining requests in current window.
    pub remaining: i32,

    /// When rate limit window resets.
    pub reset_at: DateTime<Utc>,
}

/// Credential list response for admin queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CredentialListResponse {
    /// List of credentials.
    pub items: Vec<CredentialSummary>,

    /// Total count.
    pub total: i64,
}

/// Summary of an issued credential (for listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CredentialSummary {
    /// Credential ID.
    pub id: Uuid,

    /// Agent that owns this credential.
    pub agent_id: Uuid,

    /// Secret type.
    pub secret_type: String,

    /// Current status.
    pub status: String,

    /// When issued.
    pub issued_at: DateTime<Utc>,

    /// When it expires.
    pub expires_at: DateTime<Utc>,

    /// Provider that issued it.
    pub provider: String,
}

/// Query parameters for listing credentials.
#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListCredentialsQuery {
    /// Filter by secret type.
    pub secret_type: Option<String>,

    /// Filter by status (active, expired, revoked).
    pub status: Option<String>,

    /// Maximum results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Request to revoke a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeCredentialRequest {
    /// Reason for revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_credential_request_serialization() {
        let request = CredentialRequest {
            secret_type: "postgres-readonly".to_string(),
            ttl_seconds: Some(300),
            context: CredentialRequestContext {
                conversation_id: Some(Uuid::new_v4()),
                session_id: None,
                user_instruction: Some("Query customer data".to_string()),
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("postgres-readonly"));
        assert!(json.contains("ttl_seconds"));
        assert!(json.contains("Query customer data"));
    }

    #[test]
    fn test_credential_request_minimal() {
        let json = r#"{"secret_type": "aws-readonly"}"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.secret_type, "aws-readonly");
        assert!(request.ttl_seconds.is_none());
        assert!(request.context.conversation_id.is_none());
    }

    #[test]
    fn test_credential_response_serialization() {
        let response = CredentialResponse {
            credential_id: Uuid::new_v4(),
            credentials: json!({
                "username": "dynamic_user_123",
                "password": "generated_pwd",
                "host": "db.example.com",
                "port": 5432
            }),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            ttl_seconds: 300,
            provider: "openbao".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("credential_id"));
        assert!(json.contains("dynamic_user_123"));
        assert!(json.contains("openbao"));
    }

    #[test]
    fn test_list_credentials_query_defaults() {
        let query: ListCredentialsQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(query.limit, 50);
        assert_eq!(query.offset, 0);
        assert!(query.secret_type.is_none());
    }
}
