//! Request and response models for admin session management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to revoke all tokens for a user (admin).
#[derive(Debug, Deserialize)]
pub struct AdminRevokeUserRequest {
    /// The user whose tokens to revoke.
    pub user_id: Uuid,

    /// Optional reason for revocation.
    pub reason: Option<String>,
}

/// Response after revoking all user tokens.
#[derive(Debug, Serialize)]
pub struct AdminRevokeUserResponse {
    /// The user whose tokens were revoked.
    pub user_id: Uuid,

    /// Number of refresh tokens revoked.
    pub refresh_tokens_revoked: i64,

    /// Whether access tokens were blacklisted.
    pub access_tokens_blacklisted: bool,

    /// Timestamp of revocation.
    pub revoked_at: DateTime<Utc>,
}

/// Response listing active sessions for a user.
#[derive(Debug, Serialize)]
pub struct ActiveSessionsResponse {
    /// List of active sessions (non-revoked, non-expired refresh tokens).
    pub sessions: Vec<SessionInfo>,

    /// Total number of active sessions.
    pub total: usize,
}

/// Information about an active session (refresh token).
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    /// Refresh token record ID.
    pub id: Uuid,

    /// OAuth2 client internal ID.
    pub client_id: Uuid,

    /// OAuth2 client display name.
    pub client_name: String,

    /// Granted scopes.
    pub scope: String,

    /// When the session was created.
    pub created_at: DateTime<Utc>,

    /// When the session expires.
    pub expires_at: DateTime<Utc>,
}

/// Response after revoking a specific session.
#[derive(Debug, Serialize)]
pub struct SessionRevokedResponse {
    /// ID of the revoked session.
    pub token_id: Uuid,

    /// Timestamp of revocation.
    pub revoked_at: DateTime<Utc>,

    /// Confirmation message.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_revoke_user_request_deserialize() {
        let json = r#"{"user_id":"550e8400-e29b-41d4-a716-446655440000","reason":"compromised"}"#;
        let req: AdminRevokeUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.user_id,
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
        );
        assert_eq!(req.reason.as_deref(), Some("compromised"));
    }

    #[test]
    fn test_admin_revoke_user_request_without_reason() {
        let json = r#"{"user_id":"550e8400-e29b-41d4-a716-446655440000"}"#;
        let req: AdminRevokeUserRequest = serde_json::from_str(json).unwrap();
        assert!(req.reason.is_none());
    }

    #[test]
    fn test_active_sessions_response_serialization() {
        let resp = ActiveSessionsResponse {
            sessions: vec![],
            total: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"sessions\":[]"));
        assert!(json.contains("\"total\":0"));
    }
}
