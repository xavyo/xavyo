//! DTOs for OAuth client management operations.
//!
//! F-SECRET-ROTATE: Request and response types for OAuth client secret rotation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Request to rotate an OAuth client secret.
///
/// Note: Unlike API keys, OAuth client secrets do not support a grace period.
/// The old secret is immediately invalidated per OAuth2 security best practices.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct RotateOAuthSecretRequest {
    // Currently no options - OAuth2 spec requires immediate rotation
    // This struct exists for future extensibility
}

/// Response after rotating an OAuth client secret.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RotateOAuthSecretResponse {
    /// Internal ID of the OAuth client.
    pub client_id: Uuid,

    /// Public client_id string (used in OAuth flows).
    pub public_client_id: String,

    /// The new client secret in plaintext.
    /// SECURITY: This is shown only once and cannot be retrieved later.
    #[schema(example = "a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234")]
    pub new_client_secret: String,

    /// Timestamp when the rotation occurred.
    pub rotated_at: DateTime<Utc>,

    /// Whether all refresh tokens were revoked (always true).
    pub refresh_tokens_revoked: bool,
}

/// Information about an OAuth client (without the secret).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OAuthClientDetails {
    /// Internal unique identifier for the OAuth client.
    pub id: Uuid,

    /// Public client_id string (used in OAuth flows).
    pub client_id: String,

    /// Human-readable name for the OAuth client.
    pub name: String,

    /// Client type: "confidential" or "public".
    pub client_type: String,

    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,

    /// Allowed grant types.
    pub grant_types: Vec<String>,

    /// Allowed scopes.
    pub scopes: Vec<String>,

    /// Whether the OAuth client is active.
    pub is_active: bool,

    /// When the OAuth client was created.
    pub created_at: DateTime<Utc>,

    /// When the OAuth client was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Response containing a list of OAuth clients.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OAuthClientListResponse {
    /// List of OAuth clients.
    pub oauth_clients: Vec<OAuthClientDetails>,

    /// Total number of OAuth clients.
    pub total: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotate_request_default() {
        let request = RotateOAuthSecretRequest::default();
        // Just verify it can be created with defaults
        let _ = request;
    }

    #[test]
    fn test_rotate_response_serialization() {
        let response = RotateOAuthSecretResponse {
            client_id: Uuid::new_v4(),
            public_client_id: "test_client_123".to_string(),
            new_client_secret: "abcdef123456".to_string(),
            rotated_at: Utc::now(),
            refresh_tokens_revoked: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("client_id"));
        assert!(json.contains("new_client_secret"));
        assert!(json.contains("refresh_tokens_revoked"));
    }

    #[test]
    fn test_oauth_client_info_serialization() {
        let info = OAuthClientDetails {
            id: Uuid::new_v4(),
            client_id: "my_app_client".to_string(),
            name: "My Application".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            scopes: vec!["openid".to_string(), "profile".to_string()],
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("My Application"));
        assert!(json.contains("confidential"));
        assert!(json.contains("authorization_code"));
    }

    #[test]
    fn test_oauth_client_list_response() {
        let response = OAuthClientListResponse {
            oauth_clients: vec![],
            total: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":0"));
    }
}
