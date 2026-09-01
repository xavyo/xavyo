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
/// The old secret is immediately invalidated per `OAuth2` security best practices.
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

    /// Public `client_id` string (used in OAuth flows).
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
#[derive(Debug, Clone, Serialize, ToSchema, Default)]
pub struct OAuthClientDetails {
    /// Internal unique identifier for the OAuth client.
    pub id: Uuid,

    /// Public `client_id` string (used in OAuth flows).
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

    /// Client logo URL (shown on consent page).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,

    /// Client description (shown on consent page).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Bound NHI identity (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nhi_id: Option<Uuid>,

    /// Allowed post-logout redirect URIs (OIDC RP-Initiated Logout).
    pub post_logout_redirect_uris: Vec<String>,

    /// RFC 9449: client requires DPoP-bound tokens.
    pub require_dpop: bool,

    /// FAPI 2.0 Security Profile opt-in.
    pub fapi_profile: bool,

    /// Inline JWKS for `private_key_jwt`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,

    /// Registered mTLS cert thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_cert_thumbprint: Option<String>,

    /// When the OAuth client was created.
    pub created_at: DateTime<Utc>,

    /// When the OAuth client was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<xavyo_api_oauth::models::ClientResponse> for OAuthClientDetails {
    fn from(c: xavyo_api_oauth::models::ClientResponse) -> Self {
        Self {
            id: c.id,
            client_id: c.client_id,
            name: c.name,
            client_type: c.client_type.to_string(),
            redirect_uris: c.redirect_uris,
            grant_types: c.grant_types,
            scopes: c.scopes,
            is_active: c.is_active,
            logo_url: c.logo_url,
            description: c.description,
            nhi_id: c.nhi_id,
            post_logout_redirect_uris: c.post_logout_redirect_uris,
            require_dpop: c.require_dpop,
            fapi_profile: c.fapi_profile,
            jwks: c.jwks,
            tls_client_cert_thumbprint: c.tls_client_cert_thumbprint,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
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
            logo_url: Some("https://example.com/logo.png".to_string()),
            description: Some("App".to_string()),
            nhi_id: Some(Uuid::new_v4()),
            post_logout_redirect_uris: vec!["https://example.com/logout".to_string()],
            require_dpop: true,
            fapi_profile: true,
            jwks: Some(serde_json::json!({"keys": []})),
            tls_client_cert_thumbprint: Some("abc".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["name"], "My Application");
        assert_eq!(json["client_type"], "confidential");
        assert_eq!(json["require_dpop"], true);
        assert_eq!(json["fapi_profile"], true);
        assert_eq!(
            json["post_logout_redirect_uris"][0],
            "https://example.com/logout"
        );
        assert_eq!(json["logo_url"], "https://example.com/logo.png");
    }

    #[test]
    fn tenant_list_details_round_trip_advertised_fields() {
        use xavyo_api_oauth::models::{ClientResponse, ClientType};

        let now = Utc::now();
        let nhi = Uuid::new_v4();
        let details = OAuthClientDetails::from(ClientResponse {
            id: Uuid::new_v4(),
            client_id: "cid".to_string(),
            name: "app".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: vec!["https://ex/cb".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            scopes: vec!["openid".to_string()],
            is_active: true,
            logo_url: Some("https://ex/logo.png".to_string()),
            description: Some("d".to_string()),
            nhi_id: Some(nhi),
            post_logout_redirect_uris: vec!["https://ex/logout".to_string()],
            created_at: now,
            updated_at: now,
            require_dpop: true,
            fapi_profile: true,
            jwks: Some(serde_json::json!({"keys": []})),
            tls_client_cert_thumbprint: Some("thumb".to_string()),
        });
        assert!(details.require_dpop);
        assert!(details.fapi_profile);
        assert_eq!(details.nhi_id, Some(nhi));
        assert_eq!(details.client_type, "confidential");
        assert_eq!(details.post_logout_redirect_uris.len(), 1);
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
