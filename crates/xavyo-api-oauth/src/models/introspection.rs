//! Request and response models for RFC 7662 token introspection.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// RFC 7662 Token Introspection Request (form-encoded).
///
/// Per RFC 7662 Section 2.1:
/// - `token` (REQUIRED): The token to introspect
/// - `token_type_hint` (OPTIONAL): Hint about the token type
/// - `client_id` / `client_secret` (OPTIONAL): Alternative to Basic Auth
#[derive(Debug, Deserialize)]
pub struct IntrospectionRequest {
    /// The token to introspect.
    pub token: String,

    /// Hint about the token type: "access_token" or "refresh_token".
    pub token_type_hint: Option<String>,

    /// Client ID (alternative to HTTP Basic Auth).
    pub client_id: Option<String>,

    /// Client secret (alternative to HTTP Basic Auth).
    pub client_secret: Option<String>,
}

/// RFC 7662 Token Introspection Response.
///
/// Per RFC 7662 Section 2.2:
/// - `active` (REQUIRED): Whether the token is currently active
/// - All other fields are OPTIONAL and only present when active=true
#[derive(Debug, Serialize)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active (valid, not expired, not revoked).
    pub active: bool,

    /// Subject (user_id or client_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// OAuth2 client that requested the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Space-separated scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Expiration time (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Issued at time (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// Token type (e.g., "Bearer").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// JWT ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Tenant ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<Uuid>,
}

impl IntrospectionResponse {
    /// Create an inactive response (token is invalid, expired, or revoked).
    ///
    /// Per RFC 7662: inactive tokens return only `{ "active": false }`.
    pub fn inactive() -> Self {
        Self {
            active: false,
            sub: None,
            client_id: None,
            scope: None,
            exp: None,
            iat: None,
            token_type: None,
            aud: None,
            iss: None,
            jti: None,
            tid: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inactive_response_serialization() {
        let resp = IntrospectionResponse::inactive();
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"active":false}"#);
    }

    #[test]
    fn test_active_response_serialization() {
        let resp = IntrospectionResponse {
            active: true,
            sub: Some("user-123".to_string()),
            client_id: Some("my-client".to_string()),
            scope: Some("openid profile".to_string()),
            exp: Some(1706400000),
            iat: Some(1706399100),
            token_type: Some("Bearer".to_string()),
            aud: None,
            iss: Some("https://idp.xavyo.com".to_string()),
            jti: Some("test-jti".to_string()),
            tid: None,
        };

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"active\":true"));
        assert!(json.contains("\"sub\":\"user-123\""));
        assert!(json.contains("\"scope\":\"openid profile\""));
        // Optional None fields should not appear
        assert!(!json.contains("\"aud\""));
        assert!(!json.contains("\"tid\""));
    }

    #[test]
    fn test_introspection_request_deserialize() {
        let form = "token=abc&token_type_hint=access_token";
        let req: IntrospectionRequest = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(req.token, "abc");
        assert_eq!(req.token_type_hint.as_deref(), Some("access_token"));
    }
}
