//! Request models for RFC 7009 token revocation.

use serde::Deserialize;

/// RFC 7009 Token Revocation Request (form-encoded).
///
/// Per RFC 7009 Section 2.1:
/// - `token` (REQUIRED): The token to revoke
/// - `token_type_hint` (OPTIONAL): Hint about the token type
/// - `client_id` / `client_secret` (OPTIONAL): Alternative to Basic Auth
#[derive(Debug, Deserialize)]
pub struct RevocationRequest {
    /// The token to revoke (access token JWT or opaque refresh token).
    pub token: String,

    /// Hint about the token type: "access_token" or "refresh_token".
    pub token_type_hint: Option<String>,

    /// Client ID (alternative to HTTP Basic Auth).
    pub client_id: Option<String>,

    /// Client secret (alternative to HTTP Basic Auth).
    pub client_secret: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_request_deserialize_minimal() {
        let form = "token=abc123";
        let req: RevocationRequest = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(req.token, "abc123");
        assert!(req.token_type_hint.is_none());
        assert!(req.client_id.is_none());
        assert!(req.client_secret.is_none());
    }

    #[test]
    fn test_revocation_request_deserialize_full() {
        let form = "token=abc123&token_type_hint=access_token&client_id=cid&client_secret=csec";
        let req: RevocationRequest = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(req.token, "abc123");
        assert_eq!(req.token_type_hint.as_deref(), Some("access_token"));
        assert_eq!(req.client_id.as_deref(), Some("cid"));
        assert_eq!(req.client_secret.as_deref(), Some("csec"));
    }
}
