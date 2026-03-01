//! Shared client authentication utilities for `OAuth2` endpoints.
//!
//! Extracts and validates `OAuth2` client credentials from HTTP Basic Auth
//! or form body parameters. Used by token, revocation, and introspection handlers.

use crate::error::OAuthError;
use crate::services::client::OAuth2ClientService;
use axum::http::{header, HeaderMap};
use base64::{engine::general_purpose::STANDARD, Engine};
use uuid::Uuid;

/// Extract client credentials from Authorization header or form body parameters.
///
/// Supports two methods per RFC 6749 Section 2.3:
/// 1. HTTP Basic Auth: `Authorization: Basic base64(client_id:client_secret)`
/// 2. Body parameters: `client_id` and `client_secret` in form body
///
/// Returns `(client_id, Option<client_secret>)`.
pub fn extract_client_credentials(
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
) -> Result<(String, Option<String>), OAuthError> {
    // Try HTTP Basic authentication first
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| OAuthError::InvalidClient("Invalid authorization header".to_string()))?;

        if let Some(credentials) = auth_str.strip_prefix("Basic ") {
            let decoded = STANDARD.decode(credentials).map_err(|_| {
                OAuthError::InvalidClient("Invalid base64 in authorization header".to_string())
            })?;

            let decoded_str = String::from_utf8(decoded).map_err(|_| {
                OAuthError::InvalidClient("Invalid UTF-8 in credentials".to_string())
            })?;

            let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
            if parts.len() == 2 {
                return Ok((parts[0].to_string(), Some(parts[1].to_string())));
            }
            return Err(OAuthError::InvalidClient(
                "Invalid credential format".to_string(),
            ));
        }
    }

    // Fall back to body parameters
    let client_id = body_client_id
        .filter(|s| !s.is_empty())
        .map(String::from)
        .ok_or_else(|| OAuthError::InvalidRequest("client_id is required".to_string()))?;

    Ok((client_id, body_client_secret.map(String::from)))
}

/// Extract tenant ID from the `X-Tenant-ID` request header.
///
/// Used by `OAuth2` endpoints (revocation, introspection) that authenticate
/// via client credentials rather than JWT claims.
pub fn extract_tenant_from_header(headers: &HeaderMap) -> Result<Uuid, OAuthError> {
    let tenant_str = headers
        .get("x-tenant-id")
        .ok_or_else(|| OAuthError::InvalidRequest("Missing X-Tenant-ID header".to_string()))?
        .to_str()
        .map_err(|_| OAuthError::InvalidRequest("Invalid X-Tenant-ID header".to_string()))?;

    tenant_str
        .parse::<Uuid>()
        .map_err(|_| OAuthError::InvalidRequest("X-Tenant-ID is not a valid UUID".to_string()))
}

/// Authenticate an `OAuth2` client using extracted credentials.
///
/// Looks up the client by `client_id` within the given tenant, then verifies
/// the `client_secret` against the stored hash.
///
/// Returns the internal client UUID on success.
pub async fn authenticate_client(
    client_service: &OAuth2ClientService,
    tenant_id: Uuid,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<Uuid, OAuthError> {
    match client_secret {
        Some(secret) => {
            let client = client_service
                .verify_client_credentials(tenant_id, client_id, secret)
                .await?;
            Ok(client.id)
        }
        None => {
            // Public clients authenticate with client_id only (RFC 7009 Section 2.1)
            let client = client_service
                .verify_public_client(tenant_id, client_id)
                .await?;
            Ok(client.id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_from_basic_auth() {
        let mut headers = HeaderMap::new();
        // "my-client:my-secret" in base64
        let encoded = STANDARD.encode("my-client:my-secret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );

        let (id, secret) = extract_client_credentials(&headers, None, None).unwrap();
        assert_eq!(id, "my-client");
        assert_eq!(secret, Some("my-secret".to_string()));
    }

    #[test]
    fn test_extract_from_body_params() {
        let headers = HeaderMap::new();
        let (id, secret) =
            extract_client_credentials(&headers, Some("body-client"), Some("body-secret")).unwrap();
        assert_eq!(id, "body-client");
        assert_eq!(secret, Some("body-secret".to_string()));
    }

    #[test]
    fn test_basic_auth_takes_precedence() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("header-client:header-secret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );

        let (id, _) =
            extract_client_credentials(&headers, Some("body-client"), Some("body-secret")).unwrap();
        assert_eq!(id, "header-client");
    }

    #[test]
    fn test_missing_client_id_error() {
        let headers = HeaderMap::new();
        let result = extract_client_credentials(&headers, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_client_id_error() {
        let headers = HeaderMap::new();
        let result = extract_client_credentials(&headers, Some(""), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_basic_auth_colon_in_password() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("my-client:my:complex:secret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );

        let (id, secret) = extract_client_credentials(&headers, None, None).unwrap();
        assert_eq!(id, "my-client");
        assert_eq!(secret, Some("my:complex:secret".to_string()));
    }

    #[test]
    fn test_extract_tenant_valid() {
        let mut headers = HeaderMap::new();
        let tid = Uuid::new_v4();
        headers.insert("x-tenant-id", tid.to_string().parse().unwrap());
        let result = extract_tenant_from_header(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tid);
    }

    #[test]
    fn test_extract_tenant_missing() {
        let headers = HeaderMap::new();
        let result = extract_tenant_from_header(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_tenant_invalid_uuid() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-id", "not-a-uuid".parse().unwrap());
        let result = extract_tenant_from_header(&headers);
        assert!(result.is_err());
    }
}
