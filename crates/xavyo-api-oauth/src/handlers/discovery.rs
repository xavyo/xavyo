//! OIDC Discovery and MCP Authorization metadata endpoint handlers.

use crate::models::{
    Jwk, JwkSet, McpClientMetadata, OpenIdConfiguration, ProtectedResourceMetadata,
};
use crate::router::OAuthState;
use axum::{extract::State, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;

/// Returns the `OpenID` Connect Discovery document.
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    responses(
        (status = 200, description = "OIDC Discovery document", body = OpenIdConfiguration),
    ),
    tag = "OIDC Discovery"
)]
pub async fn discovery_handler(State(state): State<OAuthState>) -> Json<OpenIdConfiguration> {
    let config = OpenIdConfiguration::new(&state.issuer);
    Json(config)
}

/// Returns the JSON Web Key Set containing public keys for token verification.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    responses(
        (status = 200, description = "JSON Web Key Set", body = JwkSet),
    ),
    tag = "OIDC Discovery"
)]
pub async fn jwks_handler(State(state): State<OAuthState>) -> Json<JwkSet> {
    let mut jwk_set = JwkSet::new();

    // Add all signing keys to the JWKS (F069-S5: multi-key rotation support)
    if state.signing_keys.is_empty() {
        // Fallback to single key for backward compatibility
        match create_jwk_from_pem(&state.public_key, &state.key_id) {
            Ok(jwk) => {
                jwk_set = jwk_set.add_key(jwk);
            }
            Err(e) => {
                tracing::error!("Failed to create JWK from public key: {}", e);
            }
        }
    } else {
        for key in &state.signing_keys {
            match create_jwk_from_pem(key.public_key_pem.as_bytes(), &key.kid) {
                Ok(jwk) => {
                    jwk_set = jwk_set.add_key(jwk);
                }
                Err(e) => {
                    tracing::error!(kid = %key.kid, "Failed to create JWK from public key: {}", e);
                }
            }
        }
    }

    Json(jwk_set)
}

/// Returns RFC 9728 Protected Resource Metadata.
///
/// MCP clients use this endpoint to discover which authorization server
/// to use for obtaining tokens accepted by this resource server.
#[utoipa::path(
    get,
    path = "/.well-known/oauth-protected-resource",
    responses(
        (status = 200, description = "Protected Resource Metadata (RFC 9728)", body = ProtectedResourceMetadata),
    ),
    tag = "MCP Authorization"
)]
pub async fn protected_resource_handler(
    State(state): State<OAuthState>,
) -> Json<ProtectedResourceMetadata> {
    let metadata = ProtectedResourceMetadata::new(&state.issuer, &state.issuer);
    Json(metadata)
}

/// Returns MCP Client Metadata for a dynamically registered client.
///
/// MCP authorization servers can use this to learn about client capabilities
/// without pre-registration (zero-registration MCP pattern).
#[utoipa::path(
    get,
    path = "/.well-known/mcp-client-metadata",
    responses(
        (status = 200, description = "MCP Client Metadata Document", body = McpClientMetadata),
    ),
    tag = "MCP Authorization"
)]
pub async fn mcp_client_metadata_handler(
    State(state): State<OAuthState>,
) -> Json<McpClientMetadata> {
    let client_id = format!("{}/mcp", state.issuer);
    let redirect_uris = vec![
        format!("{}/oauth/callback", state.issuer),
        "http://localhost:8080/callback".to_string(), // Local MCP clients
    ];

    let mut metadata = McpClientMetadata::new(&client_id, redirect_uris);
    metadata.client_name = Some("xavyo MCP Client".to_string());
    metadata.scope = Some("openid profile email crm:read crm:write tools:execute".to_string());
    metadata.client_uri = Some(state.issuer.clone());
    Json(metadata)
}

/// Create a JWK from a PEM-encoded RSA public key.
fn create_jwk_from_pem(pem_data: &[u8], key_id: &str) -> Result<Jwk, String> {
    use pkcs8::DecodePublicKey;

    // Parse PEM to string
    let pem_str =
        std::str::from_utf8(pem_data).map_err(|e| format!("Invalid PEM encoding: {e}"))?;

    // Try to parse as RSA public key from PEM
    let public_key = RsaPublicKey::from_public_key_pem(pem_str)
        .map_err(|e| format!("Failed to parse RSA public key: {e}"))?;

    // Extract n (modulus) and e (exponent)
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();

    // Encode as base64url
    let n = URL_SAFE_NO_PAD.encode(&n_bytes);
    let e = URL_SAFE_NO_PAD.encode(&e_bytes);

    Ok(Jwk {
        kty: "RSA".to_string(),
        kid: key_id.to_string(),
        key_use: "sig".to_string(),
        alg: "RS256".to_string(),
        n,
        e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openid_configuration_creation() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        assert_eq!(config.issuer, "https://idp.example.com");
        assert_eq!(
            config.authorization_endpoint,
            "https://idp.example.com/oauth/authorize"
        );
        assert_eq!(config.token_endpoint, "https://idp.example.com/oauth/token");
        assert_eq!(
            config.userinfo_endpoint,
            "https://idp.example.com/oauth/userinfo"
        );
        assert_eq!(
            config.jwks_uri,
            "https://idp.example.com/.well-known/jwks.json"
        );
        assert!(config
            .response_types_supported
            .contains(&"code".to_string()));
        assert!(config
            .code_challenge_methods_supported
            .contains(&"S256".to_string()));
        assert!(config.scopes_supported.contains(&"openid".to_string()));
        assert!(config.scopes_supported.contains(&"profile".to_string()));
        assert!(config.scopes_supported.contains(&"email".to_string()));
        assert!(config
            .scopes_supported
            .contains(&"offline_access".to_string()));
    }

    #[test]
    fn test_openid_configuration_grants() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        assert!(config
            .grant_types_supported
            .contains(&"authorization_code".to_string()));
        assert!(config
            .grant_types_supported
            .contains(&"client_credentials".to_string()));
        assert!(config
            .grant_types_supported
            .contains(&"refresh_token".to_string()));
        // RFC 8628: Device code grant
        assert!(config
            .grant_types_supported
            .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string()));
    }

    #[test]
    fn test_openid_configuration_device_authorization() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        // RFC 8628: Device authorization endpoint
        assert_eq!(
            config.device_authorization_endpoint,
            Some("https://idp.example.com/oauth/device/code".to_string())
        );
    }

    #[test]
    fn test_openid_configuration_signing() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        assert!(config
            .id_token_signing_alg_values_supported
            .contains(&"RS256".to_string()));
    }

    #[test]
    fn test_openid_configuration_claims() {
        let config = OpenIdConfiguration::new("https://idp.example.com");

        // Required OIDC claims
        assert!(config.claims_supported.contains(&"sub".to_string()));
        assert!(config.claims_supported.contains(&"iss".to_string()));
        assert!(config.claims_supported.contains(&"aud".to_string()));
        assert!(config.claims_supported.contains(&"exp".to_string()));
        assert!(config.claims_supported.contains(&"iat".to_string()));

        // Profile claims
        assert!(config.claims_supported.contains(&"name".to_string()));

        // Email claims
        assert!(config.claims_supported.contains(&"email".to_string()));
        assert!(config
            .claims_supported
            .contains(&"email_verified".to_string()));
    }

    #[test]
    fn test_protected_resource_metadata() {
        let metadata =
            ProtectedResourceMetadata::new("https://api.example.com", "https://idp.example.com");

        assert_eq!(metadata.resource, "https://api.example.com");
        assert_eq!(metadata.authorization_servers.len(), 1);
        assert_eq!(metadata.authorization_servers[0], "https://idp.example.com");
        assert!(metadata
            .scopes_supported
            .as_ref()
            .unwrap()
            .contains(&"openid".to_string()));
        assert!(metadata
            .scopes_supported
            .as_ref()
            .unwrap()
            .contains(&"crm:read".to_string()));
        assert!(metadata
            .scopes_supported
            .as_ref()
            .unwrap()
            .contains(&"tools:execute".to_string()));
        assert_eq!(
            metadata.jwks_uri,
            Some("https://idp.example.com/.well-known/jwks.json".to_string())
        );
        assert_eq!(
            metadata.introspection_endpoint,
            Some("https://idp.example.com/oauth/introspect".to_string())
        );
        assert_eq!(
            metadata.resource_name,
            Some("xavyo Identity Platform".to_string())
        );
    }

    #[test]
    fn test_protected_resource_metadata_serialization() {
        let metadata =
            ProtectedResourceMetadata::new("https://api.example.com", "https://idp.example.com");

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(!json.contains("oauth-protected-resource"));
        assert!(json.contains("\"resource\":\"https://api.example.com\""));
        assert!(json.contains("authorization_servers"));
        assert!(json.contains("bearer_methods_supported"));

        // Roundtrip
        let deserialized: ProtectedResourceMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.resource, "https://api.example.com");
    }

    #[test]
    fn test_mcp_client_metadata() {
        let redirects = vec!["http://localhost:8080/callback".to_string()];
        let metadata = McpClientMetadata::new("test-client", redirects);

        assert_eq!(metadata.client_id, "test-client");
        assert_eq!(metadata.redirect_uris.len(), 1);
        assert!(metadata
            .grant_types
            .contains(&"authorization_code".to_string()));
        assert!(metadata.grant_types.contains(&"refresh_token".to_string()));
        assert_eq!(metadata.token_endpoint_auth_method, "none"); // Public client
        assert!(metadata.response_types.contains(&"code".to_string()));
        assert!(metadata
            .code_challenge_methods_supported
            .as_ref()
            .unwrap()
            .contains(&"S256".to_string()));
    }

    #[test]
    fn test_mcp_client_metadata_serialization() {
        let redirects = vec!["http://localhost:8080/callback".to_string()];
        let mut metadata = McpClientMetadata::new("test-client", redirects);
        metadata.client_name = Some("Test MCP".to_string());
        metadata.scope = Some("openid crm:read".to_string());

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("test-client"));
        assert!(json.contains("Test MCP"));
        assert!(json.contains("S256"));

        let deserialized: McpClientMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.client_name, Some("Test MCP".to_string()));
    }

    #[test]
    fn test_step_up_auth_error() {
        use crate::models::StepUpAuthError;

        let err = StepUpAuthError::insufficient_scope("crm:write", "Write access to CRM required");
        assert_eq!(err.error, "insufficient_scope");
        assert_eq!(err.required_scope, "crm:write");

        let header = err.www_authenticate_header("xavyo");
        assert!(header.contains("Bearer realm=\"xavyo\""));
        assert!(header.contains("insufficient_scope"));
        assert!(header.contains("crm:write"));
    }

    #[test]
    fn test_step_up_auth_serialization() {
        use crate::models::StepUpAuthError;

        let err = StepUpAuthError::insufficient_scope("tools:execute", "Tool execution required");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("insufficient_scope"));
        assert!(json.contains("tools:execute"));

        let deserialized: StepUpAuthError = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.required_scope, "tools:execute");
    }

    // Note: Testing create_jwk_from_pem requires a valid RSA key pair.
    // Integration tests should verify this with actual keys.
    #[test]
    fn test_jwk_set_creation() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test-key-1".to_string(),
            key_use: "sig".to_string(),
            alg: "RS256".to_string(),
            n: "test-modulus".to_string(),
            e: "AQAB".to_string(),
        };

        let jwk_set = JwkSet::new().add_key(jwk);
        assert_eq!(jwk_set.keys.len(), 1);
        assert_eq!(jwk_set.keys[0].kid, "test-key-1");
        assert_eq!(jwk_set.keys[0].kty, "RSA");
        assert_eq!(jwk_set.keys[0].alg, "RS256");
    }
}
