//! OIDC Discovery models.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// `OpenID` Connect Discovery document.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OpenIdConfiguration {
    /// Issuer identifier.
    pub issuer: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// `UserInfo` endpoint URL.
    pub userinfo_endpoint: String,
    /// JWKS URI.
    pub jwks_uri: String,
    /// Device authorization endpoint URL (RFC 8628).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported grant types.
    pub grant_types_supported: Vec<String>,
    /// Supported subject types.
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// Supported token endpoint authentication methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported PKCE code challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported claims.
    pub claims_supported: Vec<String>,
    /// End session endpoint (OIDC RP-Initiated Logout).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
}

use super::token::DEVICE_CODE_GRANT_TYPE;
use super::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE;

impl OpenIdConfiguration {
    /// Create a new discovery document for the given issuer.
    #[must_use]
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{issuer}/oauth/authorize"),
            token_endpoint: format!("{issuer}/oauth/token"),
            userinfo_endpoint: format!("{issuer}/oauth/userinfo"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            // RFC 8628: Device Authorization endpoint
            device_authorization_endpoint: Some(format!("{issuer}/oauth/device/code")),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
                // RFC 8628: Device Code grant type
                DEVICE_CODE_GRANT_TYPE.to_string(),
                // RFC 8693: Token Exchange grant type
                TOKEN_EXCHANGE_GRANT_TYPE.to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
            ],
            code_challenge_methods_supported: vec!["S256".to_string()],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "auth_time".to_string(),
                "nonce".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "name".to_string(),
                "given_name".to_string(),
                "family_name".to_string(),
                "act".to_string(),
            ],
            end_session_endpoint: Some(format!("{issuer}/oauth/logout")),
        }
    }
}

/// JSON Web Key for JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Jwk {
    /// Key type (RSA).
    pub kty: String,
    /// Key ID.
    pub kid: String,
    /// Key use (sig = signature).
    #[serde(rename = "use")]
    pub key_use: String,
    /// Algorithm.
    pub alg: String,
    /// RSA modulus (base64url encoded).
    pub n: String,
    /// RSA exponent (base64url encoded).
    pub e: String,
}

/// JSON Web Key Set.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JwkSet {
    /// Array of JWKs.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Create a new empty JWKS.
    #[must_use]
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Add a key to the set.
    #[must_use]
    pub fn add_key(mut self, key: Jwk) -> Self {
        self.keys.push(key);
        self
    }
}

impl Default for JwkSet {
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 9728: OAuth 2.0 Protected Resource Metadata.
///
/// Describes a protected resource server's capabilities, supported
/// authorization servers, and authentication requirements.
/// MCP servers use this to advertise which authorization server to use.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProtectedResourceMetadata {
    /// The resource server's identifier (its base URL).
    pub resource: String,

    /// Authorization servers that can issue tokens accepted by this resource.
    pub authorization_servers: Vec<String>,

    /// OAuth 2.0 scopes recognized by this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// Token types accepted by this resource (e.g., "Bearer").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<String>>,

    /// Resource signing algorithms supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_signing_alg_values_supported: Option<Vec<String>>,

    /// Human-readable name of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,

    /// Documentation URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,

    /// Policy URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_policy_uri: Option<String>,

    /// Terms of service URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_tos_uri: Option<String>,

    /// JWKS URI for resource-specific keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Introspection endpoint for this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
}

impl ProtectedResourceMetadata {
    /// Create protected resource metadata for xavyo-idp as a resource server.
    #[must_use]
    pub fn new(resource_url: &str, authorization_server_url: &str) -> Self {
        Self {
            resource: resource_url.to_string(),
            authorization_servers: vec![authorization_server_url.to_string()],
            scopes_supported: Some(vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
                "crm:read".to_string(),
                "crm:write".to_string(),
                "tools:execute".to_string(),
            ]),
            bearer_methods_supported: Some(vec!["header".to_string(), "body".to_string()]),
            resource_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
            resource_name: Some("xavyo Identity Platform".to_string()),
            resource_documentation: None,
            resource_policy_uri: None,
            resource_tos_uri: None,
            jwks_uri: Some(format!("{authorization_server_url}/.well-known/jwks.json")),
            introspection_endpoint: Some(format!("{authorization_server_url}/oauth/introspect")),
        }
    }
}

/// MCP Client Metadata Document for zero-registration MCP clients.
///
/// Follows the MCP Authorization Spec (Draft) for client discovery.
/// An MCP server can GET this document from a client to learn about
/// the client's capabilities without pre-registration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct McpClientMetadata {
    /// Client identifier (the MCP tool server's base URL or registered client_id).
    pub client_id: String,

    /// Human-readable name of the MCP client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// Redirect URIs for authorization code flow.
    pub redirect_uris: Vec<String>,

    /// Grant types the client supports.
    pub grant_types: Vec<String>,

    /// Token endpoint auth method.
    pub token_endpoint_auth_method: String,

    /// Response types supported.
    pub response_types: Vec<String>,

    /// Requested scopes (space-separated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// PKCE code challenge methods supported by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,

    /// Client homepage URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
}

impl McpClientMetadata {
    /// Create default MCP client metadata for a given client.
    #[must_use]
    pub fn new(client_id: &str, redirect_uris: Vec<String>) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_name: None,
            redirect_uris,
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            token_endpoint_auth_method: "none".to_string(), // Public client (MCP default)
            response_types: vec!["code".to_string()],
            scope: None,
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
            client_uri: None,
        }
    }
}

/// Step-up authorization error response.
///
/// Returned as 403 with `WWW-Authenticate: Bearer` header when the
/// client's token lacks required scopes (RFC 6750 §3.1).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StepUpAuthError {
    /// Error code.
    pub error: String,

    /// Human-readable error description.
    pub error_description: String,

    /// Required scopes that were missing.
    pub required_scope: String,
}

impl StepUpAuthError {
    /// Create a step-up auth error for insufficient scope.
    #[must_use]
    pub fn insufficient_scope(required_scope: &str, description: &str) -> Self {
        Self {
            error: "insufficient_scope".to_string(),
            error_description: description.to_string(),
            required_scope: required_scope.to_string(),
        }
    }

    /// Generate the `WWW-Authenticate` header value for this error.
    #[must_use]
    pub fn www_authenticate_header(&self, realm: &str) -> String {
        format!(
            r#"Bearer realm="{realm}", error="insufficient_scope", error_description="{}", scope="{}"#,
            self.error_description, self.required_scope
        )
    }
}
