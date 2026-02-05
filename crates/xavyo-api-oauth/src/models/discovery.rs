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
}

use super::token::DEVICE_CODE_GRANT_TYPE;

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
            ],
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
