//! `OAuth2` client entity model.
//!
//! Represents a registered `OAuth2` application that can request authorization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use xavyo_core::TenantId;

/// `OAuth2` client type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    /// Confidential clients can securely store credentials.
    Confidential,
    /// Public clients cannot securely store credentials (e.g., SPAs, mobile apps).
    Public,
}

impl ClientType {
    /// Convert to database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Confidential => "confidential",
            Self::Public => "public",
        }
    }

    /// Parse from database string representation.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "confidential" => Some(Self::Confidential),
            "public" => Some(Self::Public),
            _ => None,
        }
    }
}

/// A registered `OAuth2` client application.
///
/// Clients are scoped to a tenant and can request authorization on behalf of users.
#[derive(Debug, Clone, FromRow)]
pub struct OAuth2Client {
    /// Internal unique identifier.
    pub id: uuid::Uuid,

    /// The tenant this client belongs to.
    pub tenant_id: uuid::Uuid,

    /// Public client identifier used in `OAuth2` flows.
    pub client_id: String,

    /// Argon2id hash of the client secret (None for public clients).
    pub client_secret_hash: Option<String>,

    /// Human-readable client name.
    pub name: String,

    /// Client type: "confidential" or "public".
    pub client_type: String,

    /// Allowed redirect URIs (exact match required).
    pub redirect_uris: Vec<String>,

    /// Allowed grant types (e.g., "`authorization_code`", "`client_credentials`").
    pub grant_types: Vec<String>,

    /// Allowed `OAuth2` scopes.
    pub scopes: Vec<String>,

    /// Whether the client is active (false = deactivated).
    pub is_active: bool,

    /// Client logo URL (shown on consent page).
    pub logo_url: Option<String>,

    /// Client description (shown on consent page).
    pub description: Option<String>,

    /// When the client was created.
    pub created_at: DateTime<Utc>,

    /// When the client was last updated.
    pub updated_at: DateTime<Utc>,

    /// Allowed post-logout redirect URIs (OIDC RP-Initiated Logout).
    pub post_logout_redirect_uris: Vec<String>,
}

impl OAuth2Client {
    /// Get the tenant ID as a typed `TenantId`.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }

    /// Get the parsed client type.
    #[must_use]
    pub fn client_type_enum(&self) -> Option<ClientType> {
        ClientType::from_str(&self.client_type)
    }

    /// Check if this is a confidential client.
    #[must_use]
    pub fn is_confidential(&self) -> bool {
        self.client_type == "confidential"
    }

    /// Check if this is a public client.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.client_type == "public"
    }

    /// Check if a redirect URI is allowed for this client.
    #[must_use]
    pub fn is_redirect_uri_allowed(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|allowed| allowed == uri)
    }

    /// Check if a grant type is allowed for this client.
    #[must_use]
    pub fn is_grant_type_allowed(&self, grant_type: &str) -> bool {
        self.grant_types.iter().any(|allowed| allowed == grant_type)
    }

    /// Check if a scope is allowed for this client.
    #[must_use]
    pub fn is_scope_allowed(&self, scope: &str) -> bool {
        self.scopes.iter().any(|allowed| allowed == scope)
    }

    /// Check if all requested scopes are allowed for this client.
    #[must_use]
    pub fn are_scopes_allowed(&self, requested_scopes: &[&str]) -> bool {
        requested_scopes.iter().all(|s| self.is_scope_allowed(s))
    }
}

/// Builder for creating a new `OAuth2` client.
#[derive(Debug, Clone)]
pub struct OAuth2ClientBuilder {
    tenant_id: uuid::Uuid,
    client_id: String,
    client_secret_hash: Option<String>,
    name: String,
    client_type: ClientType,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
}

impl OAuth2ClientBuilder {
    /// Create a new builder with required fields.
    #[must_use]
    pub fn new(
        tenant_id: uuid::Uuid,
        client_id: String,
        name: String,
        client_type: ClientType,
    ) -> Self {
        Self {
            tenant_id,
            client_id,
            client_secret_hash: None,
            name,
            client_type,
            redirect_uris: Vec::new(),
            grant_types: Vec::new(),
            scopes: vec!["openid".to_string()],
        }
    }

    /// Set the client secret hash (required for confidential clients).
    #[must_use]
    pub fn client_secret_hash(mut self, hash: String) -> Self {
        self.client_secret_hash = Some(hash);
        self
    }

    /// Add a redirect URI.
    #[must_use]
    pub fn redirect_uri(mut self, uri: String) -> Self {
        self.redirect_uris.push(uri);
        self
    }

    /// Set all redirect URIs.
    #[must_use]
    pub fn redirect_uris(mut self, uris: Vec<String>) -> Self {
        self.redirect_uris = uris;
        self
    }

    /// Add a grant type.
    #[must_use]
    pub fn grant_type(mut self, grant_type: String) -> Self {
        self.grant_types.push(grant_type);
        self
    }

    /// Set all grant types.
    #[must_use]
    pub fn grant_types(mut self, types: Vec<String>) -> Self {
        self.grant_types = types;
        self
    }

    /// Set the allowed scopes.
    #[must_use]
    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Validate and build the client data.
    ///
    /// Returns an error if:
    /// - Confidential client has no secret hash
    /// - Public client has a secret hash
    /// - No redirect URIs specified
    /// - No grant types specified
    pub fn build(self) -> Result<NewOAuth2Client, &'static str> {
        // Validate client type requirements
        match self.client_type {
            ClientType::Confidential if self.client_secret_hash.is_none() => {
                return Err("Confidential clients must have a client secret");
            }
            ClientType::Public if self.client_secret_hash.is_some() => {
                return Err("Public clients must not have a client secret");
            }
            _ => {}
        }

        // Validate required fields
        if self.redirect_uris.is_empty() {
            return Err("At least one redirect URI is required");
        }

        if self.grant_types.is_empty() {
            return Err("At least one grant type is required");
        }

        Ok(NewOAuth2Client {
            tenant_id: self.tenant_id,
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            name: self.name,
            client_type: self.client_type.as_str().to_string(),
            redirect_uris: self.redirect_uris,
            grant_types: self.grant_types,
            scopes: self.scopes,
        })
    }
}

/// Data for creating a new `OAuth2` client.
#[derive(Debug, Clone)]
pub struct NewOAuth2Client {
    pub tenant_id: uuid::Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_type_conversion() {
        assert_eq!(ClientType::Confidential.as_str(), "confidential");
        assert_eq!(ClientType::Public.as_str(), "public");
        assert_eq!(
            ClientType::from_str("confidential"),
            Some(ClientType::Confidential)
        );
        assert_eq!(ClientType::from_str("public"), Some(ClientType::Public));
        assert_eq!(ClientType::from_str("invalid"), None);
    }

    #[test]
    fn test_builder_confidential_requires_secret() {
        let result = OAuth2ClientBuilder::new(
            uuid::Uuid::new_v4(),
            "test-client".to_string(),
            "Test Client".to_string(),
            ClientType::Confidential,
        )
        .redirect_uri("https://example.com/callback".to_string())
        .grant_type("authorization_code".to_string())
        .build();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Confidential clients must have a client secret"
        );
    }

    #[test]
    fn test_builder_public_rejects_secret() {
        let result = OAuth2ClientBuilder::new(
            uuid::Uuid::new_v4(),
            "test-client".to_string(),
            "Test Client".to_string(),
            ClientType::Public,
        )
        .client_secret_hash("some-hash".to_string())
        .redirect_uri("https://example.com/callback".to_string())
        .grant_type("authorization_code".to_string())
        .build();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Public clients must not have a client secret"
        );
    }

    #[test]
    fn test_builder_success() {
        let tenant_id = uuid::Uuid::new_v4();
        let result = OAuth2ClientBuilder::new(
            tenant_id,
            "test-client".to_string(),
            "Test Client".to_string(),
            ClientType::Public,
        )
        .redirect_uri("https://example.com/callback".to_string())
        .grant_type("authorization_code".to_string())
        .scopes(vec!["openid".to_string(), "profile".to_string()])
        .build();

        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.tenant_id, tenant_id);
        assert_eq!(client.client_id, "test-client");
        assert_eq!(client.client_type, "public");
        assert!(client.client_secret_hash.is_none());
    }
}
