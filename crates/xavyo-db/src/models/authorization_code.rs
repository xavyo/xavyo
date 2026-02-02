//! Authorization code entity model.
//!
//! Represents a temporary authorization code issued after user consent,
//! to be exchanged for tokens.

use chrono::{DateTime, Duration, Utc};
use sqlx::FromRow;
use xavyo_core::{TenantId, UserId};

/// Default authorization code expiration time in minutes.
pub const AUTH_CODE_EXPIRY_MINUTES: i64 = 10;

/// A temporary authorization code for the OAuth2 authorization code flow.
///
/// Authorization codes are single-use and expire after 10 minutes.
/// They are bound to a specific client, user, redirect URI, and PKCE challenge.
#[derive(Debug, Clone, FromRow)]
pub struct AuthorizationCode {
    /// Internal unique identifier.
    pub id: uuid::Uuid,

    /// SHA-256 hash of the authorization code.
    pub code_hash: String,

    /// Reference to the OAuth2 client.
    pub client_id: uuid::Uuid,

    /// Reference to the authorizing user.
    pub user_id: uuid::Uuid,

    /// Reference to the tenant.
    pub tenant_id: uuid::Uuid,

    /// Redirect URI that must match the token request.
    pub redirect_uri: String,

    /// Granted OAuth2 scopes (space-separated).
    pub scope: String,

    /// PKCE code challenge from the authorization request.
    pub code_challenge: String,

    /// PKCE code challenge method (only "S256" supported).
    pub code_challenge_method: String,

    /// OIDC nonce for replay protection (optional).
    pub nonce: Option<String>,

    /// When the code expires.
    pub expires_at: DateTime<Utc>,

    /// Whether the code has been used (exchanged for tokens).
    pub used: bool,

    /// When the code was created.
    pub created_at: DateTime<Utc>,
}

impl AuthorizationCode {
    /// Get the user ID as a typed `UserId`.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        UserId::from_uuid(self.user_id)
    }

    /// Get the tenant ID as a typed `TenantId`.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }

    /// Check if the code has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if the code is still valid (not used and not expired).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.used && !self.is_expired()
    }

    /// Get the scopes as a vector.
    #[must_use]
    pub fn scopes(&self) -> Vec<&str> {
        self.scope.split_whitespace().collect()
    }
}

/// Builder for creating a new authorization code.
#[derive(Debug, Clone)]
pub struct AuthorizationCodeBuilder {
    code_hash: String,
    client_id: uuid::Uuid,
    user_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    code_challenge_method: String,
    nonce: Option<String>,
    expires_at: DateTime<Utc>,
}

impl AuthorizationCodeBuilder {
    /// Create a new builder with required fields.
    ///
    /// The expiration is automatically set to 10 minutes from now.
    #[must_use]
    pub fn new(
        code_hash: String,
        client_id: uuid::Uuid,
        user_id: uuid::Uuid,
        tenant_id: uuid::Uuid,
        redirect_uri: String,
        scope: String,
        code_challenge: String,
    ) -> Self {
        Self {
            code_hash,
            client_id,
            user_id,
            tenant_id,
            redirect_uri,
            scope,
            code_challenge,
            code_challenge_method: "S256".to_string(),
            nonce: None,
            expires_at: Utc::now() + Duration::minutes(AUTH_CODE_EXPIRY_MINUTES),
        }
    }

    /// Set the OIDC nonce for replay protection.
    #[must_use]
    pub fn nonce(mut self, nonce: String) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Override the expiration time.
    #[must_use]
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Validate and build the authorization code data.
    pub fn build(self) -> Result<NewAuthorizationCode, &'static str> {
        // Only S256 PKCE method is supported
        if self.code_challenge_method != "S256" {
            return Err("Only S256 PKCE method is supported");
        }

        // Code challenge must not be empty
        if self.code_challenge.is_empty() {
            return Err("Code challenge is required");
        }

        // Expiration must be in the future
        if self.expires_at <= Utc::now() {
            return Err("Expiration must be in the future");
        }

        Ok(NewAuthorizationCode {
            code_hash: self.code_hash,
            client_id: self.client_id,
            user_id: self.user_id,
            tenant_id: self.tenant_id,
            redirect_uri: self.redirect_uri,
            scope: self.scope,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            nonce: self.nonce,
            expires_at: self.expires_at,
        })
    }
}

/// Data for creating a new authorization code.
#[derive(Debug, Clone)]
pub struct NewAuthorizationCode {
    pub code_hash: String,
    pub client_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_code_validity() {
        let code = AuthorizationCode {
            id: uuid::Uuid::new_v4(),
            code_hash: "hash".to_string(),
            client_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: None,
            expires_at: Utc::now() + Duration::minutes(5),
            used: false,
            created_at: Utc::now(),
        };

        assert!(code.is_valid());
        assert!(!code.is_expired());
    }

    #[test]
    fn test_authorization_code_expired() {
        let code = AuthorizationCode {
            id: uuid::Uuid::new_v4(),
            code_hash: "hash".to_string(),
            client_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: "openid".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: None,
            expires_at: Utc::now() - Duration::minutes(1),
            used: false,
            created_at: Utc::now() - Duration::minutes(11),
        };

        assert!(!code.is_valid());
        assert!(code.is_expired());
    }

    #[test]
    fn test_authorization_code_used() {
        let code = AuthorizationCode {
            id: uuid::Uuid::new_v4(),
            code_hash: "hash".to_string(),
            client_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: "openid".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: None,
            expires_at: Utc::now() + Duration::minutes(5),
            used: true,
            created_at: Utc::now(),
        };

        assert!(!code.is_valid());
        assert!(!code.is_expired());
    }

    #[test]
    fn test_scopes_parsing() {
        let code = AuthorizationCode {
            id: uuid::Uuid::new_v4(),
            code_hash: "hash".to_string(),
            client_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: None,
            expires_at: Utc::now() + Duration::minutes(5),
            used: false,
            created_at: Utc::now(),
        };

        let scopes = code.scopes();
        assert_eq!(scopes, vec!["openid", "profile", "email"]);
    }

    #[test]
    fn test_builder_rejects_plain_pkce() {
        let result = AuthorizationCodeBuilder::new(
            "hash".to_string(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "https://example.com/callback".to_string(),
            "openid".to_string(),
            "challenge".to_string(),
        );

        // Override the method to plain (not allowed)
        let result = AuthorizationCodeBuilder {
            code_challenge_method: "plain".to_string(),
            ..result
        }
        .build();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Only S256 PKCE method is supported");
    }
}
