//! `OAuth2` refresh token entity model.
//!
//! Represents a long-lived token for obtaining new access tokens,
//! with support for token rotation and family-based revocation.

use chrono::{DateTime, Duration, Utc};
use sqlx::FromRow;
use xavyo_core::{TenantId, UserId};

/// Default refresh token expiration time in days.
pub const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 7;

/// An `OAuth2` refresh token with rotation support.
///
/// Refresh tokens are organized in families for replay detection.
/// When a token is used, a new token is issued with the same `family_id`
/// and the old one is revoked. If a revoked token is used, the entire
/// family is revoked as a security measure.
#[derive(Debug, Clone, FromRow)]
pub struct OAuthRefreshToken {
    /// Internal unique identifier.
    pub id: uuid::Uuid,

    /// SHA-256 hash of the refresh token.
    pub token_hash: String,

    /// Reference to the `OAuth2` client.
    pub client_id: uuid::Uuid,

    /// Reference to the token owner.
    pub user_id: uuid::Uuid,

    /// Reference to the tenant.
    pub tenant_id: uuid::Uuid,

    /// Granted `OAuth2` scopes (space-separated).
    pub scope: String,

    /// Token family ID for rotation tracking.
    pub family_id: uuid::Uuid,

    /// When the token expires.
    pub expires_at: DateTime<Utc>,

    /// Whether the token has been revoked.
    pub revoked: bool,

    /// When the token was revoked (if applicable).
    pub revoked_at: Option<DateTime<Utc>>,

    /// When the token was created.
    pub created_at: DateTime<Utc>,
}

impl OAuthRefreshToken {
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

    /// Check if the token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if the token is still valid (not revoked and not expired).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.is_expired()
    }

    /// Get the scopes as a vector.
    #[must_use]
    pub fn scopes(&self) -> Vec<&str> {
        self.scope.split_whitespace().collect()
    }

    /// Calculate the remaining lifetime of the token.
    #[must_use]
    pub fn remaining_lifetime(&self) -> Duration {
        let remaining = self.expires_at - Utc::now();
        if remaining < Duration::zero() {
            Duration::zero()
        } else {
            remaining
        }
    }
}

/// Builder for creating a new refresh token.
#[derive(Debug, Clone)]
pub struct OAuthRefreshTokenBuilder {
    token_hash: String,
    client_id: uuid::Uuid,
    user_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    scope: String,
    family_id: uuid::Uuid,
    expires_at: DateTime<Utc>,
}

impl OAuthRefreshTokenBuilder {
    /// Create a new builder with required fields.
    ///
    /// The expiration is automatically set to 7 days from now.
    /// A new `family_id` is generated for new token chains.
    #[must_use]
    pub fn new(
        token_hash: String,
        client_id: uuid::Uuid,
        user_id: uuid::Uuid,
        tenant_id: uuid::Uuid,
        scope: String,
    ) -> Self {
        Self {
            token_hash,
            client_id,
            user_id,
            tenant_id,
            scope,
            family_id: uuid::Uuid::new_v4(),
            expires_at: Utc::now() + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS),
        }
    }

    /// Create a new builder for a rotated token (same family).
    ///
    /// This is used when issuing a new refresh token during token rotation.
    #[must_use]
    pub fn for_rotation(
        token_hash: String,
        client_id: uuid::Uuid,
        user_id: uuid::Uuid,
        tenant_id: uuid::Uuid,
        scope: String,
        family_id: uuid::Uuid,
    ) -> Self {
        Self {
            token_hash,
            client_id,
            user_id,
            tenant_id,
            scope,
            family_id,
            expires_at: Utc::now() + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS),
        }
    }

    /// Override the family ID.
    #[must_use]
    pub fn family_id(mut self, family_id: uuid::Uuid) -> Self {
        self.family_id = family_id;
        self
    }

    /// Override the expiration time.
    #[must_use]
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Build the refresh token data.
    #[must_use]
    pub fn build(self) -> NewOAuthRefreshToken {
        NewOAuthRefreshToken {
            token_hash: self.token_hash,
            client_id: self.client_id,
            user_id: self.user_id,
            tenant_id: self.tenant_id,
            scope: self.scope,
            family_id: self.family_id,
            expires_at: self.expires_at,
        }
    }
}

/// Data for creating a new refresh token.
#[derive(Debug, Clone)]
pub struct NewOAuthRefreshToken {
    pub token_hash: String,
    pub client_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub scope: String,
    pub family_id: uuid::Uuid,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refresh_token_validity() {
        let token = OAuthRefreshToken {
            id: uuid::Uuid::new_v4(),
            token_hash: "hash".to_string(),
            client_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            scope: "openid offline_access".to_string(),
            family_id: uuid::Uuid::new_v4(),
            expires_at: Utc::now() + Duration::days(5),
            revoked: false,
            revoked_at: None,
            created_at: Utc::now(),
        };

        assert!(token.is_valid());
        assert!(!token.is_expired());
        assert!(!token.revoked);
    }

    #[test]
    fn test_refresh_token_expired() {
        let token = OAuthRefreshToken {
            id: uuid::Uuid::new_v4(),
            token_hash: "hash".to_string(),
            client_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            scope: "openid".to_string(),
            family_id: uuid::Uuid::new_v4(),
            expires_at: Utc::now() - Duration::hours(1),
            revoked: false,
            revoked_at: None,
            created_at: Utc::now() - Duration::days(8),
        };

        assert!(!token.is_valid());
        assert!(token.is_expired());
    }

    #[test]
    fn test_refresh_token_revoked() {
        let token = OAuthRefreshToken {
            id: uuid::Uuid::new_v4(),
            token_hash: "hash".to_string(),
            client_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            scope: "openid".to_string(),
            family_id: uuid::Uuid::new_v4(),
            expires_at: Utc::now() + Duration::days(5),
            revoked: true,
            revoked_at: Some(Utc::now()),
            created_at: Utc::now() - Duration::days(1),
        };

        assert!(!token.is_valid());
        assert!(!token.is_expired());
        assert!(token.revoked);
    }

    #[test]
    fn test_scopes_parsing() {
        let token = OAuthRefreshToken {
            id: uuid::Uuid::new_v4(),
            token_hash: "hash".to_string(),
            client_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            scope: "openid profile email offline_access".to_string(),
            family_id: uuid::Uuid::new_v4(),
            expires_at: Utc::now() + Duration::days(5),
            revoked: false,
            revoked_at: None,
            created_at: Utc::now(),
        };

        let scopes = token.scopes();
        assert_eq!(scopes, vec!["openid", "profile", "email", "offline_access"]);
    }

    #[test]
    fn test_builder_new_family() {
        let client_id = uuid::Uuid::new_v4();
        let user_id = uuid::Uuid::new_v4();
        let tenant_id = uuid::Uuid::new_v4();

        let token = OAuthRefreshTokenBuilder::new(
            "hash".to_string(),
            client_id,
            user_id,
            tenant_id,
            "openid".to_string(),
        )
        .build();

        assert_eq!(token.client_id, client_id);
        assert_eq!(token.user_id, user_id);
        assert_eq!(token.tenant_id, tenant_id);
        // New family_id should be generated
        assert!(!token.family_id.is_nil());
    }

    #[test]
    fn test_builder_for_rotation() {
        let family_id = uuid::Uuid::new_v4();

        let token = OAuthRefreshTokenBuilder::for_rotation(
            "hash".to_string(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "openid".to_string(),
            family_id,
        )
        .build();

        // Family ID should be preserved
        assert_eq!(token.family_id, family_id);
    }

    #[test]
    fn test_remaining_lifetime() {
        let token = OAuthRefreshToken {
            id: uuid::Uuid::new_v4(),
            token_hash: "hash".to_string(),
            client_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            scope: "openid".to_string(),
            family_id: uuid::Uuid::new_v4(),
            expires_at: Utc::now() + Duration::hours(2),
            revoked: false,
            revoked_at: None,
            created_at: Utc::now(),
        };

        let remaining = token.remaining_lifetime();
        // Should be approximately 2 hours
        assert!(remaining.num_minutes() > 110);
        assert!(remaining.num_minutes() <= 120);
    }
}
