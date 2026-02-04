//! Password reset token entity model.
//!
//! Represents a password reset token stored in the database for
//! secure password reset flow.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use std::net::IpAddr;
use xavyo_core::{TenantId, UserId};

/// A password reset token record in the database.
///
/// Password reset tokens are stored as SHA-256 hashes for security.
/// The actual token is only sent to the user via email.
#[derive(Debug, Clone, FromRow)]
pub struct PasswordResetToken {
    /// Unique identifier for this token record.
    pub id: uuid::Uuid,

    /// The tenant this token belongs to (for RLS).
    pub tenant_id: uuid::Uuid,

    /// The user who requested the reset.
    pub user_id: uuid::Uuid,

    /// SHA-256 hash of the token value.
    pub token_hash: String,

    /// When the token expires (1 hour from creation).
    pub expires_at: DateTime<Utc>,

    /// When the token was used (None if still valid).
    pub used_at: Option<DateTime<Utc>>,

    /// When the token was created.
    pub created_at: DateTime<Utc>,

    /// The client's IP address as string (optional, for auditing).
    pub ip_address: Option<String>,

    /// The client's user agent (optional, for auditing).
    pub user_agent: Option<String>,
}

impl PasswordResetToken {
    /// Check if the token is still valid (not expired and not used).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.used_at.is_none() && self.expires_at > Utc::now()
    }

    /// Check if the token has been used.
    #[must_use]
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Check if the token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

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

    /// Get the IP address as parsed `IpAddr` (if present and valid).
    #[must_use]
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip_address.as_ref().and_then(|s| s.parse().ok())
    }
}

/// Builder for creating new password reset token records.
#[derive(Debug, Clone)]
pub struct PasswordResetTokenBuilder {
    tenant_id: uuid::Uuid,
    user_id: uuid::Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
    ip_address: Option<IpAddr>,
    user_agent: Option<String>,
}

impl PasswordResetTokenBuilder {
    /// Create a new builder with required fields.
    #[must_use]
    pub fn new(
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
        token_hash: String,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            token_hash,
            expires_at,
            ip_address: None,
            user_agent: None,
        }
    }

    /// Set the client's IP address.
    #[must_use]
    pub fn ip_address(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Set the client's user agent.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Get the tenant ID.
    #[must_use]
    pub fn get_tenant_id(&self) -> uuid::Uuid {
        self.tenant_id
    }

    /// Get the user ID.
    #[must_use]
    pub fn get_user_id(&self) -> uuid::Uuid {
        self.user_id
    }

    /// Get the token hash.
    #[must_use]
    pub fn get_token_hash(&self) -> &str {
        &self.token_hash
    }

    /// Get the expiration time.
    #[must_use]
    pub fn get_expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Get the IP address.
    #[must_use]
    pub fn get_ip_address(&self) -> Option<IpAddr> {
        self.ip_address
    }

    /// Get the user agent.
    #[must_use]
    pub fn get_user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_token(
        expires_at: DateTime<Utc>,
        used_at: Option<DateTime<Utc>>,
    ) -> PasswordResetToken {
        PasswordResetToken {
            id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            token_hash: "testhash".to_string(),
            expires_at,
            used_at,
            created_at: Utc::now(),
            ip_address: None,
            user_agent: None,
        }
    }

    #[test]
    fn test_valid_token() {
        let token = create_test_token(Utc::now() + Duration::hours(1), None);
        assert!(token.is_valid());
        assert!(!token.is_used());
        assert!(!token.is_expired());
    }

    #[test]
    fn test_expired_token() {
        let token = create_test_token(Utc::now() - Duration::hours(1), None);
        assert!(!token.is_valid());
        assert!(!token.is_used());
        assert!(token.is_expired());
    }

    #[test]
    fn test_used_token() {
        let token = create_test_token(Utc::now() + Duration::hours(1), Some(Utc::now()));
        assert!(!token.is_valid());
        assert!(token.is_used());
        assert!(!token.is_expired());
    }

    #[test]
    fn test_ip_addr_parsing() {
        let mut token = create_test_token(Utc::now() + Duration::hours(1), None);
        token.ip_address = Some("192.168.1.1".to_string());

        let ip = token.ip_addr().unwrap();
        assert_eq!(ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_builder() {
        let tenant_id = uuid::Uuid::new_v4();
        let user_id = uuid::Uuid::new_v4();
        let expires = Utc::now() + Duration::hours(1);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let builder =
            PasswordResetTokenBuilder::new(tenant_id, user_id, "hash".to_string(), expires)
                .user_agent("Mozilla/5.0")
                .ip_address(ip);

        assert_eq!(builder.get_tenant_id(), tenant_id);
        assert_eq!(builder.get_user_id(), user_id);
        assert_eq!(builder.get_token_hash(), "hash");
        assert_eq!(builder.get_user_agent(), Some("Mozilla/5.0"));
        assert_eq!(builder.get_ip_address(), Some(ip));
    }
}
