//! Passwordless authentication token entity model.
//!
//! Stores magic link tokens and email OTP codes for passwordless authentication.
//! Both types share the same table with a discriminator column (`token_type`).

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use std::net::IpAddr;
use uuid::Uuid;
use xavyo_core::{TenantId, UserId};

/// Token types for passwordless authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordlessTokenType {
    /// Magic link token — single-use URL token.
    MagicLink,
    /// Email OTP — 6-digit code with attempt tracking.
    EmailOtp,
}

impl PasswordlessTokenType {
    /// Convert to database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MagicLink => "magic_link",
            Self::EmailOtp => "email_otp",
        }
    }

    /// Parse from database string representation.
    #[must_use] 
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "magic_link" => Some(Self::MagicLink),
            "email_otp" => Some(Self::EmailOtp),
            _ => None,
        }
    }
}

/// A passwordless authentication token record in the database.
#[derive(Debug, Clone, FromRow)]
pub struct PasswordlessToken {
    /// Unique identifier for this token record.
    pub id: Uuid,
    /// The tenant this token belongs to (for RLS).
    pub tenant_id: Uuid,
    /// The user who requested the token.
    pub user_id: Uuid,
    /// SHA-256 hash of the token value.
    pub token_hash: String,
    /// Discriminator: '`magic_link`' or '`email_otp`'.
    pub token_type: String,
    /// SHA-256 hash of the 6-digit OTP code (`email_otp` only).
    pub otp_code_hash: Option<String>,
    /// Remaining verification attempts (`email_otp` only).
    pub otp_attempts_remaining: Option<i32>,
    /// When the token expires.
    pub expires_at: DateTime<Utc>,
    /// When the token was consumed (None = unused).
    pub used_at: Option<DateTime<Utc>>,
    /// Requestor IP address.
    pub ip_address: Option<String>,
    /// Requestor user agent string.
    pub user_agent: Option<String>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
}

impl PasswordlessToken {
    /// Check if the token is still valid (not expired, not used, and for OTP: attempts remaining).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.used_at.is_none() && self.expires_at > Utc::now() && !self.is_exhausted()
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

    /// Check if OTP attempts are exhausted (`email_otp` only).
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.otp_attempts_remaining == Some(0)
    }

    /// Get the parsed token type.
    #[must_use]
    pub fn parsed_token_type(&self) -> Option<PasswordlessTokenType> {
        PasswordlessTokenType::parse(&self.token_type)
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

    /// Create a new passwordless token in the database.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        token_hash: &str,
        token_type: PasswordlessTokenType,
        otp_code_hash: Option<&str>,
        otp_attempts_remaining: Option<i32>,
        expires_at: DateTime<Utc>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        let token = sqlx::query_as::<_, Self>(
            r"
            INSERT INTO passwordless_tokens
                (tenant_id, user_id, token_hash, token_type, otp_code_hash,
                 otp_attempts_remaining, expires_at, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, tenant_id, user_id, token_hash, token_type, otp_code_hash,
                      otp_attempts_remaining, expires_at, used_at, ip_address, user_agent, created_at
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(token_hash)
        .bind(token_type.as_str())
        .bind(otp_code_hash)
        .bind(otp_attempts_remaining)
        .bind(expires_at)
        .bind(ip_address)
        .bind(user_agent)
        .fetch_one(pool)
        .await?;

        Ok(token)
    }

    /// Find a token by its hash and tenant.
    pub async fn find_by_token_hash(
        pool: &PgPool,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let token = sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, user_id, token_hash, token_type, otp_code_hash,
                   otp_attempts_remaining, expires_at, used_at, ip_address, user_agent, created_at
            FROM passwordless_tokens
            WHERE tenant_id = $1 AND token_hash = $2
            ",
        )
        .bind(tenant_id)
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(token)
    }

    /// Find the latest unused token for a user and type.
    pub async fn find_latest_for_user(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        token_type: PasswordlessTokenType,
    ) -> Result<Option<Self>, sqlx::Error> {
        let token = sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, user_id, token_hash, token_type, otp_code_hash,
                   otp_attempts_remaining, expires_at, used_at, ip_address, user_agent, created_at
            FROM passwordless_tokens
            WHERE tenant_id = $1 AND user_id = $2 AND token_type = $3
                  AND used_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(token_type.as_str())
        .fetch_optional(pool)
        .await?;

        Ok(token)
    }

    /// Invalidate all previous tokens for a user and type by marking them as used.
    pub async fn invalidate_previous_for_user_type(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        token_type: PasswordlessTokenType,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE passwordless_tokens
            SET used_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND token_type = $3 AND used_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(token_type.as_str())
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Mark a token as used.
    pub async fn mark_used(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"
            UPDATE passwordless_tokens
            SET used_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Decrement OTP attempts remaining. Returns the new count.
    pub async fn decrement_otp_attempts(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<i32, sqlx::Error> {
        let remaining: (i32,) = sqlx::query_as(
            r"
            UPDATE passwordless_tokens
            SET otp_attempts_remaining = otp_attempts_remaining - 1
            WHERE tenant_id = $1 AND id = $2 AND otp_attempts_remaining > 0
            RETURNING otp_attempts_remaining
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(remaining.0)
    }

    /// Delete expired tokens (cleanup task).
    pub async fn delete_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM passwordless_tokens
            WHERE expires_at < NOW() - INTERVAL '1 hour'
            ",
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_token(
        token_type: &str,
        expires_at: DateTime<Utc>,
        used_at: Option<DateTime<Utc>>,
        otp_attempts: Option<i32>,
    ) -> PasswordlessToken {
        PasswordlessToken {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "testhash".to_string(),
            token_type: token_type.to_string(),
            otp_code_hash: None,
            otp_attempts_remaining: otp_attempts,
            expires_at,
            used_at,
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_valid_magic_link_token() {
        let token = create_test_token("magic_link", Utc::now() + Duration::hours(1), None, None);
        assert!(token.is_valid());
        assert!(!token.is_used());
        assert!(!token.is_expired());
        assert!(!token.is_exhausted());
    }

    #[test]
    fn test_expired_token() {
        let token = create_test_token("magic_link", Utc::now() - Duration::hours(1), None, None);
        assert!(!token.is_valid());
        assert!(token.is_expired());
    }

    #[test]
    fn test_used_token() {
        let token = create_test_token(
            "magic_link",
            Utc::now() + Duration::hours(1),
            Some(Utc::now()),
            None,
        );
        assert!(!token.is_valid());
        assert!(token.is_used());
    }

    #[test]
    fn test_exhausted_otp() {
        let token = create_test_token("email_otp", Utc::now() + Duration::hours(1), None, Some(0));
        assert!(!token.is_valid());
        assert!(token.is_exhausted());
    }

    #[test]
    fn test_otp_with_attempts() {
        let token = create_test_token("email_otp", Utc::now() + Duration::hours(1), None, Some(3));
        assert!(token.is_valid());
        assert!(!token.is_exhausted());
    }

    #[test]
    fn test_token_type_parsing() {
        assert_eq!(
            PasswordlessTokenType::parse("magic_link"),
            Some(PasswordlessTokenType::MagicLink)
        );
        assert_eq!(
            PasswordlessTokenType::parse("email_otp"),
            Some(PasswordlessTokenType::EmailOtp)
        );
        assert_eq!(PasswordlessTokenType::parse("invalid"), None);
    }

    #[test]
    fn test_token_type_as_str() {
        assert_eq!(PasswordlessTokenType::MagicLink.as_str(), "magic_link");
        assert_eq!(PasswordlessTokenType::EmailOtp.as_str(), "email_otp");
    }

    #[test]
    fn test_ip_addr_parsing() {
        let mut token =
            create_test_token("magic_link", Utc::now() + Duration::hours(1), None, None);
        token.ip_address = Some("192.168.1.1".to_string());
        assert_eq!(token.ip_addr().unwrap().to_string(), "192.168.1.1");
    }

    #[test]
    fn test_typed_ids() {
        let token = create_test_token("magic_link", Utc::now() + Duration::hours(1), None, None);
        let user_id = token.user_id();
        let tenant_id = token.tenant_id();
        assert_eq!(*user_id.as_uuid(), token.user_id);
        assert_eq!(*tenant_id.as_uuid(), token.tenant_id);
    }
}
