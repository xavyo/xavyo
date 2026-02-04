//! Login attempt model for comprehensive audit logging.
//!
//! Records all authentication attempts (successful and failed) for security analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Authentication method used for login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Standard email/password authentication.
    Password,
    /// `OAuth2` social login (Google, GitHub, etc.).
    Social,
    /// Enterprise SSO/SAML.
    Sso,
    /// MFA step verification.
    Mfa,
    /// Token refresh.
    Refresh,
}

impl AuthMethod {
    /// Convert to database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Social => "social",
            Self::Sso => "sso",
            Self::Mfa => "mfa",
            Self::Refresh => "refresh",
        }
    }

    /// Parse from database string representation.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "password" => Self::Password,
            "social" => Self::Social,
            "sso" => Self::Sso,
            "mfa" => Self::Mfa,
            "refresh" => Self::Refresh,
            _ => Self::Password,
        }
    }
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A record of a login attempt (successful or failed).
///
/// Used for comprehensive security audit trail.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct LoginAttempt {
    /// Unique identifier for this attempt.
    pub id: Uuid,

    /// The tenant for RLS isolation.
    pub tenant_id: Uuid,

    /// The user if identified (None for unknown emails).
    pub user_id: Option<Uuid>,

    /// The email address attempted.
    pub email: String,

    /// Whether the authentication succeeded.
    pub success: bool,

    /// Reason for failure (None if success).
    pub failure_reason: Option<String>,

    /// Authentication method used.
    pub auth_method: String,

    /// Client IP address (IPv4 or IPv6).
    pub ip_address: Option<String>,

    /// Full user agent string.
    pub user_agent: Option<String>,

    /// SHA-256 hash of client device fingerprint.
    pub device_fingerprint: Option<String>,

    /// ISO 3166-1 alpha-2 country code from geo-lookup.
    pub geo_country: Option<String>,

    /// City name from geo-lookup.
    pub geo_city: Option<String>,

    /// Whether this is first login from this device.
    pub is_new_device: bool,

    /// Whether this is first login from this location.
    pub is_new_location: bool,

    /// When the attempt occurred.
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new login attempt.
#[derive(Debug, Clone)]
pub struct CreateLoginAttempt {
    pub tenant_id: Uuid,
    pub user_id: Option<Uuid>,
    pub email: String,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub auth_method: AuthMethod,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_fingerprint: Option<String>,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub is_new_device: bool,
    pub is_new_location: bool,
}

impl LoginAttempt {
    /// Record a login attempt.
    pub async fn create<'e, E>(executor: E, input: CreateLoginAttempt) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            INSERT INTO login_attempts (
                tenant_id, user_id, email, success, failure_reason, auth_method,
                ip_address, user_agent, device_fingerprint, geo_country, geo_city,
                is_new_device, is_new_location
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(input.user_id)
        .bind(&input.email)
        .bind(input.success)
        .bind(&input.failure_reason)
        .bind(input.auth_method.as_str())
        .bind(&input.ip_address)
        .bind(&input.user_agent)
        .bind(&input.device_fingerprint)
        .bind(&input.geo_country)
        .bind(&input.geo_city)
        .bind(input.is_new_device)
        .bind(input.is_new_location)
        .fetch_one(executor)
        .await
    }

    /// Get the authentication method as an enum.
    #[must_use]
    pub fn method(&self) -> AuthMethod {
        AuthMethod::parse(&self.auth_method)
    }

    /// Get login history for a user with cursor-based pagination.
    pub async fn get_user_history<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        match cursor {
            Some(cursor_time) => {
                sqlx::query_as(
                    r"
                    SELECT * FROM login_attempts
                    WHERE tenant_id = $1 AND user_id = $2 AND created_at < $3
                    ORDER BY created_at DESC
                    LIMIT $4
                    ",
                )
                .bind(tenant_id)
                .bind(user_id)
                .bind(cursor_time)
                .bind(limit)
                .fetch_all(executor)
                .await
            }
            None => {
                sqlx::query_as(
                    r"
                    SELECT * FROM login_attempts
                    WHERE tenant_id = $1 AND user_id = $2
                    ORDER BY created_at DESC
                    LIMIT $3
                    ",
                )
                .bind(tenant_id)
                .bind(user_id)
                .bind(limit)
                .fetch_all(executor)
                .await
            }
        }
    }

    /// Get login history for a user filtered by success status.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_user_history_filtered<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        success: Option<bool>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM login_attempts
            WHERE tenant_id = $1
              AND user_id = $2
              AND ($3::boolean IS NULL OR success = $3)
              AND ($4::timestamptz IS NULL OR created_at >= $4)
              AND ($5::timestamptz IS NULL OR created_at <= $5)
              AND ($6::timestamptz IS NULL OR created_at < $6)
            ORDER BY created_at DESC
            LIMIT $7
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(success)
        .bind(start_date)
        .bind(end_date)
        .bind(cursor)
        .bind(limit)
        .fetch_all(executor)
        .await
    }

    /// Count total login attempts for a user.
    pub async fn count_user_history<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM login_attempts
            WHERE tenant_id = $1 AND user_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Get all login attempts for a tenant (admin query).
    #[allow(clippy::too_many_arguments)]
    pub async fn get_tenant_attempts<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        email_filter: Option<&str>,
        success: Option<bool>,
        auth_method: Option<&str>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM login_attempts
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR user_id = $2)
              AND ($3::text IS NULL OR email ILIKE '%' || $3 || '%')
              AND ($4::boolean IS NULL OR success = $4)
              AND ($5::text IS NULL OR auth_method = $5)
              AND ($6::timestamptz IS NULL OR created_at >= $6)
              AND ($7::timestamptz IS NULL OR created_at <= $7)
              AND ($8::timestamptz IS NULL OR created_at < $8)
            ORDER BY created_at DESC
            LIMIT $9
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(email_filter)
        .bind(success)
        .bind(auth_method)
        .bind(start_date)
        .bind(end_date)
        .bind(cursor)
        .bind(limit)
        .fetch_all(executor)
        .await
    }

    /// Count total login attempts for a tenant.
    pub async fn count_tenant_attempts<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM login_attempts
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_roundtrip() {
        let methods = [
            AuthMethod::Password,
            AuthMethod::Social,
            AuthMethod::Sso,
            AuthMethod::Mfa,
            AuthMethod::Refresh,
        ];

        for method in methods {
            let s = method.as_str();
            let parsed = AuthMethod::parse(s);
            assert_eq!(method, parsed);
        }
    }

    #[test]
    fn test_auth_method_display() {
        assert_eq!(AuthMethod::Password.to_string(), "password");
        assert_eq!(AuthMethod::Social.to_string(), "social");
    }

    #[test]
    fn test_unknown_method_defaults_to_password() {
        let parsed = AuthMethod::parse("unknown");
        assert_eq!(parsed, AuthMethod::Password);
    }
}
