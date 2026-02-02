//! Failed login attempt model for audit logging.
//!
//! Records all failed login attempts for security analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Reason for a failed login attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// Invalid password provided.
    InvalidPassword,
    /// Account is currently locked.
    AccountLocked,
    /// Account is deactivated.
    AccountInactive,
    /// Email address not found.
    UnknownEmail,
    /// Password has expired.
    PasswordExpired,
    /// MFA verification failed.
    MfaFailed,
    /// Other/unspecified reason.
    Other,
}

impl FailureReason {
    /// Convert to database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidPassword => "invalid_password",
            Self::AccountLocked => "account_locked",
            Self::AccountInactive => "account_inactive",
            Self::UnknownEmail => "unknown_email",
            Self::PasswordExpired => "password_expired",
            Self::MfaFailed => "mfa_failed",
            Self::Other => "other",
        }
    }

    /// Parse from database string representation.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "invalid_password" => Self::InvalidPassword,
            "account_locked" => Self::AccountLocked,
            "account_inactive" => Self::AccountInactive,
            "unknown_email" => Self::UnknownEmail,
            "password_expired" => Self::PasswordExpired,
            "mfa_failed" => Self::MfaFailed,
            _ => Self::Other,
        }
    }
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A record of a failed login attempt.
///
/// Used for security audit and attack pattern detection.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct FailedLoginAttempt {
    /// Unique identifier for this attempt.
    pub id: Uuid,

    /// The tenant for RLS isolation.
    pub tenant_id: Uuid,

    /// The user if identified (None for unknown emails).
    pub user_id: Option<Uuid>,

    /// The email address attempted.
    pub email: String,

    /// Client IP address (IPv4 or IPv6).
    pub ip_address: Option<String>,

    /// Reason for the failure.
    pub failure_reason: String,

    /// When the attempt occurred.
    pub created_at: DateTime<Utc>,
}

impl FailedLoginAttempt {
    /// Record a failed login attempt.
    pub async fn create<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        email: &str,
        ip_address: Option<&str>,
        failure_reason: FailureReason,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO failed_login_attempts (tenant_id, user_id, email, ip_address, failure_reason)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(email)
        .bind(ip_address)
        .bind(failure_reason.as_str())
        .fetch_one(executor)
        .await
    }

    /// Get the failure reason as an enum.
    #[must_use]
    pub fn reason(&self) -> FailureReason {
        FailureReason::parse(&self.failure_reason)
    }

    /// Get recent failed attempts for a tenant.
    pub async fn get_recent_for_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM failed_login_attempts
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(executor)
        .await
    }

    /// Get recent failed attempts for an email address.
    pub async fn get_recent_for_email<'e, E>(
        executor: E,
        tenant_id: Uuid,
        email: &str,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM failed_login_attempts
            WHERE tenant_id = $1 AND email = $2
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(email)
        .bind(limit)
        .fetch_all(executor)
        .await
    }

    /// Get recent failed attempts from an IP address.
    pub async fn get_recent_for_ip<'e, E>(
        executor: E,
        tenant_id: Uuid,
        ip_address: &str,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM failed_login_attempts
            WHERE tenant_id = $1 AND ip_address = $2
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(ip_address)
        .bind(limit)
        .fetch_all(executor)
        .await
    }

    /// Count failed attempts for an email in a time window.
    pub async fn count_recent_for_email<'e, E>(
        executor: E,
        tenant_id: Uuid,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM failed_login_attempts
            WHERE tenant_id = $1 AND email = $2 AND created_at >= $3
            "#,
        )
        .bind(tenant_id)
        .bind(email)
        .bind(since)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Delete old failed login attempts (for cleanup/retention).
    pub async fn delete_older_than<'e, E>(
        executor: E,
        tenant_id: Uuid,
        older_than: DateTime<Utc>,
    ) -> Result<u64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r#"
            DELETE FROM failed_login_attempts
            WHERE tenant_id = $1 AND created_at < $2
            "#,
        )
        .bind(tenant_id)
        .bind(older_than)
        .execute(executor)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_reason_roundtrip() {
        let reasons = [
            FailureReason::InvalidPassword,
            FailureReason::AccountLocked,
            FailureReason::AccountInactive,
            FailureReason::UnknownEmail,
            FailureReason::PasswordExpired,
            FailureReason::MfaFailed,
            FailureReason::Other,
        ];

        for reason in reasons {
            let s = reason.as_str();
            let parsed = FailureReason::parse(s);
            assert_eq!(reason, parsed);
        }
    }

    #[test]
    fn test_failure_reason_display() {
        assert_eq!(
            FailureReason::InvalidPassword.to_string(),
            "invalid_password"
        );
        assert_eq!(FailureReason::AccountLocked.to_string(), "account_locked");
    }

    #[test]
    fn test_unknown_reason_parses_as_other() {
        let parsed = FailureReason::parse("unknown_reason");
        assert_eq!(parsed, FailureReason::Other);
    }
}
