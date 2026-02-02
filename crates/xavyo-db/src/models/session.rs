//! Session model for tracking user sessions.
//!
//! Sessions are linked to refresh tokens and track device information
//! for security auditing and session management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// A user session tracking device and activity information.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Session {
    /// Unique identifier for this session.
    pub id: Uuid,

    /// The user this session belongs to.
    pub user_id: Uuid,

    /// The tenant this session belongs to.
    pub tenant_id: Uuid,

    /// Reference to the refresh token (if still exists).
    pub refresh_token_id: Option<Uuid>,

    /// Device fingerprint (optional).
    pub device_id: Option<String>,

    /// Human-readable device name.
    pub device_name: Option<String>,

    /// Device type: desktop, mobile, tablet, unknown.
    pub device_type: Option<String>,

    /// Browser name.
    pub browser: Option<String>,

    /// Browser version.
    pub browser_version: Option<String>,

    /// Operating system name.
    pub os: Option<String>,

    /// Operating system version.
    pub os_version: Option<String>,

    /// Client IP address.
    pub ip_address: Option<String>,

    /// Full user agent string.
    pub user_agent: Option<String>,

    /// When the session was created.
    pub created_at: DateTime<Utc>,

    /// Last activity timestamp.
    pub last_activity_at: DateTime<Utc>,

    /// When the session expires.
    pub expires_at: DateTime<Utc>,

    /// When the session was revoked (None if still active).
    pub revoked_at: Option<DateTime<Utc>>,

    /// Why the session was revoked.
    pub revoked_reason: Option<String>,
}

/// Data required to create a new session.
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub refresh_token_id: Option<Uuid>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// Session information for API responses (sanitized).
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub browser: Option<String>,
    pub os: Option<String>,
    pub ip_address: Option<String>,
    pub is_current: bool,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
}

impl From<Session> for SessionInfo {
    fn from(session: Session) -> Self {
        Self {
            id: session.id,
            device_name: session.device_name,
            device_type: session.device_type,
            browser: session.browser,
            os: session.os,
            ip_address: session.ip_address,
            is_current: false, // Set by caller
            created_at: session.created_at,
            last_activity_at: session.last_activity_at,
        }
    }
}

/// Reasons for session revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReason {
    UserLogout,
    AdminRevoke,
    MaxSessions,
    IdleTimeout,
    PasswordChange,
    Security,
}

impl std::fmt::Display for RevokeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserLogout => write!(f, "user_logout"),
            Self::AdminRevoke => write!(f, "admin_revoke"),
            Self::MaxSessions => write!(f, "max_sessions"),
            Self::IdleTimeout => write!(f, "idle_timeout"),
            Self::PasswordChange => write!(f, "password_change"),
            Self::Security => write!(f, "security"),
        }
    }
}

impl Session {
    /// Check if the session is active (not revoked and not expired).
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none() && self.expires_at > Utc::now()
    }

    /// Check if the session has exceeded idle timeout.
    pub fn is_idle(&self, idle_timeout_minutes: i64) -> bool {
        if idle_timeout_minutes == 0 {
            return false; // Idle timeout disabled
        }
        let idle_duration = Utc::now() - self.last_activity_at;
        idle_duration.num_minutes() > idle_timeout_minutes
    }

    /// Create a new session.
    pub async fn create<'e, E>(executor: E, data: CreateSession) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO sessions (
                user_id, tenant_id, refresh_token_id, device_id, device_name,
                device_type, browser, browser_version, os, os_version,
                ip_address, user_agent, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(data.user_id)
        .bind(data.tenant_id)
        .bind(data.refresh_token_id)
        .bind(&data.device_id)
        .bind(&data.device_name)
        .bind(&data.device_type)
        .bind(&data.browser)
        .bind(&data.browser_version)
        .bind(&data.os)
        .bind(&data.os_version)
        .bind(&data.ip_address)
        .bind(&data.user_agent)
        .bind(data.expires_at)
        .fetch_one(executor)
        .await
    }

    /// Find a session by ID.
    pub async fn find_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM sessions WHERE id = $1")
            .bind(id)
            .fetch_optional(executor)
            .await
    }

    /// Find a session by refresh token ID.
    pub async fn find_by_refresh_token<'e, E>(
        executor: E,
        refresh_token_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM sessions WHERE refresh_token_id = $1")
            .bind(refresh_token_id)
            .fetch_optional(executor)
            .await
    }

    /// Find all active sessions for a user.
    pub async fn find_active_by_user<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM sessions
            WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY last_activity_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(executor)
        .await
    }

    /// Count active sessions for a user.
    pub async fn count_active_by_user<'e, E>(executor: E, user_id: Uuid) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM sessions
            WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }

    /// Revoke a session.
    pub async fn revoke<'e, E>(
        executor: E,
        id: Uuid,
        reason: RevokeReason,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r#"
            UPDATE sessions
            SET revoked_at = NOW(), revoked_reason = $2
            WHERE id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(id)
        .bind(reason.to_string())
        .execute(executor)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Revoke all sessions for a user except the specified one.
    pub async fn revoke_all_except<'e, E>(
        executor: E,
        user_id: Uuid,
        except_session_id: Uuid,
        reason: RevokeReason,
    ) -> Result<u64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r#"
            UPDATE sessions
            SET revoked_at = NOW(), revoked_reason = $3
            WHERE user_id = $1 AND id != $2 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(except_session_id)
        .bind(reason.to_string())
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// Revoke all sessions for a user.
    pub async fn revoke_all_for_user<'e, E>(
        executor: E,
        user_id: Uuid,
        reason: RevokeReason,
    ) -> Result<u64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r#"
            UPDATE sessions
            SET revoked_at = NOW(), revoked_reason = $2
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(reason.to_string())
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// Find the oldest active session for a user.
    pub async fn find_oldest_active<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM sessions
            WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY created_at ASC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(executor)
        .await
    }

    /// Update last activity timestamp.
    pub async fn update_activity<'e, E>(executor: E, id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r#"
            UPDATE sessions
            SET last_activity_at = NOW()
            WHERE id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(id)
        .execute(executor)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete expired and revoked sessions (cleanup).
    pub async fn cleanup_old<'e, E>(executor: E, older_than_days: i64) -> Result<u64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r#"
            DELETE FROM sessions
            WHERE (revoked_at IS NOT NULL OR expires_at < NOW())
              AND created_at < NOW() - ($1 || ' days')::INTERVAL
            "#,
        )
        .bind(older_than_days.to_string())
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revoke_reason_display() {
        assert_eq!(RevokeReason::UserLogout.to_string(), "user_logout");
        assert_eq!(RevokeReason::MaxSessions.to_string(), "max_sessions");
        assert_eq!(RevokeReason::IdleTimeout.to_string(), "idle_timeout");
    }

    #[test]
    fn test_session_is_idle() {
        let mut session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            refresh_token_id: None,
            device_id: None,
            device_name: None,
            device_type: None,
            browser: None,
            browser_version: None,
            os: None,
            os_version: None,
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
            last_activity_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            revoked_at: None,
            revoked_reason: None,
        };

        // Recent activity - not idle
        assert!(!session.is_idle(30));

        // Old activity - should be idle
        session.last_activity_at = Utc::now() - chrono::Duration::minutes(60);
        assert!(session.is_idle(30));

        // Idle timeout disabled
        assert!(!session.is_idle(0));
    }

    #[test]
    fn test_session_is_active() {
        let mut session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            refresh_token_id: None,
            device_id: None,
            device_name: None,
            device_type: None,
            browser: None,
            browser_version: None,
            os: None,
            os_version: None,
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
            last_activity_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            revoked_at: None,
            revoked_reason: None,
        };

        // Active session
        assert!(session.is_active());

        // Revoked session
        session.revoked_at = Some(Utc::now());
        assert!(!session.is_active());

        // Expired session
        session.revoked_at = None;
        session.expires_at = Utc::now() - chrono::Duration::hours(1);
        assert!(!session.is_active());
    }

    #[test]
    fn test_session_info_from_session() {
        let session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            refresh_token_id: None,
            device_id: Some("abc123".to_string()),
            device_name: Some("Chrome on MacOS".to_string()),
            device_type: Some("desktop".to_string()),
            browser: Some("Chrome".to_string()),
            browser_version: Some("120.0".to_string()),
            os: Some("MacOS".to_string()),
            os_version: Some("14.0".to_string()),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0...".to_string()),
            created_at: Utc::now(),
            last_activity_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            revoked_at: None,
            revoked_reason: None,
        };

        let info: SessionInfo = session.into();
        assert_eq!(info.device_name, Some("Chrome on MacOS".to_string()));
        assert!(!info.is_current); // Default false, set by caller
    }
}
