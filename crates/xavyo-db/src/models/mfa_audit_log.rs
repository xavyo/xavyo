//! MFA audit log model.
//!
//! Tracks all MFA-related actions for security auditing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// An entry in the MFA audit log.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct MfaAuditLog {
    /// Unique identifier for this log entry.
    pub id: Uuid,

    /// The user who performed the action.
    pub user_id: Uuid,

    /// The tenant context.
    pub tenant_id: Uuid,

    /// The action that was performed.
    pub action: String,

    /// IP address of the request (stored as string).
    pub ip_address: Option<String>,

    /// User agent string from the request.
    pub user_agent: Option<String>,

    /// Additional metadata about the action.
    pub metadata: Option<serde_json::Value>,

    /// When the action occurred.
    pub created_at: DateTime<Utc>,
}

/// Types of MFA audit actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaAuditAction {
    /// TOTP setup was initiated.
    SetupInitiated,
    /// TOTP setup was completed.
    SetupCompleted,
    /// TOTP verification succeeded.
    VerifySuccess,
    /// TOTP verification failed.
    VerifyFailed,
    /// MFA was disabled.
    Disabled,
    /// Recovery code was used.
    RecoveryUsed,
    /// Recovery codes were regenerated.
    RecoveryRegenerated,
    /// Tenant MFA policy was changed.
    PolicyChanged,
    /// Account was locked due to failed attempts.
    AccountLocked,
    /// Account lockout expired.
    LockoutExpired,
}

impl std::fmt::Display for MfaAuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetupInitiated => write!(f, "setup_initiated"),
            Self::SetupCompleted => write!(f, "setup_completed"),
            Self::VerifySuccess => write!(f, "verify_success"),
            Self::VerifyFailed => write!(f, "verify_failed"),
            Self::Disabled => write!(f, "disabled"),
            Self::RecoveryUsed => write!(f, "recovery_used"),
            Self::RecoveryRegenerated => write!(f, "recovery_regenerated"),
            Self::PolicyChanged => write!(f, "policy_changed"),
            Self::AccountLocked => write!(f, "account_locked"),
            Self::LockoutExpired => write!(f, "lockout_expired"),
        }
    }
}

/// Data required to create a new audit log entry.
#[derive(Debug)]
pub struct CreateMfaAuditLog {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub action: MfaAuditAction,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl MfaAuditLog {
    /// Create a new audit log entry.
    pub async fn create<'e, E>(executor: E, data: CreateMfaAuditLog) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            INSERT INTO mfa_audit_log (user_id, tenant_id, action, ip_address, user_agent, metadata)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(data.user_id)
        .bind(data.tenant_id)
        .bind(data.action.to_string())
        .bind(data.ip_address)
        .bind(&data.user_agent)
        .bind(&data.metadata)
        .fetch_one(executor)
        .await
    }

    /// Find audit logs for a user with pagination.
    pub async fn find_by_user<'e, E>(
        executor: E,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM mfa_audit_log
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            ",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await
    }

    /// Find audit logs for a tenant with pagination and optional action filter.
    pub async fn find_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
        action_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        if let Some(action) = action_filter {
            sqlx::query_as(
                r"
                SELECT * FROM mfa_audit_log
                WHERE tenant_id = $1 AND action = $2
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(action)
            .bind(limit)
            .bind(offset)
            .fetch_all(executor)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM mfa_audit_log
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                ",
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(executor)
            .await
        }
    }

    /// Count recent failed verification attempts for a user.
    pub async fn count_recent_failures<'e, E>(
        executor: E,
        user_id: Uuid,
        minutes: i64,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM mfa_audit_log
            WHERE user_id = $1
              AND action = 'verify_failed'
              AND created_at > NOW() - ($2 || ' minutes')::INTERVAL
            ",
        )
        .bind(user_id)
        .bind(minutes.to_string())
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_audit_action_display() {
        assert_eq!(
            MfaAuditAction::SetupInitiated.to_string(),
            "setup_initiated"
        );
        assert_eq!(MfaAuditAction::VerifySuccess.to_string(), "verify_success");
        assert_eq!(MfaAuditAction::RecoveryUsed.to_string(), "recovery_used");
    }

    #[test]
    fn test_audit_log_struct() {
        let log = MfaAuditLog {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action: "verify_success".to_string(),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            metadata: None,
            created_at: Utc::now(),
        };
        assert_eq!(log.action, "verify_success");
    }
}
