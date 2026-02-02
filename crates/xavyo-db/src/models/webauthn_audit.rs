//! WebAuthn audit log model.
//!
//! Stores security audit events for all WebAuthn operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// WebAuthn audit action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebAuthnAuditAction {
    /// Registration ceremony started.
    RegistrationStarted,
    /// Registration completed successfully.
    RegistrationCompleted,
    /// Registration failed.
    RegistrationFailed,
    /// Authentication ceremony started.
    AuthenticationStarted,
    /// Authentication succeeded.
    AuthenticationSuccess,
    /// Authentication failed.
    AuthenticationFailed,
    /// Credential was renamed.
    CredentialRenamed,
    /// Credential was deleted by user.
    CredentialDeleted,
    /// Credential was revoked by administrator.
    CredentialRevokedByAdmin,
    /// Sign counter anomaly detected (possible cloned credential).
    CounterAnomalyDetected,
}

impl std::fmt::Display for WebAuthnAuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::RegistrationStarted => "registration_started",
            Self::RegistrationCompleted => "registration_completed",
            Self::RegistrationFailed => "registration_failed",
            Self::AuthenticationStarted => "authentication_started",
            Self::AuthenticationSuccess => "authentication_success",
            Self::AuthenticationFailed => "authentication_failed",
            Self::CredentialRenamed => "credential_renamed",
            Self::CredentialDeleted => "credential_deleted",
            Self::CredentialRevokedByAdmin => "credential_revoked_by_admin",
            Self::CounterAnomalyDetected => "counter_anomaly_detected",
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for WebAuthnAuditAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "registration_started" => Ok(Self::RegistrationStarted),
            "registration_completed" => Ok(Self::RegistrationCompleted),
            "registration_failed" => Ok(Self::RegistrationFailed),
            "authentication_started" => Ok(Self::AuthenticationStarted),
            "authentication_success" => Ok(Self::AuthenticationSuccess),
            "authentication_failed" => Ok(Self::AuthenticationFailed),
            "credential_renamed" => Ok(Self::CredentialRenamed),
            "credential_deleted" => Ok(Self::CredentialDeleted),
            "credential_revoked_by_admin" => Ok(Self::CredentialRevokedByAdmin),
            "counter_anomaly_detected" => Ok(Self::CounterAnomalyDetected),
            _ => Err(format!("Invalid WebAuthn audit action: {}", s)),
        }
    }
}

/// A WebAuthn audit log entry.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct WebAuthnAuditLog {
    /// Unique identifier for this log entry.
    pub id: Uuid,

    /// The user involved in this action.
    pub user_id: Uuid,

    /// The tenant this user belongs to.
    pub tenant_id: Uuid,

    /// The credential involved (if applicable).
    pub credential_id: Option<Uuid>,

    /// The action that occurred.
    pub action: String,

    /// Client IP address.
    pub ip_address: Option<String>,

    /// Client user agent.
    pub user_agent: Option<String>,

    /// Additional metadata (error details, etc.).
    pub metadata: Option<serde_json::Value>,

    /// When this event occurred.
    pub created_at: DateTime<Utc>,
}

/// Data required to create a new audit log entry.
#[derive(Debug)]
pub struct CreateWebAuthnAuditLog {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub credential_id: Option<Uuid>,
    pub action: WebAuthnAuditAction,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Filter for querying WebAuthn audit logs.
#[derive(Debug, Default)]
pub struct WebAuthnAuditLogFilter {
    pub user_id: Option<Uuid>,
    pub credential_id: Option<Uuid>,
    pub action: Option<WebAuthnAuditAction>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl WebAuthnAuditLog {
    /// Create a new audit log entry.
    pub async fn create<'e, E>(
        executor: E,
        data: CreateWebAuthnAuditLog,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO webauthn_audit_log (
                user_id, tenant_id, credential_id, action, ip_address, user_agent, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(data.user_id)
        .bind(data.tenant_id)
        .bind(data.credential_id)
        .bind(data.action.to_string())
        .bind(&data.ip_address)
        .bind(&data.user_agent)
        .bind(&data.metadata)
        .fetch_one(executor)
        .await
    }

    /// Find audit logs for a user.
    pub async fn find_by_user_id<'e, E>(
        executor: E,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM webauthn_audit_log
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await
    }

    /// Find audit logs for a specific credential.
    pub async fn find_by_credential_id<'e, E>(
        executor: E,
        credential_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM webauthn_audit_log
            WHERE credential_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(credential_id)
        .bind(limit)
        .fetch_all(executor)
        .await
    }

    /// Find recent failed authentication attempts for a user.
    pub async fn count_recent_failures<'e, E>(
        executor: E,
        user_id: Uuid,
        minutes: i64,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM webauthn_audit_log
            WHERE user_id = $1
                AND action = 'authentication_failed'
                AND created_at > NOW() - ($2 || ' minutes')::INTERVAL
            "#,
        )
        .bind(user_id)
        .bind(minutes.to_string())
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }

    /// Find counter anomaly events for a credential.
    pub async fn find_counter_anomalies<'e, E>(
        executor: E,
        credential_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM webauthn_audit_log
            WHERE credential_id = $1 AND action = 'counter_anomaly_detected'
            ORDER BY created_at DESC
            "#,
        )
        .bind(credential_id)
        .fetch_all(executor)
        .await
    }

    /// Delete old audit logs (retention policy).
    pub async fn delete_older_than<'e, E>(executor: E, days: i64) -> Result<u64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            "DELETE FROM webauthn_audit_log WHERE created_at < NOW() - ($1 || ' days')::INTERVAL",
        )
        .bind(days.to_string())
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_display() {
        assert_eq!(
            WebAuthnAuditAction::RegistrationStarted.to_string(),
            "registration_started"
        );
        assert_eq!(
            WebAuthnAuditAction::AuthenticationSuccess.to_string(),
            "authentication_success"
        );
        assert_eq!(
            WebAuthnAuditAction::CounterAnomalyDetected.to_string(),
            "counter_anomaly_detected"
        );
    }

    #[test]
    fn test_audit_action_parse() {
        assert_eq!(
            "registration_started"
                .parse::<WebAuthnAuditAction>()
                .unwrap(),
            WebAuthnAuditAction::RegistrationStarted
        );
        assert_eq!(
            "authentication_failed"
                .parse::<WebAuthnAuditAction>()
                .unwrap(),
            WebAuthnAuditAction::AuthenticationFailed
        );
        assert!("invalid_action".parse::<WebAuthnAuditAction>().is_err());
    }
}
