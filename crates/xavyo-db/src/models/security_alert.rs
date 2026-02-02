//! Security alert model for user notifications.
//!
//! Alerts users about suspicious activity on their accounts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// Type of security alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    /// First login from a new device.
    NewDevice,
    /// First login from a new location.
    NewLocation,
    /// Multiple failed login attempts.
    FailedAttempts,
    /// Password was changed.
    PasswordChange,
    /// MFA was disabled.
    MfaDisabled,
}

impl AlertType {
    /// Convert to database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NewDevice => "new_device",
            Self::NewLocation => "new_location",
            Self::FailedAttempts => "failed_attempts",
            Self::PasswordChange => "password_change",
            Self::MfaDisabled => "mfa_disabled",
        }
    }

    /// Parse from database string representation.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "new_device" => Some(Self::NewDevice),
            "new_location" => Some(Self::NewLocation),
            "failed_attempts" => Some(Self::FailedAttempts),
            "password_change" => Some(Self::PasswordChange),
            "mfa_disabled" => Some(Self::MfaDisabled),
            _ => None,
        }
    }
}

impl std::fmt::Display for AlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Severity level of a security alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational, normal activity.
    Info,
    /// Suspicious activity, requires attention.
    Warning,
    /// Urgent, immediate attention required.
    Critical,
}

impl Severity {
    /// Convert to database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    /// Parse from database string representation.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "info" => Self::Info,
            "warning" => Self::Warning,
            "critical" => Self::Critical,
            _ => Self::Info,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A security alert for a user.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SecurityAlert {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant for RLS isolation.
    pub tenant_id: Uuid,

    /// The user this alert is for.
    pub user_id: Uuid,

    /// Type of alert.
    pub alert_type: String,

    /// Severity level.
    pub severity: String,

    /// Human-readable title.
    pub title: String,

    /// Detailed message.
    pub message: String,

    /// Additional context data.
    pub metadata: JsonValue,

    /// When the user acknowledged this alert.
    pub acknowledged_at: Option<DateTime<Utc>>,

    /// When the alert was created.
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new security alert.
#[derive(Debug, Clone)]
pub struct CreateSecurityAlert {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub alert_type: AlertType,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    pub metadata: JsonValue,
}

impl SecurityAlert {
    /// Create a new security alert.
    pub async fn create<'e, E>(executor: E, input: CreateSecurityAlert) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO security_alerts (tenant_id, user_id, alert_type, severity, title, message, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(input.tenant_id)
        .bind(input.user_id)
        .bind(input.alert_type.as_str())
        .bind(input.severity.as_str())
        .bind(&input.title)
        .bind(&input.message)
        .bind(&input.metadata)
        .fetch_one(executor)
        .await
    }

    /// Get the alert type as an enum.
    #[must_use]
    pub fn alert_type_enum(&self) -> Option<AlertType> {
        AlertType::parse(&self.alert_type)
    }

    /// Get the severity as an enum.
    #[must_use]
    pub fn severity_enum(&self) -> Severity {
        Severity::parse(&self.severity)
    }

    /// Check if the alert has been acknowledged.
    #[must_use]
    pub fn is_acknowledged(&self) -> bool {
        self.acknowledged_at.is_some()
    }

    /// Get alerts for a user with cursor-based pagination.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_user_alerts<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        alert_type: Option<&str>,
        severity: Option<&str>,
        acknowledged: Option<bool>,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM security_alerts
            WHERE tenant_id = $1
              AND user_id = $2
              AND ($3::text IS NULL OR alert_type = $3)
              AND ($4::text IS NULL OR severity = $4)
              AND ($5::boolean IS NULL OR
                   ($5 = true AND acknowledged_at IS NOT NULL) OR
                   ($5 = false AND acknowledged_at IS NULL))
              AND ($6::timestamptz IS NULL OR created_at < $6)
            ORDER BY created_at DESC
            LIMIT $7
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(alert_type)
        .bind(severity)
        .bind(acknowledged)
        .bind(cursor)
        .bind(limit)
        .fetch_all(executor)
        .await
    }

    /// Count total alerts for a user.
    pub async fn count_user_alerts<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM security_alerts
            WHERE tenant_id = $1 AND user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Count unacknowledged alerts for a user.
    pub async fn count_unacknowledged<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM security_alerts
            WHERE tenant_id = $1 AND user_id = $2 AND acknowledged_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Get an alert by ID.
    pub async fn get_by_id<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            SELECT * FROM security_alerts
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// Acknowledge an alert.
    pub async fn acknowledge<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            UPDATE security_alerts
            SET acknowledged_at = NOW()
            WHERE tenant_id = $1 AND id = $2 AND user_id = $3 AND acknowledged_at IS NULL
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .fetch_optional(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_type_roundtrip() {
        let types = [
            AlertType::NewDevice,
            AlertType::NewLocation,
            AlertType::FailedAttempts,
            AlertType::PasswordChange,
            AlertType::MfaDisabled,
        ];

        for alert_type in types {
            let s = alert_type.as_str();
            let parsed = AlertType::parse(s);
            assert_eq!(Some(alert_type), parsed);
        }
    }

    #[test]
    fn test_severity_roundtrip() {
        let severities = [Severity::Info, Severity::Warning, Severity::Critical];

        for severity in severities {
            let s = severity.as_str();
            let parsed = Severity::parse(s);
            assert_eq!(severity, parsed);
        }
    }

    #[test]
    fn test_unknown_alert_type_returns_none() {
        let parsed = AlertType::parse("unknown");
        assert!(parsed.is_none());
    }

    #[test]
    fn test_unknown_severity_defaults_to_info() {
        let parsed = Severity::parse("unknown");
        assert_eq!(parsed, Severity::Info);
    }
}
