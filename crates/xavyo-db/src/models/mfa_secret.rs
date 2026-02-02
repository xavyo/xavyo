//! MFA TOTP secret model.
//!
//! Stores encrypted TOTP secrets for multi-factor authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// A user's TOTP secret for MFA authentication.
///
/// The secret is encrypted at rest using AES-256-GCM.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct UserTotpSecret {
    /// Unique identifier for this TOTP record.
    pub id: Uuid,

    /// The user this TOTP belongs to.
    pub user_id: Uuid,

    /// The tenant this user belongs to.
    pub tenant_id: Uuid,

    /// AES-256-GCM encrypted TOTP secret (160-bit minimum).
    #[serde(skip_serializing)]
    pub secret_encrypted: Vec<u8>,

    /// Initialization vector for AES-GCM encryption.
    #[serde(skip_serializing)]
    pub iv: Vec<u8>,

    /// Whether MFA is fully enabled (setup completed).
    pub is_enabled: bool,

    /// Number of consecutive failed verification attempts.
    pub failed_attempts: i32,

    /// If locked, when the lockout expires.
    pub locked_until: Option<DateTime<Utc>>,

    /// When the setup process was initiated.
    pub setup_started_at: DateTime<Utc>,

    /// When the setup was completed (code verified).
    pub setup_completed_at: Option<DateTime<Utc>>,

    /// When TOTP was last successfully used.
    pub last_used_at: Option<DateTime<Utc>>,

    /// When this record was created.
    pub created_at: DateTime<Utc>,

    /// When this record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Data required to create a new TOTP secret.
#[derive(Debug)]
pub struct CreateTotpSecret {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub secret_encrypted: Vec<u8>,
    pub iv: Vec<u8>,
}

impl UserTotpSecret {
    /// Check if the TOTP verification is currently locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            locked_until > Utc::now()
        } else {
            false
        }
    }

    /// Check if the setup has expired (10 minutes timeout).
    #[must_use]
    pub fn is_setup_expired(&self) -> bool {
        if self.is_enabled {
            return false;
        }
        let expiry = self.setup_started_at + chrono::Duration::minutes(10);
        Utc::now() > expiry
    }

    /// Create a new TOTP secret record (setup initiated, not yet enabled).
    pub async fn create<'e, E>(executor: E, data: CreateTotpSecret) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO user_totp_secrets (user_id, tenant_id, secret_encrypted, iv, is_enabled)
            VALUES ($1, $2, $3, $4, false)
            RETURNING *
            "#,
        )
        .bind(data.user_id)
        .bind(data.tenant_id)
        .bind(&data.secret_encrypted)
        .bind(&data.iv)
        .fetch_one(executor)
        .await
    }

    /// Find a TOTP secret by user ID.
    pub async fn find_by_user_id<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM user_totp_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(executor)
            .await
    }

    /// Enable MFA after successful setup verification.
    pub async fn enable<'e, E>(executor: E, user_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            UPDATE user_totp_secrets
            SET is_enabled = true, setup_completed_at = NOW(), failed_attempts = 0
            WHERE user_id = $1
            RETURNING *
            "#,
        )
        .bind(user_id)
        .fetch_one(executor)
        .await
    }

    /// Record successful TOTP verification.
    pub async fn record_success<'e, E>(executor: E, user_id: Uuid) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE user_totp_secrets
            SET last_used_at = NOW(), failed_attempts = 0, locked_until = NULL
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Record failed TOTP verification and potentially lock.
    /// Returns the new failed_attempts count.
    pub async fn record_failure<'e, E>(
        executor: E,
        user_id: Uuid,
        max_attempts: i32,
        lockout_minutes: i64,
    ) -> Result<i32, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result: (i32,) = sqlx::query_as(
            r#"
            UPDATE user_totp_secrets
            SET
                failed_attempts = failed_attempts + 1,
                locked_until = CASE
                    WHEN failed_attempts + 1 >= $2 THEN NOW() + ($3 || ' minutes')::INTERVAL
                    ELSE locked_until
                END
            WHERE user_id = $1
            RETURNING failed_attempts
            "#,
        )
        .bind(user_id)
        .bind(max_attempts)
        .bind(lockout_minutes.to_string())
        .fetch_one(executor)
        .await?;
        Ok(result.0)
    }

    /// Delete a TOTP secret (disable MFA).
    pub async fn delete<'e, E>(executor: E, user_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM user_totp_secrets WHERE user_id = $1")
            .bind(user_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete an incomplete setup (for retry).
    pub async fn delete_if_not_enabled<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result =
            sqlx::query("DELETE FROM user_totp_secrets WHERE user_id = $1 AND is_enabled = false")
                .bind(user_id)
                .execute(executor)
                .await?;
        Ok(result.rows_affected() > 0)
    }
}

/// MFA policy for a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MfaPolicy {
    /// MFA is disabled for this tenant.
    Disabled,
    /// MFA is optional (user's choice).
    #[default]
    Optional,
    /// MFA is required for all users.
    Required,
}

impl std::fmt::Display for MfaPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Optional => write!(f, "optional"),
            Self::Required => write!(f, "required"),
        }
    }
}

impl std::str::FromStr for MfaPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disabled" => Ok(Self::Disabled),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => Err(format!("Invalid MFA policy: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_locked_when_not_locked() {
        let secret = create_test_secret(None);
        assert!(!secret.is_locked());
    }

    #[test]
    fn test_is_locked_when_locked() {
        let locked_until = Utc::now() + chrono::Duration::minutes(5);
        let secret = create_test_secret(Some(locked_until));
        assert!(secret.is_locked());
    }

    #[test]
    fn test_is_locked_when_expired() {
        let locked_until = Utc::now() - chrono::Duration::minutes(1);
        let secret = create_test_secret(Some(locked_until));
        assert!(!secret.is_locked());
    }

    #[test]
    fn test_mfa_policy_display() {
        assert_eq!(MfaPolicy::Disabled.to_string(), "disabled");
        assert_eq!(MfaPolicy::Optional.to_string(), "optional");
        assert_eq!(MfaPolicy::Required.to_string(), "required");
    }

    #[test]
    fn test_mfa_policy_parse() {
        assert_eq!(
            "disabled".parse::<MfaPolicy>().unwrap(),
            MfaPolicy::Disabled
        );
        assert_eq!(
            "OPTIONAL".parse::<MfaPolicy>().unwrap(),
            MfaPolicy::Optional
        );
        assert_eq!(
            "Required".parse::<MfaPolicy>().unwrap(),
            MfaPolicy::Required
        );
        assert!("invalid".parse::<MfaPolicy>().is_err());
    }

    fn create_test_secret(locked_until: Option<DateTime<Utc>>) -> UserTotpSecret {
        UserTotpSecret {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            secret_encrypted: vec![],
            iv: vec![],
            is_enabled: true,
            failed_attempts: 0,
            locked_until,
            setup_started_at: Utc::now(),
            setup_completed_at: Some(Utc::now()),
            last_used_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}
