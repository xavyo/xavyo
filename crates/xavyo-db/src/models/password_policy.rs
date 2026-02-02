//! Password policy model for tenant-level password requirements.
//!
//! Defines the configurable password strength rules per tenant.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Tenant-level password policy configuration.
///
/// Defines password strength requirements including length, character types,
/// expiration, and history tracking. Uses NIST 800-63B compliant defaults.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TenantPasswordPolicy {
    /// The tenant this policy belongs to.
    pub tenant_id: Uuid,

    /// Minimum password length (8-128, default 8).
    pub min_length: i32,

    /// Maximum password length (default 128).
    pub max_length: i32,

    /// Require at least one uppercase letter (A-Z).
    pub require_uppercase: bool,

    /// Require at least one lowercase letter (a-z).
    pub require_lowercase: bool,

    /// Require at least one digit (0-9).
    pub require_digit: bool,

    /// Require at least one special character (!@#$%^&*...).
    pub require_special: bool,

    /// Days until password expires (0 = never expires).
    pub expiration_days: i32,

    /// Number of previous passwords to check for reuse (0-24, 0 = no check).
    pub history_count: i32,

    /// Minimum hours before password can be changed (0 = immediate).
    pub min_age_hours: i32,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

impl Default for TenantPasswordPolicy {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            min_length: 8,
            max_length: 128,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            expiration_days: 0,
            history_count: 0,
            min_age_hours: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl TenantPasswordPolicy {
    /// Create a default policy for the given tenant.
    #[must_use]
    pub fn default_for_tenant(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            ..Default::default()
        }
    }

    /// Find policy by tenant ID.
    pub async fn find_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as("SELECT * FROM tenant_password_policies WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
    }

    /// Get policy for tenant, returning defaults if not configured.
    pub async fn get_or_default<'e, E>(executor: E, tenant_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        match Self::find_by_tenant(executor, tenant_id).await? {
            Some(policy) => Ok(policy),
            None => Ok(Self::default_for_tenant(tenant_id)),
        }
    }

    /// Create default password policy for a newly provisioned tenant.
    ///
    /// This is used during tenant provisioning (F097) to set up initial password policy.
    /// The defaults follow NIST 800-63B recommendations:
    /// - Minimum 12 characters (more secure than default 8)
    /// - No character type requirements (users choose memorable passwords)
    /// - No expiration (password rotation not recommended by NIST)
    pub async fn create_default<'e, E>(executor: E, tenant_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO tenant_password_policies (
                tenant_id, min_length, max_length, require_uppercase, require_lowercase,
                require_digit, require_special, expiration_days, history_count, min_age_hours
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(12i32) // NIST recommends longer minimums
        .bind(128i32)
        .bind(false) // No uppercase requirement
        .bind(false) // No lowercase requirement
        .bind(false) // No digit requirement
        .bind(false) // No special char requirement
        .bind(0i32) // No expiration (NIST recommendation)
        .bind(0i32) // No history check
        .bind(0i32) // No minimum age
        .fetch_one(executor)
        .await
    }

    /// Upsert (insert or update) the password policy for a tenant.
    pub async fn upsert<'e, E>(
        executor: E,
        tenant_id: Uuid,
        data: UpsertPasswordPolicy,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO tenant_password_policies (
                tenant_id, min_length, max_length, require_uppercase, require_lowercase,
                require_digit, require_special, expiration_days, history_count, min_age_hours
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (tenant_id) DO UPDATE SET
                min_length = EXCLUDED.min_length,
                max_length = EXCLUDED.max_length,
                require_uppercase = EXCLUDED.require_uppercase,
                require_lowercase = EXCLUDED.require_lowercase,
                require_digit = EXCLUDED.require_digit,
                require_special = EXCLUDED.require_special,
                expiration_days = EXCLUDED.expiration_days,
                history_count = EXCLUDED.history_count,
                min_age_hours = EXCLUDED.min_age_hours,
                updated_at = now()
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(data.min_length.unwrap_or(8))
        .bind(data.max_length.unwrap_or(128))
        .bind(data.require_uppercase.unwrap_or(false))
        .bind(data.require_lowercase.unwrap_or(false))
        .bind(data.require_digit.unwrap_or(false))
        .bind(data.require_special.unwrap_or(false))
        .bind(data.expiration_days.unwrap_or(0))
        .bind(data.history_count.unwrap_or(0))
        .bind(data.min_age_hours.unwrap_or(0))
        .fetch_one(executor)
        .await
    }

    /// Check if this policy has any character requirements enabled.
    #[must_use]
    pub fn has_character_requirements(&self) -> bool {
        self.require_uppercase
            || self.require_lowercase
            || self.require_digit
            || self.require_special
    }

    /// Check if password expiration is enabled.
    #[must_use]
    pub fn has_expiration(&self) -> bool {
        self.expiration_days > 0
    }

    /// Check if password history tracking is enabled.
    #[must_use]
    pub fn has_history_check(&self) -> bool {
        self.history_count > 0
    }

    /// Check if minimum password age is enabled.
    #[must_use]
    pub fn has_min_age(&self) -> bool {
        self.min_age_hours > 0
    }
}

/// Data for upserting a password policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpsertPasswordPolicy {
    pub min_length: Option<i32>,
    pub max_length: Option<i32>,
    pub require_uppercase: Option<bool>,
    pub require_lowercase: Option<bool>,
    pub require_digit: Option<bool>,
    pub require_special: Option<bool>,
    pub expiration_days: Option<i32>,
    pub history_count: Option<i32>,
    pub min_age_hours: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = TenantPasswordPolicy::default();
        assert_eq!(policy.min_length, 8);
        assert_eq!(policy.max_length, 128);
        assert!(!policy.require_uppercase);
        assert!(!policy.require_lowercase);
        assert!(!policy.require_digit);
        assert!(!policy.require_special);
        assert_eq!(policy.expiration_days, 0);
        assert_eq!(policy.history_count, 0);
        assert_eq!(policy.min_age_hours, 0);
    }

    #[test]
    fn test_default_for_tenant() {
        let tenant_id = Uuid::new_v4();
        let policy = TenantPasswordPolicy::default_for_tenant(tenant_id);
        assert_eq!(policy.tenant_id, tenant_id);
        assert_eq!(policy.min_length, 8);
    }

    #[test]
    fn test_has_character_requirements() {
        let mut policy = TenantPasswordPolicy::default();
        assert!(!policy.has_character_requirements());

        policy.require_uppercase = true;
        assert!(policy.has_character_requirements());
    }

    #[test]
    fn test_has_expiration() {
        let mut policy = TenantPasswordPolicy::default();
        assert!(!policy.has_expiration());

        policy.expiration_days = 90;
        assert!(policy.has_expiration());
    }

    #[test]
    fn test_has_history_check() {
        let mut policy = TenantPasswordPolicy::default();
        assert!(!policy.has_history_check());

        policy.history_count = 5;
        assert!(policy.has_history_check());
    }

    #[test]
    fn test_has_min_age() {
        let mut policy = TenantPasswordPolicy::default();
        assert!(!policy.has_min_age());

        policy.min_age_hours = 24;
        assert!(policy.has_min_age());
    }
}
