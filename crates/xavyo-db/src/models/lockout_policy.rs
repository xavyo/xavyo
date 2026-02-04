//! Lockout policy model for tenant-level account lockout configuration.
//!
//! Defines the configurable lockout rules per tenant.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Tenant-level lockout policy configuration.
///
/// Defines account lockout behavior including threshold, duration,
/// and notification settings.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TenantLockoutPolicy {
    /// The tenant this policy belongs to.
    pub tenant_id: Uuid,

    /// Maximum failed login attempts before lockout (0 = disabled).
    pub max_failed_attempts: i32,

    /// Lockout duration in minutes (0 = permanent until admin unlock).
    pub lockout_duration_minutes: i32,

    /// Send email notification when account is locked.
    pub notify_on_lockout: bool,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

impl Default for TenantLockoutPolicy {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            max_failed_attempts: 5,
            lockout_duration_minutes: 30,
            notify_on_lockout: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl TenantLockoutPolicy {
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
        sqlx::query_as("SELECT * FROM tenant_lockout_policies WHERE tenant_id = $1")
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

    /// Upsert (insert or update) the lockout policy for a tenant.
    pub async fn upsert<'e, E>(
        executor: E,
        tenant_id: Uuid,
        data: UpsertLockoutPolicy,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            INSERT INTO tenant_lockout_policies (
                tenant_id, max_failed_attempts, lockout_duration_minutes, notify_on_lockout
            )
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id) DO UPDATE SET
                max_failed_attempts = EXCLUDED.max_failed_attempts,
                lockout_duration_minutes = EXCLUDED.lockout_duration_minutes,
                notify_on_lockout = EXCLUDED.notify_on_lockout,
                updated_at = now()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.max_failed_attempts.unwrap_or(5))
        .bind(data.lockout_duration_minutes.unwrap_or(30))
        .bind(data.notify_on_lockout.unwrap_or(false))
        .fetch_one(executor)
        .await
    }

    /// Check if lockout is enabled for this policy.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.max_failed_attempts > 0
    }

    /// Check if lockout is permanent (requires admin unlock).
    #[must_use]
    pub fn is_permanent_lockout(&self) -> bool {
        self.lockout_duration_minutes == 0
    }

    /// Get the lockout duration as a `chrono::Duration`.
    #[must_use]
    pub fn lockout_duration(&self) -> chrono::Duration {
        chrono::Duration::minutes(i64::from(self.lockout_duration_minutes))
    }
}

/// Data for upserting a lockout policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpsertLockoutPolicy {
    pub max_failed_attempts: Option<i32>,
    pub lockout_duration_minutes: Option<i32>,
    pub notify_on_lockout: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = TenantLockoutPolicy::default();
        assert_eq!(policy.max_failed_attempts, 5);
        assert_eq!(policy.lockout_duration_minutes, 30);
        assert!(!policy.notify_on_lockout);
    }

    #[test]
    fn test_default_for_tenant() {
        let tenant_id = Uuid::new_v4();
        let policy = TenantLockoutPolicy::default_for_tenant(tenant_id);
        assert_eq!(policy.tenant_id, tenant_id);
        assert_eq!(policy.max_failed_attempts, 5);
    }

    #[test]
    fn test_is_enabled() {
        let mut policy = TenantLockoutPolicy::default();
        assert!(policy.is_enabled());

        policy.max_failed_attempts = 0;
        assert!(!policy.is_enabled());
    }

    #[test]
    fn test_is_permanent_lockout() {
        let mut policy = TenantLockoutPolicy::default();
        assert!(!policy.is_permanent_lockout());

        policy.lockout_duration_minutes = 0;
        assert!(policy.is_permanent_lockout());
    }

    #[test]
    fn test_lockout_duration() {
        let mut policy = TenantLockoutPolicy::default();
        assert_eq!(policy.lockout_duration().num_minutes(), 30);

        policy.lockout_duration_minutes = 60;
        assert_eq!(policy.lockout_duration().num_minutes(), 60);
    }
}
