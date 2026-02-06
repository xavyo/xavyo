//! Tenant MFA configuration model (F097).
//!
//! Detailed MFA configuration for tenants stored in `tenant_mfa_policies` table.
//! This is separate from the simpler `MfaPolicy` enum stored in `tenants.mfa_policy`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Default MFA configuration values.
pub const DEFAULT_MFA_REQUIRED: bool = false;
pub const DEFAULT_MFA_METHODS: &[&str] = &["totp", "webauthn"];
pub const DEFAULT_MFA_GRACE_PERIOD_DAYS: i32 = 0;
pub const DEFAULT_MFA_REMEMBER_DEVICE_DAYS: i32 = 30;

/// Detailed MFA configuration for a tenant.
///
/// This provides granular MFA settings beyond the simple required/optional/disabled
/// enum stored in the tenants table.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TenantMfaConfig {
    /// The tenant this configuration belongs to.
    pub tenant_id: Uuid,

    /// Whether MFA is required for all users.
    pub required: bool,

    /// Allowed MFA methods (e.g., "totp", "webauthn", "sms").
    pub methods_allowed: Vec<String>,

    /// Grace period in days before MFA is enforced for new users.
    pub grace_period_days: i32,

    /// Days to remember a device and skip MFA.
    pub remember_device_days: i32,

    /// When the configuration was created.
    pub created_at: DateTime<Utc>,

    /// When the configuration was last updated.
    pub updated_at: DateTime<Utc>,
}

impl Default for TenantMfaConfig {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            required: DEFAULT_MFA_REQUIRED,
            methods_allowed: DEFAULT_MFA_METHODS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            grace_period_days: DEFAULT_MFA_GRACE_PERIOD_DAYS,
            remember_device_days: DEFAULT_MFA_REMEMBER_DEVICE_DAYS,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// Data for creating or updating MFA configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct UpsertMfaConfig {
    pub required: Option<bool>,
    pub methods_allowed: Option<Vec<String>>,
    pub grace_period_days: Option<i32>,
    pub remember_device_days: Option<i32>,
}

impl TenantMfaConfig {
    /// Get default configuration for a tenant (doesn't persist).
    #[must_use]
    pub fn default_for_tenant(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            ..Default::default()
        }
    }

    /// Find MFA configuration by tenant ID.
    pub async fn find_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM tenant_mfa_policies WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
    }

    /// Get MFA configuration for tenant, returning defaults if none exists.
    pub async fn get_or_default<'e, E>(executor: E, tenant_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        match Self::find_by_tenant(executor, tenant_id).await? {
            Some(config) => Ok(config),
            None => Ok(Self::default_for_tenant(tenant_id)),
        }
    }

    /// Create default MFA configuration for a newly provisioned tenant.
    ///
    /// This is used during tenant provisioning to set up initial MFA policy.
    pub async fn create_default<'e, E>(executor: E, tenant_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            INSERT INTO tenant_mfa_policies (
                tenant_id,
                required,
                methods_allowed,
                grace_period_days,
                remember_device_days
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(DEFAULT_MFA_REQUIRED)
        .bind(
            DEFAULT_MFA_METHODS
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>(),
        )
        .bind(DEFAULT_MFA_GRACE_PERIOD_DAYS)
        .bind(DEFAULT_MFA_REMEMBER_DEVICE_DAYS)
        .fetch_one(executor)
        .await
    }

    /// Create or update MFA configuration.
    pub async fn upsert<'e, E>(
        executor: E,
        tenant_id: Uuid,
        data: UpsertMfaConfig,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let default_methods: Vec<String> = DEFAULT_MFA_METHODS
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        sqlx::query_as(
            r"
            INSERT INTO tenant_mfa_policies (
                tenant_id,
                required,
                methods_allowed,
                grace_period_days,
                remember_device_days
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id) DO UPDATE SET
                required = COALESCE($2, tenant_mfa_policies.required),
                methods_allowed = COALESCE($3, tenant_mfa_policies.methods_allowed),
                grace_period_days = COALESCE($4, tenant_mfa_policies.grace_period_days),
                remember_device_days = COALESCE($5, tenant_mfa_policies.remember_device_days),
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.required.unwrap_or(DEFAULT_MFA_REQUIRED))
        .bind(data.methods_allowed.unwrap_or(default_methods))
        .bind(
            data.grace_period_days
                .unwrap_or(DEFAULT_MFA_GRACE_PERIOD_DAYS),
        )
        .bind(
            data.remember_device_days
                .unwrap_or(DEFAULT_MFA_REMEMBER_DEVICE_DAYS),
        )
        .fetch_one(executor)
        .await
    }

    /// Delete MFA configuration.
    pub async fn delete<'e, E>(executor: E, tenant_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM tenant_mfa_policies WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TenantMfaConfig::default();
        assert!(!config.required);
        assert_eq!(config.methods_allowed, vec!["totp", "webauthn"]);
        assert_eq!(config.grace_period_days, 0);
        assert_eq!(config.remember_device_days, 30);
    }

    #[test]
    fn test_default_for_tenant() {
        let tenant_id = Uuid::new_v4();
        let config = TenantMfaConfig::default_for_tenant(tenant_id);
        assert_eq!(config.tenant_id, tenant_id);
        assert!(!config.required);
    }
}
