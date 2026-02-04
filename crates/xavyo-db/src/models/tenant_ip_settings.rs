//! Tenant IP restriction settings model.
//!
//! Configures IP-based access control per tenant: enforcement mode and super admin bypass.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor, Type};
use uuid::Uuid;

/// IP restriction enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "ip_enforcement_mode", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum IpEnforcementMode {
    /// No IP restrictions applied.
    #[default]
    Disabled,
    /// Only IPs matching active whitelist rules can access.
    Whitelist,
    /// IPs matching active blacklist rules are blocked.
    Blacklist,
}

impl std::fmt::Display for IpEnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Whitelist => write!(f, "whitelist"),
            Self::Blacklist => write!(f, "blacklist"),
        }
    }
}

/// Tenant IP restriction settings.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TenantIpSettings {
    /// The tenant this settings belongs to.
    pub tenant_id: Uuid,

    /// IP restriction enforcement mode.
    pub enforcement_mode: IpEnforcementMode,

    /// Allow super admins to bypass IP restrictions.
    pub bypass_for_super_admin: bool,

    /// When the settings were last updated.
    pub updated_at: DateTime<Utc>,

    /// User who last updated the settings.
    pub updated_by: Option<Uuid>,
}

impl Default for TenantIpSettings {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            enforcement_mode: IpEnforcementMode::Disabled,
            bypass_for_super_admin: true,
            updated_at: Utc::now(),
            updated_by: None,
        }
    }
}

/// Data for updating IP restriction settings.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateIpSettings {
    pub enforcement_mode: Option<IpEnforcementMode>,
    pub bypass_for_super_admin: Option<bool>,
}

impl TenantIpSettings {
    /// Get default settings for a tenant (doesn't persist).
    #[must_use] 
    pub fn default_for_tenant(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            ..Default::default()
        }
    }

    /// Find settings by tenant ID.
    pub async fn find_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM tenant_ip_settings WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
    }

    /// Get settings for tenant, returning defaults if none exists.
    pub async fn get_or_default<'e, E>(executor: E, tenant_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        match Self::find_by_tenant(executor, tenant_id).await? {
            Some(settings) => Ok(settings),
            None => Ok(Self::default_for_tenant(tenant_id)),
        }
    }

    /// Create or update IP restriction settings.
    pub async fn upsert<'e, E>(
        executor: E,
        tenant_id: Uuid,
        data: UpdateIpSettings,
        updated_by: Option<Uuid>,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let enforcement_mode = data.enforcement_mode.unwrap_or(IpEnforcementMode::Disabled);
        let bypass_for_super_admin = data.bypass_for_super_admin.unwrap_or(true);

        sqlx::query_as(
            r"
            INSERT INTO tenant_ip_settings (
                tenant_id,
                enforcement_mode,
                bypass_for_super_admin,
                updated_at,
                updated_by
            )
            VALUES ($1, $2, $3, NOW(), $4)
            ON CONFLICT (tenant_id) DO UPDATE SET
                enforcement_mode = COALESCE($2, tenant_ip_settings.enforcement_mode),
                bypass_for_super_admin = COALESCE($3, tenant_ip_settings.bypass_for_super_admin),
                updated_at = NOW(),
                updated_by = $4
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(enforcement_mode)
        .bind(bypass_for_super_admin)
        .bind(updated_by)
        .fetch_one(executor)
        .await
    }

    /// Delete IP restriction settings for a tenant.
    pub async fn delete<'e, E>(executor: E, tenant_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM tenant_ip_settings WHERE tenant_id = $1")
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
    fn test_default_settings() {
        let settings = TenantIpSettings::default();
        assert_eq!(settings.enforcement_mode, IpEnforcementMode::Disabled);
        assert!(settings.bypass_for_super_admin);
    }

    #[test]
    fn test_default_for_tenant() {
        let tenant_id = Uuid::new_v4();
        let settings = TenantIpSettings::default_for_tenant(tenant_id);
        assert_eq!(settings.tenant_id, tenant_id);
        assert_eq!(settings.enforcement_mode, IpEnforcementMode::Disabled);
        assert!(settings.bypass_for_super_admin);
    }

    #[test]
    fn test_enforcement_mode_display() {
        assert_eq!(IpEnforcementMode::Disabled.to_string(), "disabled");
        assert_eq!(IpEnforcementMode::Whitelist.to_string(), "whitelist");
        assert_eq!(IpEnforcementMode::Blacklist.to_string(), "blacklist");
    }

    #[test]
    fn test_enforcement_mode_serialization() {
        let json = serde_json::to_string(&IpEnforcementMode::Whitelist).unwrap();
        assert_eq!(json, "\"whitelist\"");

        let mode: IpEnforcementMode = serde_json::from_str("\"blacklist\"").unwrap();
        assert_eq!(mode, IpEnforcementMode::Blacklist);
    }
}
