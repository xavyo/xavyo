//! Tenant MFA policy model.
//!
//! Manages MFA policy settings for tenants (disabled, optional, required).

use serde::{Deserialize, Serialize};
use sqlx::PgExecutor;
use uuid::Uuid;

use super::mfa_secret::MfaPolicy;

/// Tenant MFA policy with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMfaPolicy {
    /// The tenant ID.
    pub tenant_id: Uuid,
    /// The MFA policy.
    pub mfa_policy: MfaPolicy,
}

impl TenantMfaPolicy {
    /// Get MFA policy for a tenant.
    pub async fn get<'e, E>(executor: E, tenant_id: Uuid) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let row: (String,) = sqlx::query_as("SELECT mfa_policy FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_one(executor)
            .await?;

        let mfa_policy = row.0.parse().unwrap_or_default();

        Ok(Self {
            tenant_id,
            mfa_policy,
        })
    }

    /// Update MFA policy for a tenant.
    pub async fn update<'e, E>(
        executor: E,
        tenant_id: Uuid,
        policy: MfaPolicy,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE tenants SET mfa_policy = $1 WHERE id = $2")
            .bind(policy.to_string())
            .bind(tenant_id)
            .execute(executor)
            .await?;

        Ok(Self {
            tenant_id,
            mfa_policy: policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_mfa_policy_struct() {
        let policy = TenantMfaPolicy {
            tenant_id: Uuid::new_v4(),
            mfa_policy: MfaPolicy::Required,
        };
        assert_eq!(policy.mfa_policy, MfaPolicy::Required);
    }
}
