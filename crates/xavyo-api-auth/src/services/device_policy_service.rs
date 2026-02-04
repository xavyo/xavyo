//! Device policy service (F026).
//!
//! Handles tenant device policy configuration.

use crate::error::ApiAuthError;
use crate::models::device_requests::{DevicePolicyResponse, UpdateDevicePolicyRequest};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;
use xavyo_db::set_tenant_context;

/// Default trust duration in days.
pub const DEFAULT_TRUST_DURATION_DAYS: i32 = 30;

/// Device policy key in `tenant_policies` JSONB.
const DEVICE_POLICY_KEY: &str = "device_policy";

/// Device policy settings stored in `tenant_policies` JSONB.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DevicePolicy {
    /// Allow trusted devices to bypass MFA.
    pub allow_trusted_device_mfa_bypass: bool,

    /// Default trust duration in days (0 = permanent).
    pub trusted_device_duration_days: i32,
}

impl Default for DevicePolicy {
    fn default() -> Self {
        Self {
            allow_trusted_device_mfa_bypass: false,
            trusted_device_duration_days: DEFAULT_TRUST_DURATION_DAYS,
        }
    }
}

impl From<DevicePolicy> for DevicePolicyResponse {
    fn from(policy: DevicePolicy) -> Self {
        Self {
            allow_trusted_device_mfa_bypass: policy.allow_trusted_device_mfa_bypass,
            trusted_device_duration_days: policy.trusted_device_duration_days,
        }
    }
}

/// Device policy service.
#[derive(Clone)]
pub struct DevicePolicyService {
    pool: PgPool,
}

impl DevicePolicyService {
    /// Create a new device policy service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get device policy for a tenant.
    pub async fn get_device_policy(&self, tenant_id: Uuid) -> Result<DevicePolicy, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Query tenant_policies for device policy
        let result: Option<(serde_json::Value,)> = sqlx::query_as(
            r"
            SELECT policies
            FROM tenant_policies
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        if let Some((policies,)) = result {
            if let Some(device_policy) = policies.get(DEVICE_POLICY_KEY) {
                if let Ok(policy) = serde_json::from_value(device_policy.clone()) {
                    return Ok(policy);
                }
            }
        }

        // Return default policy if not found
        Ok(DevicePolicy::default())
    }

    /// Update device policy for a tenant.
    pub async fn update_device_policy(
        &self,
        tenant_id: Uuid,
        request: UpdateDevicePolicyRequest,
    ) -> Result<DevicePolicy, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get current policy
        let mut current = self.get_device_policy(tenant_id).await?;

        // Apply updates
        if let Some(allow_mfa_bypass) = request.allow_trusted_device_mfa_bypass {
            current.allow_trusted_device_mfa_bypass = allow_mfa_bypass;
        }
        if let Some(duration_days) = request.trusted_device_duration_days {
            // Validate: must be >= 0
            if duration_days < 0 {
                return Err(ApiAuthError::Validation(
                    "trusted_device_duration_days must be >= 0".to_string(),
                ));
            }
            current.trusted_device_duration_days = duration_days;
        }

        // Upsert into tenant_policies
        let policy_value = serde_json::to_value(&current).map_err(|e| {
            ApiAuthError::Internal(format!("Failed to serialize device policy: {e}"))
        })?;

        sqlx::query(
            r"
            INSERT INTO tenant_policies (tenant_id, policies)
            VALUES ($1, jsonb_build_object($2, $3))
            ON CONFLICT (tenant_id) DO UPDATE
            SET policies = tenant_policies.policies || jsonb_build_object($2, $3),
                updated_at = NOW()
            ",
        )
        .bind(tenant_id)
        .bind(DEVICE_POLICY_KEY)
        .bind(policy_value)
        .execute(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        info!(
            tenant_id = %tenant_id,
            allow_mfa_bypass = current.allow_trusted_device_mfa_bypass,
            duration_days = current.trusted_device_duration_days,
            "Device policy updated"
        );

        Ok(current)
    }

    /// Check if trusted device MFA bypass is allowed for a tenant.
    pub async fn is_mfa_bypass_allowed(&self, tenant_id: Uuid) -> Result<bool, ApiAuthError> {
        let policy = self.get_device_policy(tenant_id).await?;
        Ok(policy.allow_trusted_device_mfa_bypass)
    }

    /// Get default trust duration for a tenant.
    pub async fn get_default_trust_duration(&self, tenant_id: Uuid) -> Result<i32, ApiAuthError> {
        let policy = self.get_device_policy(tenant_id).await?;
        Ok(policy.trusted_device_duration_days)
    }

    /// Cap trust duration to tenant maximum.
    /// If requested duration exceeds tenant's configured maximum, returns the tenant maximum.
    pub async fn cap_trust_duration(
        &self,
        tenant_id: Uuid,
        requested_days: Option<i32>,
    ) -> Result<i32, ApiAuthError> {
        let policy = self.get_device_policy(tenant_id).await?;
        let tenant_max = policy.trusted_device_duration_days;

        // If tenant allows permanent trust (0), don't cap
        if tenant_max == 0 {
            return Ok(requested_days.unwrap_or(0));
        }

        // If no duration requested, use tenant default
        let requested = requested_days.unwrap_or(tenant_max);

        // If requested is 0 (permanent) but tenant doesn't allow, use tenant max
        if requested == 0 {
            return Ok(tenant_max);
        }

        // Cap to tenant maximum
        Ok(requested.min(tenant_max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = DevicePolicy::default();
        assert!(!policy.allow_trusted_device_mfa_bypass);
        assert_eq!(policy.trusted_device_duration_days, 30);
    }

    #[test]
    fn test_policy_to_response() {
        let policy = DevicePolicy {
            allow_trusted_device_mfa_bypass: true,
            trusted_device_duration_days: 14,
        };
        let response: DevicePolicyResponse = policy.into();
        assert!(response.allow_trusted_device_mfa_bypass);
        assert_eq!(response.trusted_device_duration_days, 14);
    }
}
