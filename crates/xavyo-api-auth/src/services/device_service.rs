//! Device management service (F026).
//!
//! Handles device listing, trust management, renaming, and revocation.

use crate::error::ApiAuthError;
use crate::services::user_agent_parser::parse_user_agent;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;
use xavyo_db::{set_tenant_context, UserDevice};

/// Minimum length for a valid device fingerprint (SHA-256 = 64 hex chars).
const MIN_FINGERPRINT_LENGTH: usize = 32;
/// Maximum length for a valid device fingerprint.
const MAX_FINGERPRINT_LENGTH: usize = 128;

/// Validate that a device fingerprint is properly formatted.
/// Accepts hex strings of reasonable length (at least 32 chars for truncated hashes).
fn validate_fingerprint(fingerprint: &str) -> Result<(), ApiAuthError> {
    let len = fingerprint.len();
    if !(MIN_FINGERPRINT_LENGTH..=MAX_FINGERPRINT_LENGTH).contains(&len) {
        return Err(ApiAuthError::Validation(format!(
            "device_fingerprint must be between {} and {} characters",
            MIN_FINGERPRINT_LENGTH, MAX_FINGERPRINT_LENGTH
        )));
    }
    if !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiAuthError::Validation(
            "device_fingerprint must be a valid hexadecimal string".to_string(),
        ));
    }
    Ok(())
}

/// Device management service.
#[derive(Clone)]
pub struct DeviceService {
    pool: PgPool,
}

impl DeviceService {
    /// Create a new device service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ========================================================================
    // User Story 1: View My Devices
    // ========================================================================

    /// Get all active (non-revoked) devices for a user.
    pub async fn get_user_devices(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        current_fingerprint: Option<&str>,
    ) -> Result<(Vec<UserDevice>, Option<Uuid>), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let devices = UserDevice::get_user_devices(&mut *conn, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Find current device ID if fingerprint provided
        let current_device_id = current_fingerprint.and_then(|fp| {
            devices
                .iter()
                .find(|d| d.device_fingerprint == fp)
                .map(|d| d.id)
        });

        Ok((devices, current_device_id))
    }

    /// Update device information on login (upsert).
    /// Returns the device ID and whether it's a new device.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_device_on_login(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        device_fingerprint: &str,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
        geo_country: Option<&str>,
        geo_city: Option<&str>,
    ) -> Result<(Uuid, bool), ApiAuthError> {
        // Validate fingerprint format
        validate_fingerprint(device_fingerprint)?;

        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Parse user agent for device info
        let device_info = user_agent.map(parse_user_agent).unwrap_or_default();

        // Check if device exists
        let existing =
            UserDevice::get_by_fingerprint(&mut *conn, tenant_id, user_id, device_fingerprint)
                .await
                .map_err(ApiAuthError::Database)?;

        if let Some(device) = existing {
            // Check if device is revoked
            if device.revoked_at.is_some() {
                warn!(
                    device_id = %device.id,
                    user_id = %user_id,
                    "Login attempt from revoked device"
                );
                return Err(ApiAuthError::DeviceRevoked);
            }

            // Update existing device
            UserDevice::update_device_info(
                &mut *conn,
                tenant_id,
                device.id,
                Some(&device_info.device_type),
                device_info.browser.as_deref(),
                device_info.browser_version.as_deref(),
                device_info.os.as_deref(),
                device_info.os_version.as_deref(),
                ip_address,
                geo_country,
                geo_city,
            )
            .await
            .map_err(ApiAuthError::Database)?;

            info!(
                device_id = %device.id,
                user_id = %user_id,
                "Device info updated on login"
            );

            Ok((device.id, false))
        } else {
            // Create new device using record_login
            let (device, is_new) =
                UserDevice::record_login(&mut *conn, tenant_id, user_id, device_fingerprint)
                    .await
                    .map_err(ApiAuthError::Database)?;

            // Update device info if we have user agent
            if user_agent.is_some() {
                UserDevice::update_device_info(
                    &mut *conn,
                    tenant_id,
                    device.id,
                    Some(&device_info.device_type),
                    device_info.browser.as_deref(),
                    device_info.browser_version.as_deref(),
                    device_info.os.as_deref(),
                    device_info.os_version.as_deref(),
                    ip_address,
                    geo_country,
                    geo_city,
                )
                .await
                .map_err(ApiAuthError::Database)?;
            }

            info!(
                device_id = %device.id,
                user_id = %user_id,
                device_type = ?device_info.device_type,
                browser = ?device_info.browser,
                os = ?device_info.os,
                is_new = is_new,
                "Device recorded on login"
            );

            Ok((device.id, is_new))
        }
    }

    // ========================================================================
    // User Story 2: Manage Device Trust
    // ========================================================================

    /// Trust a device with optional custom duration.
    pub async fn trust_device(
        &self,
        device_id: Uuid,
        user_id: Uuid,
        tenant_id: Uuid,
        duration_days: Option<i32>,
        default_duration_days: i32,
    ) -> Result<UserDevice, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get device and verify ownership
        let device = UserDevice::get_by_id_and_user(&mut *conn, tenant_id, device_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::DeviceNotFound)?;

        // Check if device is revoked
        if device.revoked_at.is_some() {
            return Err(ApiAuthError::DeviceRevoked);
        }

        // Calculate trust expiry
        let days = duration_days.unwrap_or(default_duration_days);
        let trust_expires_at = if days <= 0 {
            None // Permanent trust
        } else {
            Some(Utc::now() + Duration::days(days as i64))
        };

        // Trust the device
        let updated =
            UserDevice::trust(&mut *conn, tenant_id, device_id, user_id, trust_expires_at)
                .await
                .map_err(ApiAuthError::Database)?
                .ok_or(ApiAuthError::DeviceNotFound)?;

        info!(
            device_id = %device_id,
            user_id = %user_id,
            trust_expires_at = ?trust_expires_at,
            "Device trusted"
        );

        Ok(updated)
    }

    /// Remove trust from a device.
    pub async fn untrust_device(
        &self,
        device_id: Uuid,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<UserDevice, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get device and verify ownership
        let device = UserDevice::get_by_id_and_user(&mut *conn, tenant_id, device_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::DeviceNotFound)?;

        // Check if device is revoked
        if device.revoked_at.is_some() {
            return Err(ApiAuthError::DeviceRevoked);
        }

        // Untrust the device
        let updated = UserDevice::untrust(&mut *conn, tenant_id, device_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::DeviceNotFound)?;

        info!(
            device_id = %device_id,
            user_id = %user_id,
            "Device trust removed"
        );

        Ok(updated)
    }

    /// Check if a device is currently trusted (for MFA bypass).
    pub async fn is_device_trusted(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        device_fingerprint: &str,
    ) -> Result<bool, ApiAuthError> {
        // Validate fingerprint format
        validate_fingerprint(device_fingerprint)?;

        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let trusted =
            UserDevice::get_trusted_device(&mut *conn, tenant_id, user_id, device_fingerprint)
                .await
                .map_err(ApiAuthError::Database)?;

        Ok(trusted.is_some())
    }

    // ========================================================================
    // User Story 3: Rename and Revoke Devices
    // ========================================================================

    /// Rename a device.
    pub async fn rename_device(
        &self,
        device_id: Uuid,
        user_id: Uuid,
        tenant_id: Uuid,
        new_name: &str,
    ) -> Result<UserDevice, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get device and verify ownership
        let device = UserDevice::get_by_id_and_user(&mut *conn, tenant_id, device_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::DeviceNotFound)?;

        // Check if device is revoked
        if device.revoked_at.is_some() {
            return Err(ApiAuthError::DeviceRevoked);
        }

        // Rename the device
        let updated =
            UserDevice::update_name(&mut *conn, tenant_id, device_id, user_id, Some(new_name))
                .await
                .map_err(ApiAuthError::Database)?
                .ok_or(ApiAuthError::DeviceNotFound)?;

        info!(
            device_id = %device_id,
            user_id = %user_id,
            new_name = %new_name,
            "Device renamed"
        );

        Ok(updated)
    }

    /// Revoke a device (soft delete).
    pub async fn revoke_device(
        &self,
        device_id: Uuid,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get device and verify ownership
        let device = UserDevice::get_by_id_and_user(&mut *conn, tenant_id, device_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::DeviceNotFound)?;

        // Check if already revoked
        if device.revoked_at.is_some() {
            return Err(ApiAuthError::DeviceRevoked);
        }

        // Revoke the device
        UserDevice::revoke(&mut *conn, tenant_id, device_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(
            device_id = %device_id,
            user_id = %user_id,
            "Device revoked by user"
        );

        Ok(())
    }

    // ========================================================================
    // User Story 4: Admin Device Management
    // ========================================================================

    /// Get all devices for a user (admin view, optionally including revoked).
    pub async fn get_user_devices_admin(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        include_revoked: bool,
    ) -> Result<Vec<UserDevice>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let devices =
            UserDevice::get_user_devices_all(&mut *conn, tenant_id, user_id, include_revoked)
                .await
                .map_err(ApiAuthError::Database)?;

        Ok(devices)
    }

    /// Revoke a device as admin (no ownership check, just tenant check).
    pub async fn revoke_device_admin(
        &self,
        device_id: Uuid,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get device (verify it belongs to the specified user in this tenant)
        let device = UserDevice::get_by_id(&mut *conn, tenant_id, device_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::DeviceNotFound)?;

        // Verify user_id matches
        if device.user_id != user_id {
            return Err(ApiAuthError::DeviceNotFound);
        }

        // Check if already revoked
        if device.revoked_at.is_some() {
            return Err(ApiAuthError::DeviceRevoked);
        }

        // Revoke the device (admin version)
        UserDevice::revoke_admin(&mut *conn, tenant_id, device_id)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(
            device_id = %device_id,
            user_id = %user_id,
            tenant_id = %tenant_id,
            "Device revoked by admin"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_fingerprint_valid_sha256() {
        let fingerprint = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
        assert!(validate_fingerprint(fingerprint).is_ok());
    }

    #[test]
    fn test_validate_fingerprint_valid_minimum() {
        let fingerprint = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"; // 32 chars
        assert!(validate_fingerprint(fingerprint).is_ok());
    }

    #[test]
    fn test_validate_fingerprint_too_short() {
        let fingerprint = "a1b2c3d4e5f6a7b8"; // 16 chars
        let result = validate_fingerprint(fingerprint);
        assert!(result.is_err());
        if let Err(ApiAuthError::Validation(msg)) = result {
            assert!(msg.contains("between"));
        }
    }

    #[test]
    fn test_validate_fingerprint_too_long() {
        let fingerprint = "a".repeat(200);
        let result = validate_fingerprint(&fingerprint);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_fingerprint_invalid_chars() {
        let fingerprint = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6ghij"; // contains g, h, i, j
        let result = validate_fingerprint(fingerprint);
        assert!(result.is_err());
        if let Err(ApiAuthError::Validation(msg)) = result {
            assert!(msg.contains("hexadecimal"));
        }
    }

    #[test]
    fn test_validate_fingerprint_uppercase_hex() {
        let fingerprint = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6";
        assert!(validate_fingerprint(fingerprint).is_ok());
    }

    #[test]
    fn test_validate_fingerprint_mixed_case() {
        let fingerprint = "a1B2c3D4e5F6a7B8c9D0e1F2a3B4c5D6";
        assert!(validate_fingerprint(fingerprint).is_ok());
    }
}
