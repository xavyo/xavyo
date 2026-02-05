//! Request and response models for device management API (F026).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// ============================================================================
// Request Models
// ============================================================================

/// Request to rename a device.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RenameDeviceRequest {
    /// New device name (max 100 characters).
    pub device_name: String,
}

/// Request to trust a device.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct TrustDeviceRequest {
    /// Optional trust duration in days (uses tenant default if not specified).
    /// Set to 0 for permanent trust.
    #[serde(default)]
    pub trust_duration_days: Option<i32>,
}

/// Query parameters for admin listing user devices.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct AdminListDevicesQuery {
    /// Include revoked devices in the list.
    #[serde(default)]
    pub include_revoked: bool,
}

/// Request to update device policy.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateDevicePolicyRequest {
    /// Allow trusted devices to bypass MFA.
    #[serde(default)]
    pub allow_trusted_device_mfa_bypass: Option<bool>,

    /// Default trust duration in days (0 = permanent).
    #[serde(default)]
    pub trusted_device_duration_days: Option<i32>,
}

// ============================================================================
// Response Models
// ============================================================================

/// Device information response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeviceResponse {
    /// Device ID.
    pub id: Uuid,

    /// Device fingerprint (first 8 chars for display).
    pub device_fingerprint: String,

    /// User-defined device name.
    pub device_name: Option<String>,

    /// Device type (desktop, mobile, tablet).
    pub device_type: Option<String>,

    /// Browser name.
    pub browser: Option<String>,

    /// Browser version.
    pub browser_version: Option<String>,

    /// Operating system.
    pub os: Option<String>,

    /// OS version.
    pub os_version: Option<String>,

    /// Whether device is trusted.
    pub is_trusted: bool,

    /// Trust expiration timestamp.
    pub trust_expires_at: Option<DateTime<Utc>>,

    /// When device was first seen.
    pub first_seen_at: DateTime<Utc>,

    /// When device was last seen.
    pub last_seen_at: DateTime<Utc>,

    /// Number of logins from this device.
    pub login_count: i32,

    /// Last IP address (only for admin view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ip_address: Option<String>,

    /// Last geo country (only for admin view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_geo_country: Option<String>,

    /// Last geo city (only for admin view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_geo_city: Option<String>,

    /// Whether this is the current device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_current: Option<bool>,

    /// Revocation timestamp (only in admin view with `include_revoked`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// List of devices response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeviceListResponse {
    /// List of devices.
    pub items: Vec<DeviceResponse>,

    /// Total count of devices.
    pub total: i64,
}

/// Trust operation result.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TrustDeviceResponse {
    /// Device ID.
    pub id: Uuid,

    /// Whether device is trusted.
    pub is_trusted: bool,

    /// Trust expiration timestamp.
    pub trust_expires_at: Option<DateTime<Utc>>,
}

/// Rename operation result.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RenameDeviceResponse {
    /// Device ID.
    pub id: Uuid,

    /// New device name.
    pub device_name: String,
}

/// Device policy response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DevicePolicyResponse {
    /// Allow trusted devices to bypass MFA.
    pub allow_trusted_device_mfa_bypass: bool,

    /// Default trust duration in days (0 = permanent).
    pub trusted_device_duration_days: i32,
}

impl Default for DevicePolicyResponse {
    fn default() -> Self {
        Self {
            allow_trusted_device_mfa_bypass: false,
            trusted_device_duration_days: 30,
        }
    }
}

// ============================================================================
// Conversion Implementations
// ============================================================================

impl DeviceResponse {
    /// Create a device response from a `UserDevice`.
    /// Use `with_admin_details` for admin responses.
    #[must_use]
    pub fn from_user_device(device: xavyo_db::UserDevice, is_current: bool) -> Self {
        Self {
            id: device.id,
            // Show truncated fingerprint for security
            device_fingerprint: device.device_fingerprint[..8.min(device.device_fingerprint.len())]
                .to_string(),
            device_name: device.device_name,
            device_type: device.device_type,
            browser: device.browser,
            browser_version: device.browser_version,
            os: device.os,
            os_version: device.os_version,
            is_trusted: device.is_trusted,
            trust_expires_at: device.trust_expires_at,
            first_seen_at: device.first_seen_at,
            last_seen_at: device.last_seen_at,
            login_count: device.login_count,
            last_ip_address: None,
            last_geo_country: None,
            last_geo_city: None,
            is_current: if is_current { Some(true) } else { None },
            revoked_at: None,
        }
    }

    /// Create a device response with admin details (includes IP, geo, and `revoked_at`).
    #[must_use]
    pub fn from_user_device_admin(device: xavyo_db::UserDevice, include_revoked: bool) -> Self {
        Self {
            id: device.id,
            device_fingerprint: device.device_fingerprint[..8.min(device.device_fingerprint.len())]
                .to_string(),
            device_name: device.device_name,
            device_type: device.device_type,
            browser: device.browser,
            browser_version: device.browser_version,
            os: device.os,
            os_version: device.os_version,
            is_trusted: device.is_trusted,
            trust_expires_at: device.trust_expires_at,
            first_seen_at: device.first_seen_at,
            last_seen_at: device.last_seen_at,
            login_count: device.login_count,
            last_ip_address: device.last_ip_address,
            last_geo_country: device.last_geo_country,
            last_geo_city: device.last_geo_city,
            is_current: None,
            revoked_at: if include_revoked {
                device.revoked_at
            } else {
                None
            },
        }
    }
}
