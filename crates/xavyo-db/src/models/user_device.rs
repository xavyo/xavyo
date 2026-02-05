//! User device model for device tracking and trust management.
//!
//! Tracks known devices per user for new device detection and trusted device MFA bypass.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::fmt;
use uuid::Uuid;

/// Device type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    /// Desktop computer (Windows, macOS, Linux).
    Desktop,
    /// Mobile phone (iOS, Android).
    Mobile,
    /// Tablet device (iPad, Android tablet).
    Tablet,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceType::Desktop => write!(f, "desktop"),
            DeviceType::Mobile => write!(f, "mobile"),
            DeviceType::Tablet => write!(f, "tablet"),
        }
    }
}

impl std::str::FromStr for DeviceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "desktop" => Ok(DeviceType::Desktop),
            "mobile" => Ok(DeviceType::Mobile),
            "tablet" => Ok(DeviceType::Tablet),
            _ => Err(format!("Unknown device type: {s}")),
        }
    }
}

/// A known device for a user with trust management.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserDevice {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant for RLS isolation.
    pub tenant_id: Uuid,

    /// The user who owns this device.
    pub user_id: Uuid,

    /// SHA-256 hash of client device fingerprint.
    pub device_fingerprint: String,

    /// Optional user-provided device name.
    pub device_name: Option<String>,

    /// Device type (desktop, mobile, tablet).
    pub device_type: Option<String>,

    /// Browser name from User-Agent.
    pub browser: Option<String>,

    /// Browser version from User-Agent.
    pub browser_version: Option<String>,

    /// Operating system from User-Agent.
    pub os: Option<String>,

    /// OS version from User-Agent.
    pub os_version: Option<String>,

    /// Whether the device is trusted for MFA bypass.
    pub is_trusted: bool,

    /// When trust expires (NULL = permanent).
    pub trust_expires_at: Option<DateTime<Utc>>,

    /// Last IP address used from this device.
    pub last_ip_address: Option<String>,

    /// Last geo country code (ISO 3166-1 alpha-2).
    pub last_geo_country: Option<String>,

    /// Last geo city name.
    pub last_geo_city: Option<String>,

    /// When the device was first seen.
    pub first_seen_at: DateTime<Utc>,

    /// When the device was last seen.
    pub last_seen_at: DateTime<Utc>,

    /// Number of logins from this device.
    pub login_count: i32,

    /// When the device was revoked (soft delete).
    pub revoked_at: Option<DateTime<Utc>>,
}

impl UserDevice {
    /// Check if the device trust is currently valid.
    #[must_use]
    pub fn is_trust_valid(&self) -> bool {
        if !self.is_trusted {
            return false;
        }
        if self.revoked_at.is_some() {
            return false;
        }
        match self.trust_expires_at {
            Some(expires_at) => expires_at > Utc::now(),
            None => true, // NULL = permanent trust
        }
    }

    /// Check if a device exists for a user (excluding revoked).
    pub async fn exists<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        device_fingerprint: &str,
    ) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (bool,) = sqlx::query_as(
            r"
            SELECT EXISTS(
                SELECT 1 FROM user_devices
                WHERE tenant_id = $1 AND user_id = $2 AND device_fingerprint = $3
                AND revoked_at IS NULL
            )
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_fingerprint)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Get a device by fingerprint (excluding revoked).
    pub async fn get_by_fingerprint<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        device_fingerprint: &str,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM user_devices
            WHERE tenant_id = $1 AND user_id = $2 AND device_fingerprint = $3
            AND revoked_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_fingerprint)
        .fetch_optional(executor)
        .await
    }

    /// Get a device by ID (excluding revoked).
    pub async fn get_by_id<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM user_devices
            WHERE tenant_id = $1 AND id = $2
            AND revoked_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// Get a device by ID for a specific user (excluding revoked).
    pub async fn get_by_id_and_user<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM user_devices
            WHERE tenant_id = $1 AND id = $2 AND user_id = $3
            AND revoked_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .fetch_optional(executor)
        .await
    }

    /// Upsert a device (create or update `last_seen` and `login_count`).
    ///
    /// Returns (device, `is_new`) where `is_new` indicates if this was a new device.
    pub async fn upsert<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        device_fingerprint: &str,
    ) -> Result<(Self, bool), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        // Try to update existing device first
        let existing: Option<Self> = sqlx::query_as(
            r"
            UPDATE user_devices
            SET last_seen_at = NOW(), login_count = login_count + 1
            WHERE tenant_id = $1 AND user_id = $2 AND device_fingerprint = $3
            AND revoked_at IS NULL
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_fingerprint)
        .fetch_optional(executor)
        .await?;

        if let Some(device) = existing {
            return Ok((device, false));
        }

        // Device doesn't exist, need to insert
        // Note: This requires a new executor since the previous one was consumed
        // In practice, this should be called within a transaction
        Err(sqlx::Error::RowNotFound) // Signal that insert is needed
    }

    /// Create a new device record.
    pub async fn create<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        device_fingerprint: &str,
    ) -> Result<Self, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            INSERT INTO user_devices (tenant_id, user_id, device_fingerprint)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, user_id, device_fingerprint)
            DO UPDATE SET last_seen_at = NOW(), login_count = user_devices.login_count + 1
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_fingerprint)
        .fetch_one(executor)
        .await
    }

    /// Record a device login (upsert with ON CONFLICT).
    ///
    /// Returns (device, `is_new`) where `is_new` indicates if this was a new device.
    pub async fn record_login<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        device_fingerprint: &str,
    ) -> Result<(Self, bool), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        // Use INSERT with ON CONFLICT and check if it was an insert or update
        let device: Self = sqlx::query_as(
            r"
            INSERT INTO user_devices (tenant_id, user_id, device_fingerprint)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, user_id, device_fingerprint)
            DO UPDATE SET last_seen_at = NOW(), login_count = user_devices.login_count + 1
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_fingerprint)
        .fetch_one(executor)
        .await?;

        // Check if it's a new device (login_count = 1)
        let is_new = device.login_count == 1;
        Ok((device, is_new))
    }

    /// Get all active (non-revoked) devices for a user.
    pub async fn get_user_devices<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM user_devices
            WHERE tenant_id = $1 AND user_id = $2
            AND revoked_at IS NULL
            ORDER BY last_seen_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(executor)
        .await
    }

    /// Get all devices for a user (including revoked, for admin queries).
    pub async fn get_user_devices_all<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        include_revoked: bool,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        if include_revoked {
            sqlx::query_as(
                r"
                SELECT * FROM user_devices
                WHERE tenant_id = $1 AND user_id = $2
                ORDER BY last_seen_at DESC
                ",
            )
            .bind(tenant_id)
            .bind(user_id)
            .fetch_all(executor)
            .await
        } else {
            Self::get_user_devices(executor, tenant_id, user_id).await
        }
    }

    /// Count active devices for a user.
    pub async fn count_user_devices<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM user_devices
            WHERE tenant_id = $1 AND user_id = $2
            AND revoked_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Update device name.
    pub async fn update_name<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        user_id: Uuid,
        device_name: Option<&str>,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            UPDATE user_devices
            SET device_name = $4
            WHERE tenant_id = $1 AND id = $2 AND user_id = $3
            AND revoked_at IS NULL
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .bind(device_name)
        .fetch_optional(executor)
        .await
    }

    /// Update device info (type, browser, OS, IP, geo).
    #[allow(clippy::too_many_arguments)]
    pub async fn update_device_info<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        device_type: Option<&str>,
        browser: Option<&str>,
        browser_version: Option<&str>,
        os: Option<&str>,
        os_version: Option<&str>,
        ip_address: Option<&str>,
        geo_country: Option<&str>,
        geo_city: Option<&str>,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            UPDATE user_devices
            SET device_type = COALESCE($3, device_type),
                browser = COALESCE($4, browser),
                browser_version = COALESCE($5, browser_version),
                os = COALESCE($6, os),
                os_version = COALESCE($7, os_version),
                last_ip_address = COALESCE($8, last_ip_address),
                last_geo_country = COALESCE($9, last_geo_country),
                last_geo_city = COALESCE($10, last_geo_city),
                last_seen_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            AND revoked_at IS NULL
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(device_type)
        .bind(browser)
        .bind(browser_version)
        .bind(os)
        .bind(os_version)
        .bind(ip_address)
        .bind(geo_country)
        .bind(geo_city)
        .fetch_optional(executor)
        .await
    }

    /// Mark a device as trusted.
    pub async fn trust<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        user_id: Uuid,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            UPDATE user_devices
            SET is_trusted = TRUE, trust_expires_at = $4
            WHERE tenant_id = $1 AND id = $2 AND user_id = $3
            AND revoked_at IS NULL
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .bind(expires_at)
        .fetch_optional(executor)
        .await
    }

    /// Remove trust from a device.
    pub async fn untrust<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            UPDATE user_devices
            SET is_trusted = FALSE, trust_expires_at = NULL
            WHERE tenant_id = $1 AND id = $2 AND user_id = $3
            AND revoked_at IS NULL
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .fetch_optional(executor)
        .await
    }

    /// Revoke (soft-delete) a device.
    pub async fn revoke<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r"
            UPDATE user_devices
            SET revoked_at = NOW(), is_trusted = FALSE, trust_expires_at = NULL
            WHERE tenant_id = $1 AND id = $2 AND user_id = $3
            AND revoked_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke (soft-delete) a device (admin, no `user_id` check).
    pub async fn revoke_admin<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r"
            UPDATE user_devices
            SET revoked_at = NOW(), is_trusted = FALSE, trust_expires_at = NULL
            WHERE tenant_id = $1 AND id = $2
            AND revoked_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(executor)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a device (hard delete, use revoke for soft delete).
    pub async fn delete<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            r"
            DELETE FROM user_devices
            WHERE tenant_id = $1 AND id = $2 AND user_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get a trusted device by fingerprint for MFA bypass check.
    pub async fn get_trusted_device<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
        device_fingerprint: &str,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM user_devices
            WHERE tenant_id = $1 AND user_id = $2 AND device_fingerprint = $3
            AND is_trusted = TRUE
            AND revoked_at IS NULL
            AND (trust_expires_at IS NULL OR trust_expires_at > NOW())
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_fingerprint)
        .fetch_optional(executor)
        .await
    }
}
