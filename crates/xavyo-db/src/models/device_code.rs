//! Device code entity model for RFC 8628 Device Authorization Grant.
//!
//! Represents a pending device authorization request where a CLI/headless client
//! requests authorization that will be completed by a user in a browser.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Type};
use uuid::Uuid;
use xavyo_core::{TenantId, UserId};

/// Default device code expiration time in seconds.
pub const DEVICE_CODE_EXPIRY_SECONDS: i64 = 600; // 10 minutes

/// Default polling interval in seconds.
pub const DEFAULT_POLLING_INTERVAL: i32 = 5;

/// Status of a device code request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Type, Serialize, Deserialize)]
#[sqlx(type_name = "device_code_status", rename_all = "lowercase")]
pub enum DeviceCodeStatus {
    /// Waiting for user to authorize in browser.
    #[default]
    Pending,
    /// User approved, ready for token exchange.
    Authorized,
    /// User denied the authorization request.
    Denied,
    /// Device code exceeded expires_at.
    Expired,
}

/// A device authorization request for the OAuth 2.0 Device Authorization Grant flow.
///
/// Device codes allow CLI/headless clients to authenticate users via a secondary
/// device (browser). The flow:
/// 1. Client requests device_code and user_code
/// 2. User visits verification_uri and enters user_code
/// 3. User authenticates and approves/denies
/// 4. Client polls for tokens using device_code
#[derive(Debug, Clone, FromRow)]
pub struct DeviceCode {
    /// Internal unique identifier.
    pub id: Uuid,

    /// Tenant owning this device code.
    pub tenant_id: Uuid,

    /// OAuth client requesting authorization.
    pub client_id: String,

    /// Secret code for CLI polling (32 bytes URL-safe base64).
    pub device_code: String,

    /// User-facing code for browser entry (8 chars, no ambiguous chars).
    pub user_code: String,

    /// Requested OAuth scopes.
    pub scopes: Vec<String>,

    /// Current status.
    pub status: DeviceCodeStatus,

    /// User who authorized (set on approval).
    pub user_id: Option<Uuid>,

    /// When this device code expires.
    pub expires_at: DateTime<Utc>,

    /// Minimum seconds between polling requests.
    pub interval_seconds: i32,

    /// Last time client polled for token.
    pub last_poll_at: Option<DateTime<Utc>>,

    /// When the device code was created.
    pub created_at: DateTime<Utc>,

    /// When user approved (if approved).
    pub authorized_at: Option<DateTime<Utc>>,

    // Storm-2372 remediation fields (F117)
    /// IP address from which the device code was requested.
    pub origin_ip: Option<String>,

    /// User-Agent header from the device code request.
    pub origin_user_agent: Option<String>,

    /// ISO 3166-1 alpha-2 country code of origin IP (XX if unknown).
    pub origin_country: Option<String>,
}

impl DeviceCode {
    /// Get the tenant ID as a typed `TenantId`.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }

    /// Get the user ID as a typed `UserId` (if authorized).
    #[must_use]
    pub fn user_id(&self) -> Option<UserId> {
        self.user_id.map(UserId::from_uuid)
    }

    /// Check if the device code has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if the device code is still pending.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status == DeviceCodeStatus::Pending && !self.is_expired()
    }

    /// Check if the device code has been authorized.
    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.status == DeviceCodeStatus::Authorized
    }

    /// Check if the device code has been denied.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.status == DeviceCodeStatus::Denied
    }

    /// Get the scopes as a space-separated string.
    #[must_use]
    pub fn scopes_string(&self) -> String {
        self.scopes.join(" ")
    }

    /// Check if polling is allowed (respects interval).
    #[must_use]
    pub fn can_poll(&self) -> bool {
        match self.last_poll_at {
            Some(last_poll) => {
                let next_allowed = last_poll + Duration::seconds(i64::from(self.interval_seconds));
                Utc::now() >= next_allowed
            }
            None => true,
        }
    }

    /// Create a new device code.
    pub async fn create(pool: &PgPool, new: &NewDeviceCode) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO device_codes (
                tenant_id, client_id, device_code, user_code, scopes,
                status, expires_at, interval_seconds,
                origin_ip, origin_user_agent, origin_country
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(new.tenant_id)
        .bind(&new.client_id)
        .bind(&new.device_code)
        .bind(&new.user_code)
        .bind(&new.scopes)
        .bind(DeviceCodeStatus::Pending)
        .bind(new.expires_at)
        .bind(new.interval_seconds)
        .bind(&new.origin_ip)
        .bind(&new.origin_user_agent)
        .bind(&new.origin_country)
        .fetch_one(pool)
        .await
    }

    /// Get the age of this device code in minutes.
    #[must_use]
    pub fn age_minutes(&self) -> i64 {
        let duration = Utc::now() - self.created_at;
        duration.num_minutes()
    }

    /// Check if this device code is older than the warning threshold (5 minutes).
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.age_minutes() >= 5
    }

    /// Find a device code by its device_code value.
    pub async fn find_by_device_code(
        pool: &PgPool,
        tenant_id: Uuid,
        device_code: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM device_codes
            WHERE tenant_id = $1 AND device_code = $2
            "#,
        )
        .bind(tenant_id)
        .bind(device_code)
        .fetch_optional(pool)
        .await
    }

    /// Find a device code by its user_code value.
    pub async fn find_by_user_code(
        pool: &PgPool,
        tenant_id: Uuid,
        user_code: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM device_codes
            WHERE tenant_id = $1 AND user_code = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_code)
        .fetch_optional(pool)
        .await
    }

    /// Find a pending device code by its user_code value.
    pub async fn find_pending_by_user_code(
        pool: &PgPool,
        tenant_id: Uuid,
        user_code: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM device_codes
            WHERE tenant_id = $1
              AND user_code = $2
              AND status = 'pending'
              AND expires_at > NOW()
            "#,
        )
        .bind(tenant_id)
        .bind(user_code)
        .fetch_optional(pool)
        .await
    }

    /// Update the status of a device code.
    pub async fn update_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: DeviceCodeStatus,
        user_id: Option<Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        let authorized_at = if status == DeviceCodeStatus::Authorized {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query_as::<_, Self>(
            r#"
            UPDATE device_codes
            SET status = $3, user_id = $4, authorized_at = $5
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(status)
        .bind(user_id)
        .bind(authorized_at)
        .fetch_optional(pool)
        .await
    }

    /// Update the last poll time for rate limiting.
    pub async fn update_last_poll(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE device_codes
            SET last_poll_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Mark a device code as expired.
    pub async fn mark_expired(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE device_codes
            SET status = 'expired'
            WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Delete a device code (after successful token exchange).
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM device_codes
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all expired device codes (for cleanup job).
    pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM device_codes
            WHERE expires_at < NOW()
            "#,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

/// Data for creating a new device code.
#[derive(Debug, Clone)]
pub struct NewDeviceCode {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub device_code: String,
    pub user_code: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub interval_seconds: i32,
    // Storm-2372 remediation fields (F117)
    pub origin_ip: Option<String>,
    pub origin_user_agent: Option<String>,
    pub origin_country: Option<String>,
}

impl NewDeviceCode {
    /// Create a new device code with default expiration and interval.
    #[must_use]
    pub fn new(
        tenant_id: Uuid,
        client_id: String,
        device_code: String,
        user_code: String,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            tenant_id,
            client_id,
            device_code,
            user_code,
            scopes,
            expires_at: Utc::now() + Duration::seconds(DEVICE_CODE_EXPIRY_SECONDS),
            interval_seconds: DEFAULT_POLLING_INTERVAL,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        }
    }

    /// Set a custom expiration time.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Set a custom polling interval.
    #[must_use]
    pub fn with_interval(mut self, interval_seconds: i32) -> Self {
        self.interval_seconds = interval_seconds;
        self
    }

    /// Set the origin IP address (Storm-2372 remediation).
    #[must_use]
    pub fn with_origin_ip(mut self, ip: Option<String>) -> Self {
        self.origin_ip = ip;
        self
    }

    /// Set the origin User-Agent (Storm-2372 remediation).
    #[must_use]
    pub fn with_origin_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.origin_user_agent = user_agent;
        self
    }

    /// Set the origin country code (Storm-2372 remediation).
    #[must_use]
    pub fn with_origin_country(mut self, country: Option<String>) -> Self {
        self.origin_country = country;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_code_status_default() {
        let status = DeviceCodeStatus::default();
        assert_eq!(status, DeviceCodeStatus::Pending);
    }

    #[test]
    fn test_device_code_is_pending() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            status: DeviceCodeStatus::Pending,
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(10),
            interval_seconds: 5,
            last_poll_at: None,
            created_at: Utc::now(),
            authorized_at: None,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert!(code.is_pending());
        assert!(!code.is_expired());
        assert!(!code.is_authorized());
        assert!(!code.is_denied());
    }

    #[test]
    fn test_device_code_is_expired() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string()],
            status: DeviceCodeStatus::Pending,
            user_id: None,
            expires_at: Utc::now() - Duration::minutes(1),
            interval_seconds: 5,
            last_poll_at: None,
            created_at: Utc::now() - Duration::minutes(11),
            authorized_at: None,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert!(code.is_expired());
        assert!(!code.is_pending()); // Expired codes are not pending
    }

    #[test]
    fn test_device_code_is_authorized() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string()],
            status: DeviceCodeStatus::Authorized,
            user_id: Some(Uuid::new_v4()),
            expires_at: Utc::now() + Duration::minutes(5),
            interval_seconds: 5,
            last_poll_at: None,
            created_at: Utc::now(),
            authorized_at: Some(Utc::now()),
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert!(code.is_authorized());
        assert!(!code.is_pending());
    }

    #[test]
    fn test_device_code_is_denied() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string()],
            status: DeviceCodeStatus::Denied,
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(5),
            interval_seconds: 5,
            last_poll_at: None,
            created_at: Utc::now(),
            authorized_at: None,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert!(code.is_denied());
        assert!(!code.is_pending());
    }

    #[test]
    fn test_scopes_string() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            status: DeviceCodeStatus::Pending,
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(10),
            interval_seconds: 5,
            last_poll_at: None,
            created_at: Utc::now(),
            authorized_at: None,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert_eq!(code.scopes_string(), "openid profile email");
    }

    #[test]
    fn test_can_poll_first_time() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string()],
            status: DeviceCodeStatus::Pending,
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(10),
            interval_seconds: 5,
            last_poll_at: None, // Never polled
            created_at: Utc::now(),
            authorized_at: None,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert!(code.can_poll());
    }

    #[test]
    fn test_can_poll_too_soon() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string()],
            status: DeviceCodeStatus::Pending,
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(10),
            interval_seconds: 5,
            last_poll_at: Some(Utc::now() - Duration::seconds(2)), // Polled 2 seconds ago
            created_at: Utc::now(),
            authorized_at: None,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert!(!code.can_poll()); // Too soon, need to wait 5 seconds
    }

    #[test]
    fn test_can_poll_after_interval() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string()],
            status: DeviceCodeStatus::Pending,
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(10),
            interval_seconds: 5,
            last_poll_at: Some(Utc::now() - Duration::seconds(6)), // Polled 6 seconds ago
            created_at: Utc::now(),
            authorized_at: None,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert!(code.can_poll()); // OK, more than 5 seconds
    }

    #[test]
    fn test_new_device_code_builder() {
        let tenant_id = Uuid::new_v4();
        let new_code = NewDeviceCode::new(
            tenant_id,
            "test-client".to_string(),
            "device-code-xyz".to_string(),
            "ABCD1234".to_string(),
            vec!["openid".to_string()],
        );

        assert_eq!(new_code.tenant_id, tenant_id);
        assert_eq!(new_code.client_id, "test-client");
        assert_eq!(new_code.interval_seconds, DEFAULT_POLLING_INTERVAL);
        assert!(new_code.expires_at > Utc::now());
    }

    #[test]
    fn test_new_device_code_with_custom_interval() {
        let new_code = NewDeviceCode::new(
            Uuid::new_v4(),
            "test-client".to_string(),
            "device-code-xyz".to_string(),
            "ABCD1234".to_string(),
            vec!["openid".to_string()],
        )
        .with_interval(10);

        assert_eq!(new_code.interval_seconds, 10);
    }

    // Storm-2372 remediation tests (F117)

    #[test]
    fn test_device_code_with_origin_context() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string()],
            status: DeviceCodeStatus::Pending,
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(10),
            interval_seconds: 5,
            last_poll_at: None,
            created_at: Utc::now(),
            authorized_at: None,
            origin_ip: Some("192.168.1.100".to_string()),
            origin_user_agent: Some("Mozilla/5.0".to_string()),
            origin_country: Some("US".to_string()),
        };

        assert_eq!(code.origin_ip, Some("192.168.1.100".to_string()));
        assert_eq!(code.origin_user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(code.origin_country, Some("US".to_string()));
    }

    #[test]
    fn test_device_code_age_minutes() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string()],
            status: DeviceCodeStatus::Pending,
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(10),
            interval_seconds: 5,
            last_poll_at: None,
            created_at: Utc::now() - Duration::minutes(3),
            authorized_at: None,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert!(code.age_minutes() >= 3);
        assert!(!code.is_stale()); // Less than 5 minutes
    }

    #[test]
    fn test_device_code_is_stale() {
        let code = DeviceCode {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            device_code: "test-device-code".to_string(),
            user_code: "ABCD1234".to_string(),
            scopes: vec!["openid".to_string()],
            status: DeviceCodeStatus::Pending,
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(5),
            interval_seconds: 5,
            last_poll_at: None,
            created_at: Utc::now() - Duration::minutes(6), // 6 minutes old
            authorized_at: None,
            origin_ip: None,
            origin_user_agent: None,
            origin_country: None,
        };

        assert!(code.is_stale()); // More than 5 minutes
    }

    #[test]
    fn test_new_device_code_with_origin_fields() {
        let new_code = NewDeviceCode::new(
            Uuid::new_v4(),
            "test-client".to_string(),
            "device-code-xyz".to_string(),
            "ABCD1234".to_string(),
            vec!["openid".to_string()],
        )
        .with_origin_ip(Some("10.0.0.1".to_string()))
        .with_origin_user_agent(Some("CLI/1.0".to_string()))
        .with_origin_country(Some("FR".to_string()));

        assert_eq!(new_code.origin_ip, Some("10.0.0.1".to_string()));
        assert_eq!(new_code.origin_user_agent, Some("CLI/1.0".to_string()));
        assert_eq!(new_code.origin_country, Some("FR".to_string()));
    }
}
