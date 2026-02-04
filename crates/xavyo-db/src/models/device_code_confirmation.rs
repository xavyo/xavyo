//! Device code confirmation model for Storm-2372 remediation.
//!
//! Represents an email confirmation required when a user attempts to approve
//! a device code from a suspicious IP address (different from origin).

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Default confirmation expiration time in minutes.
pub const CONFIRMATION_EXPIRY_MINUTES: i64 = 10;

/// Maximum number of resend attempts.
pub const MAX_RESEND_COUNT: i32 = 5;

/// Minimum seconds between resend attempts.
pub const RESEND_COOLDOWN_SECONDS: i64 = 60;

/// A device code confirmation record.
///
/// Created when a user attempts to approve a device code from an IP
/// that differs from the origin IP where the code was requested.
#[derive(Debug, Clone, FromRow)]
pub struct DeviceCodeConfirmation {
    /// Unique identifier for this confirmation.
    pub id: Uuid,

    /// Tenant owning this confirmation.
    pub tenant_id: Uuid,

    /// The device code being confirmed.
    pub device_code_id: Uuid,

    /// User who needs to confirm.
    pub user_id: Uuid,

    /// SHA-256 hash of the confirmation token.
    pub confirmation_token_hash: String,

    /// IP address from which confirmation was requested.
    pub requested_from_ip: Option<String>,

    /// When the confirmation was completed (None if pending).
    pub confirmed_at: Option<DateTime<Utc>>,

    /// When the last email was sent.
    pub last_sent_at: DateTime<Utc>,

    /// Number of times email was sent.
    pub send_count: i32,

    /// When this confirmation was created.
    pub created_at: DateTime<Utc>,

    /// When this confirmation expires.
    pub expires_at: DateTime<Utc>,
}

impl DeviceCodeConfirmation {
    /// Check if this confirmation has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if this confirmation is still pending (not confirmed, not expired).
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.confirmed_at.is_none() && !self.is_expired()
    }

    /// Check if this confirmation has been completed.
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }

    /// Check if resend is allowed (respects cooldown and max count).
    #[must_use]
    pub fn can_resend(&self) -> bool {
        if self.send_count >= MAX_RESEND_COUNT {
            return false;
        }

        let cooldown_elapsed = Utc::now() - self.last_sent_at;
        cooldown_elapsed.num_seconds() >= RESEND_COOLDOWN_SECONDS
    }

    /// Hash a confirmation token for storage.
    #[must_use]
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Create a new device code confirmation.
    pub async fn create(
        pool: &PgPool,
        new: &NewDeviceCodeConfirmation,
    ) -> Result<Self, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(new.tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO device_code_confirmations (
                tenant_id, device_code_id, user_id, confirmation_token_hash,
                requested_from_ip, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(new.tenant_id)
        .bind(new.device_code_id)
        .bind(new.user_id)
        .bind(&new.confirmation_token_hash)
        .bind(&new.requested_from_ip)
        .bind(new.expires_at)
        .fetch_one(&mut *conn)
        .await
    }

    /// Find a confirmation by its token hash.
    pub async fn find_by_token_hash(
        pool: &PgPool,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM device_code_confirmations
            WHERE tenant_id = $1 AND confirmation_token_hash = $2
            ",
        )
        .bind(tenant_id)
        .bind(token_hash)
        .fetch_optional(&mut *conn)
        .await
    }

    /// Find a pending confirmation for a device code.
    pub async fn find_pending_for_device_code(
        pool: &PgPool,
        tenant_id: Uuid,
        device_code_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        sqlx::query_as::<_, Self>(
            r"
            SELECT * FROM device_code_confirmations
            WHERE tenant_id = $1
              AND device_code_id = $2
              AND confirmed_at IS NULL
              AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(device_code_id)
        .fetch_optional(&mut *conn)
        .await
    }

    /// Mark a confirmation as confirmed.
    pub async fn confirm(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        sqlx::query_as::<_, Self>(
            r"
            UPDATE device_code_confirmations
            SET confirmed_at = NOW()
            WHERE tenant_id = $1 AND id = $2 AND confirmed_at IS NULL AND expires_at > NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
    }

    /// Increment send count and update `last_sent_at` (for resend).
    pub async fn record_resend(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        sqlx::query_as::<_, Self>(
            r"
            UPDATE device_code_confirmations
            SET send_count = send_count + 1, last_sent_at = NOW()
            WHERE tenant_id = $1 AND id = $2 AND send_count < $3
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(MAX_RESEND_COUNT)
        .fetch_optional(&mut *conn)
        .await
    }

    /// Delete a confirmation.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let result = sqlx::query(
            r"
            DELETE FROM device_code_confirmations
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *conn)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all expired confirmations (cleanup job).
    pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM device_code_confirmations
            WHERE expires_at < NOW()
            ",
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Cancel (delete) all pending confirmations for a device code (FR-012).
    ///
    /// Called before creating a new confirmation to invalidate any previous ones.
    pub async fn cancel_pending_for_device_code(
        pool: &PgPool,
        tenant_id: Uuid,
        device_code_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await?;

        let result = sqlx::query(
            r"
            DELETE FROM device_code_confirmations
            WHERE tenant_id = $1
              AND device_code_id = $2
              AND confirmed_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(device_code_id)
        .execute(&mut *conn)
        .await?;

        Ok(result.rows_affected())
    }
}

/// Data for creating a new device code confirmation.
#[derive(Debug, Clone)]
pub struct NewDeviceCodeConfirmation {
    pub tenant_id: Uuid,
    pub device_code_id: Uuid,
    pub user_id: Uuid,
    pub confirmation_token_hash: String,
    pub requested_from_ip: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl NewDeviceCodeConfirmation {
    /// Create a new confirmation with default expiration.
    #[must_use]
    pub fn new(
        tenant_id: Uuid,
        device_code_id: Uuid,
        user_id: Uuid,
        token: &str,
        requested_from_ip: Option<String>,
    ) -> Self {
        Self {
            tenant_id,
            device_code_id,
            user_id,
            confirmation_token_hash: DeviceCodeConfirmation::hash_token(token),
            requested_from_ip,
            expires_at: Utc::now() + Duration::minutes(CONFIRMATION_EXPIRY_MINUTES),
        }
    }

    /// Set a custom expiration time.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = expires_at;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token() {
        let token = "test-token-12345";
        let hash = DeviceCodeConfirmation::hash_token(token);

        // SHA-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);

        // Same input produces same hash
        let hash2 = DeviceCodeConfirmation::hash_token(token);
        assert_eq!(hash, hash2);

        // Different input produces different hash
        let hash3 = DeviceCodeConfirmation::hash_token("different-token");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_new_device_code_confirmation() {
        let tenant_id = Uuid::new_v4();
        let device_code_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let token = "confirmation-token";

        let new_confirmation = NewDeviceCodeConfirmation::new(
            tenant_id,
            device_code_id,
            user_id,
            token,
            Some("192.168.1.100".to_string()),
        );

        assert_eq!(new_confirmation.tenant_id, tenant_id);
        assert_eq!(new_confirmation.device_code_id, device_code_id);
        assert_eq!(new_confirmation.user_id, user_id);
        assert_eq!(
            new_confirmation.confirmation_token_hash,
            DeviceCodeConfirmation::hash_token(token)
        );
        assert_eq!(
            new_confirmation.requested_from_ip,
            Some("192.168.1.100".to_string())
        );
        assert!(new_confirmation.expires_at > Utc::now());
    }

    #[test]
    fn test_confirmation_is_expired() {
        let confirmation = DeviceCodeConfirmation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            device_code_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            confirmation_token_hash: "hash".to_string(),
            requested_from_ip: None,
            confirmed_at: None,
            last_sent_at: Utc::now(),
            send_count: 1,
            created_at: Utc::now() - Duration::minutes(15),
            expires_at: Utc::now() - Duration::minutes(5), // Expired 5 minutes ago
        };

        assert!(confirmation.is_expired());
        assert!(!confirmation.is_pending());
    }

    #[test]
    fn test_confirmation_is_pending() {
        let confirmation = DeviceCodeConfirmation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            device_code_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            confirmation_token_hash: "hash".to_string(),
            requested_from_ip: None,
            confirmed_at: None,
            last_sent_at: Utc::now(),
            send_count: 1,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5), // Expires in 5 minutes
        };

        assert!(confirmation.is_pending());
        assert!(!confirmation.is_expired());
        assert!(!confirmation.is_confirmed());
    }

    #[test]
    fn test_confirmation_is_confirmed() {
        let confirmation = DeviceCodeConfirmation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            device_code_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            confirmation_token_hash: "hash".to_string(),
            requested_from_ip: None,
            confirmed_at: Some(Utc::now()),
            last_sent_at: Utc::now(),
            send_count: 1,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };

        assert!(confirmation.is_confirmed());
        assert!(!confirmation.is_pending());
    }

    #[test]
    fn test_can_resend_within_cooldown() {
        let confirmation = DeviceCodeConfirmation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            device_code_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            confirmation_token_hash: "hash".to_string(),
            requested_from_ip: None,
            confirmed_at: None,
            last_sent_at: Utc::now() - Duration::seconds(30), // 30 seconds ago
            send_count: 1,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };

        // Cooldown is 60 seconds, only 30 have passed
        assert!(!confirmation.can_resend());
    }

    #[test]
    fn test_can_resend_after_cooldown() {
        let confirmation = DeviceCodeConfirmation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            device_code_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            confirmation_token_hash: "hash".to_string(),
            requested_from_ip: None,
            confirmed_at: None,
            last_sent_at: Utc::now() - Duration::seconds(90), // 90 seconds ago
            send_count: 1,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };

        // Cooldown is 60 seconds, 90 have passed
        assert!(confirmation.can_resend());
    }

    #[test]
    fn test_cannot_resend_max_reached() {
        let confirmation = DeviceCodeConfirmation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            device_code_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            confirmation_token_hash: "hash".to_string(),
            requested_from_ip: None,
            confirmed_at: None,
            last_sent_at: Utc::now() - Duration::minutes(5), // Long ago
            send_count: MAX_RESEND_COUNT,                    // Max reached
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };

        assert!(!confirmation.can_resend());
    }
}
