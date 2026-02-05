//! Device code service for RFC 8628 Device Authorization Grant.
//!
//! Handles the business logic for device code flow:
//! - Creating device authorization requests
//! - Validating and approving/denying user codes
//! - Checking authorization status for polling
//! - Token exchange after approval

use crate::error::OAuthError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::{DeviceCode, DeviceCodeStatus, NewDeviceCode};

/// Character set for user codes (excludes ambiguous characters: 0, O, 1, I, L).
const USER_CODE_CHARSET: &[u8] = b"BCDFGHJKMNPQRSTVWXYZ23456789";

/// Length of user codes (8 characters).
const USER_CODE_LENGTH: usize = 8;

/// Length of device codes in bytes (32 bytes = 256 bits of entropy).
const DEVICE_CODE_LENGTH: usize = 32;

/// Default device code expiration in seconds (10 minutes).
const DEFAULT_EXPIRY_SECONDS: i64 = 600;

/// Default polling interval in seconds.
const DEFAULT_INTERVAL: i32 = 5;

/// Slow down increment in seconds (added when polling too fast).
const SLOW_DOWN_INCREMENT: i32 = 5;

/// Result of checking device authorization status.
#[derive(Debug, Clone)]
pub enum DeviceAuthorizationStatus {
    /// User hasn't completed authorization yet.
    Pending,
    /// User approved, ready for token exchange. Contains `user_id`.
    Authorized(Uuid),
    /// User denied the authorization request.
    Denied,
    /// Device code has expired.
    Expired,
    /// Client is polling too fast.
    SlowDown {
        /// Updated interval to use.
        interval: i32,
    },
}

/// Service for handling RFC 8628 device code flow.
#[derive(Debug, Clone)]
pub struct DeviceCodeService {
    pool: PgPool,
}

impl DeviceCodeService {
    /// Create a new device code service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Generate a cryptographically secure device code (32 bytes URL-safe base64).
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
    fn generate_device_code() -> String {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut bytes = [0u8; DEVICE_CODE_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate a user-friendly user code (8 chars, no ambiguous characters).
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
    fn generate_user_code() -> String {
        use rand::rngs::OsRng;
        let code: String = (0..USER_CODE_LENGTH)
            .map(|_| {
                let idx = OsRng.gen_range(0..USER_CODE_CHARSET.len());
                USER_CODE_CHARSET[idx] as char
            })
            .collect();

        // Format as XXXX-XXXX for readability
        format!("{}-{}", &code[..4], &code[4..])
    }

    /// Normalize a user code (uppercase, remove dashes/spaces).
    fn normalize_user_code(code: &str) -> String {
        code.to_uppercase()
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect()
    }

    /// Create a new device authorization request.
    ///
    /// Returns the device code, user code, verification URI, and expiration info.
    ///
    /// # Storm-2372 Remediation (F117)
    /// Now accepts origin context (IP, user agent, country) to enable phishing detection
    /// on the approval page.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_device_authorization(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        scopes: Vec<String>,
        verification_uri: &str,
        origin_ip: Option<String>,
        origin_user_agent: Option<String>,
        origin_country: Option<String>,
    ) -> Result<DeviceAuthorizationResponse, OAuthError> {
        let device_code = Self::generate_device_code();
        let user_code_raw = Self::generate_user_code();
        let user_code_normalized = Self::normalize_user_code(&user_code_raw);

        let expires_at = Utc::now() + Duration::seconds(DEFAULT_EXPIRY_SECONDS);

        let new_device_code = NewDeviceCode {
            tenant_id,
            client_id: client_id.to_string(),
            device_code: device_code.clone(),
            user_code: user_code_normalized.clone(),
            scopes: scopes.clone(),
            expires_at,
            interval_seconds: DEFAULT_INTERVAL,
            origin_ip: origin_ip.clone(),
            origin_user_agent: origin_user_agent.clone(),
            origin_country: origin_country.clone(),
        };

        // Create the device code record
        DeviceCode::create(&self.pool, &new_device_code)
            .await
            .map_err(|e| {
                // Check for unique constraint violation (collision on user_code)
                if let Some(db_err) = e.as_database_error() {
                    if db_err.is_unique_violation() {
                        tracing::warn!("User code collision, retrying");
                        return OAuthError::Internal(
                            "Failed to generate unique code, please retry".to_string(),
                        );
                    }
                }
                tracing::error!("Failed to create device code: {}", e);
                OAuthError::Internal("Failed to create device authorization".to_string())
            })?;

        // Build verification_uri_complete with the user code
        let verification_uri_complete = format!("{verification_uri}?code={user_code_raw}");

        tracing::info!(
            "Device code created: client_id={}, origin_ip={:?}, origin_country={:?}",
            client_id,
            origin_ip,
            origin_country
        );

        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code: user_code_raw,
            verification_uri: verification_uri.to_string(),
            verification_uri_complete,
            expires_in: DEFAULT_EXPIRY_SECONDS,
            interval: DEFAULT_INTERVAL,
        })
    }

    /// Find a pending device code by user code (for verification page).
    pub async fn find_pending_by_user_code(
        &self,
        tenant_id: Uuid,
        user_code: &str,
    ) -> Result<Option<DeviceCodeInfo>, OAuthError> {
        let normalized = Self::normalize_user_code(user_code);

        let device_code = DeviceCode::find_pending_by_user_code(&self.pool, tenant_id, &normalized)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find device code: {}", e);
                OAuthError::Internal("Database error".to_string())
            })?;

        Ok(device_code.map(|dc| DeviceCodeInfo {
            id: dc.id,
            client_id: dc.client_id,
            scopes: dc.scopes,
            expires_at: dc.expires_at.to_rfc3339(),
            // Storm-2372 remediation fields (F117)
            origin_ip: dc.origin_ip,
            origin_user_agent: dc.origin_user_agent,
            origin_country: dc.origin_country,
            created_at: dc.created_at,
        }))
    }

    /// Authorize a device code (user approved).
    pub async fn authorize(
        &self,
        tenant_id: Uuid,
        user_code: &str,
        user_id: Uuid,
    ) -> Result<(), OAuthError> {
        let normalized = Self::normalize_user_code(user_code);

        // Find the pending device code
        let device_code = DeviceCode::find_pending_by_user_code(&self.pool, tenant_id, &normalized)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find device code: {}", e);
                OAuthError::Internal("Database error".to_string())
            })?
            .ok_or_else(|| {
                OAuthError::InvalidGrant("Device code not found or expired".to_string())
            })?;

        // Update status to authorized
        DeviceCode::update_status(
            &self.pool,
            tenant_id,
            device_code.id,
            DeviceCodeStatus::Authorized,
            Some(user_id),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to authorize device code: {}", e);
            OAuthError::Internal("Failed to authorize device code".to_string())
        })?;

        tracing::info!(
            "Device code authorized: id={}, user_id={}",
            device_code.id,
            user_id
        );

        Ok(())
    }

    /// Deny a device code (user rejected).
    pub async fn deny(&self, tenant_id: Uuid, user_code: &str) -> Result<(), OAuthError> {
        let normalized = Self::normalize_user_code(user_code);

        // Find the pending device code
        let device_code = DeviceCode::find_pending_by_user_code(&self.pool, tenant_id, &normalized)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find device code: {}", e);
                OAuthError::Internal("Database error".to_string())
            })?
            .ok_or_else(|| {
                OAuthError::InvalidGrant("Device code not found or expired".to_string())
            })?;

        // Update status to denied
        DeviceCode::update_status(
            &self.pool,
            tenant_id,
            device_code.id,
            DeviceCodeStatus::Denied,
            None,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to deny device code: {}", e);
            OAuthError::Internal("Failed to deny device code".to_string())
        })?;

        tracing::info!("Device code denied: id={}", device_code.id);

        Ok(())
    }

    /// Check the authorization status of a device code (for polling).
    ///
    /// This also enforces rate limiting by checking the polling interval.
    pub async fn check_authorization(
        &self,
        tenant_id: Uuid,
        device_code: &str,
        client_id: &str,
    ) -> Result<DeviceAuthorizationStatus, OAuthError> {
        // Find the device code
        let record = DeviceCode::find_by_device_code(&self.pool, tenant_id, device_code)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find device code: {}", e);
                OAuthError::Internal("Database error".to_string())
            })?
            .ok_or_else(|| OAuthError::InvalidGrant("Invalid device code".to_string()))?;

        // Validate client_id matches
        if record.client_id != client_id {
            return Err(OAuthError::InvalidGrant("Client ID mismatch".to_string()));
        }

        // Check expiration first
        if record.is_expired() {
            // Mark as expired if still pending
            if record.status == DeviceCodeStatus::Pending {
                let _ = DeviceCode::mark_expired(&self.pool, tenant_id, record.id).await;
            }
            return Ok(DeviceAuthorizationStatus::Expired);
        }

        // Check rate limiting
        if !record.can_poll() {
            // Update interval with slow_down increment
            let new_interval = record.interval_seconds + SLOW_DOWN_INCREMENT;
            return Ok(DeviceAuthorizationStatus::SlowDown {
                interval: new_interval,
            });
        }

        // Update last poll time
        let _ = DeviceCode::update_last_poll(&self.pool, tenant_id, record.id).await;

        // Return status
        match record.status {
            DeviceCodeStatus::Pending => Ok(DeviceAuthorizationStatus::Pending),
            DeviceCodeStatus::Authorized => {
                let user_id = record.user_id.ok_or_else(|| {
                    OAuthError::Internal("Authorized device code missing user_id".to_string())
                })?;
                Ok(DeviceAuthorizationStatus::Authorized(user_id))
            }
            DeviceCodeStatus::Denied => Ok(DeviceAuthorizationStatus::Denied),
            DeviceCodeStatus::Expired => Ok(DeviceAuthorizationStatus::Expired),
        }
    }

    /// Exchange a device code for tokens (after authorization).
    ///
    /// This consumes the device code (one-time use) and returns the `user_id`
    /// and scopes for token generation.
    pub async fn exchange_for_tokens(
        &self,
        tenant_id: Uuid,
        device_code: &str,
        client_id: &str,
    ) -> Result<DeviceTokenExchangeResult, OAuthError> {
        // Find the device code
        let record = DeviceCode::find_by_device_code(&self.pool, tenant_id, device_code)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find device code: {}", e);
                OAuthError::Internal("Database error".to_string())
            })?
            .ok_or_else(|| OAuthError::InvalidGrant("Invalid device code".to_string()))?;

        // Validate client_id matches
        if record.client_id != client_id {
            return Err(OAuthError::InvalidGrant("Client ID mismatch".to_string()));
        }

        // Must be authorized
        if record.status != DeviceCodeStatus::Authorized {
            return Err(OAuthError::InvalidGrant(
                "Device code is not authorized".to_string(),
            ));
        }

        let user_id = record.user_id.ok_or_else(|| {
            OAuthError::Internal("Authorized device code missing user_id".to_string())
        })?;

        // Delete the device code (one-time use)
        DeviceCode::delete(&self.pool, tenant_id, record.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete device code: {}", e);
                OAuthError::Internal("Failed to complete token exchange".to_string())
            })?;

        tracing::info!(
            "Device code exchanged for tokens: id={}, user_id={}",
            record.id,
            user_id
        );

        Ok(DeviceTokenExchangeResult {
            user_id,
            scope: record.scopes_string(),
        })
    }

    /// Mark a device code as expired.
    pub async fn mark_expired(&self, tenant_id: Uuid, device_code: &str) -> Result<(), OAuthError> {
        let record = DeviceCode::find_by_device_code(&self.pool, tenant_id, device_code)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find device code: {}", e);
                OAuthError::Internal("Database error".to_string())
            })?;

        if let Some(record) = record {
            DeviceCode::mark_expired(&self.pool, tenant_id, record.id)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to mark device code expired: {}", e);
                    OAuthError::Internal("Database error".to_string())
                })?;
        }

        Ok(())
    }

    /// Cleanup expired device codes (for background job).
    pub async fn cleanup_expired(&self) -> Result<u64, OAuthError> {
        DeviceCode::cleanup_expired(&self.pool).await.map_err(|e| {
            tracing::error!("Failed to cleanup expired device codes: {}", e);
            OAuthError::Internal("Database error".to_string())
        })
    }

    /// Storm-2372 Remediation (F117): Get client name from `oauth_clients` table.
    ///
    /// Returns the human-readable client name if found, or None if the client
    /// doesn't exist or has no name set. This is used to display a meaningful
    /// application name on the device code approval page.
    pub async fn get_client_name(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<Option<String>, OAuthError> {
        // Acquire a connection for RLS context
        let mut conn = self.pool.acquire().await.map_err(|e| {
            tracing::error!("Failed to acquire connection: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?;

        // Set tenant context for RLS
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                OAuthError::Internal("Database error".to_string())
            })?;

        // Query just the name field
        let result: Option<(String,)> = sqlx::query_as(
            r"
            SELECT name FROM oauth_clients
            WHERE client_id = $1 AND tenant_id = $2 AND is_active = true
            ",
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch client name: {}", e);
            OAuthError::Internal("Database error".to_string())
        })?;

        Ok(result.map(|(name,)| name))
    }
}

/// Response from creating a device authorization request.
#[derive(Debug, Clone)]
pub struct DeviceAuthorizationResponse {
    /// Secret code for CLI polling.
    pub device_code: String,
    /// User-facing code for browser entry (formatted with dash).
    pub user_code: String,
    /// URL where user should visit.
    pub verification_uri: String,
    /// URL with code pre-filled.
    pub verification_uri_complete: String,
    /// Seconds until `device_code` expires.
    pub expires_in: i64,
    /// Minimum seconds between polling requests.
    pub interval: i32,
}

/// Information about a device code (for verification page).
#[derive(Debug, Clone)]
pub struct DeviceCodeInfo {
    /// Internal ID.
    pub id: Uuid,
    /// OAuth client requesting authorization.
    pub client_id: String,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Expiration time as ISO 8601 string.
    pub expires_at: String,
    // Storm-2372 remediation fields (F117)
    /// IP address from which the device code was requested.
    pub origin_ip: Option<String>,
    /// User-Agent header from the device code request.
    pub origin_user_agent: Option<String>,
    /// Country code of the origin IP.
    pub origin_country: Option<String>,
    /// When the device code was created.
    pub created_at: chrono::DateTime<Utc>,
}

/// Result of exchanging a device code for tokens.
#[derive(Debug, Clone)]
pub struct DeviceTokenExchangeResult {
    /// User who authorized.
    pub user_id: Uuid,
    /// Granted scopes (space-separated).
    pub scope: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_device_code_length() {
        let code = DeviceCodeService::generate_device_code();
        // 32 bytes base64url encoded = 43 characters
        assert_eq!(code.len(), 43);
    }

    #[test]
    fn test_generate_device_code_unique() {
        let code1 = DeviceCodeService::generate_device_code();
        let code2 = DeviceCodeService::generate_device_code();
        assert_ne!(code1, code2);
    }

    #[test]
    fn test_generate_user_code_format() {
        let code = DeviceCodeService::generate_user_code();
        // Format: XXXX-XXXX (9 characters with dash)
        assert_eq!(code.len(), 9);
        assert_eq!(&code[4..5], "-");
    }

    #[test]
    fn test_generate_user_code_charset() {
        let code = DeviceCodeService::generate_user_code();
        // Remove dash and check all chars are valid
        let normalized = code.replace('-', "");
        for c in normalized.chars() {
            assert!(USER_CODE_CHARSET.contains(&(c as u8)));
        }
    }

    #[test]
    fn test_generate_user_code_no_ambiguous_chars() {
        // Generate many codes and verify no ambiguous chars
        for _ in 0..100 {
            let code = DeviceCodeService::generate_user_code();
            let normalized = code.replace('-', "");
            assert!(!normalized.contains('0')); // No zero
            assert!(!normalized.contains('O')); // No letter O
            assert!(!normalized.contains('1')); // No one
            assert!(!normalized.contains('I')); // No letter I
            assert!(!normalized.contains('L')); // No letter L
        }
    }

    #[test]
    fn test_normalize_user_code() {
        // Test various input formats
        assert_eq!(
            DeviceCodeService::normalize_user_code("WDJB-MJHT"),
            "WDJBMJHT"
        );
        assert_eq!(
            DeviceCodeService::normalize_user_code("wdjb-mjht"),
            "WDJBMJHT"
        );
        assert_eq!(
            DeviceCodeService::normalize_user_code("wdjbmjht"),
            "WDJBMJHT"
        );
        assert_eq!(
            DeviceCodeService::normalize_user_code("WDJB MJHT"),
            "WDJBMJHT"
        );
        assert_eq!(
            DeviceCodeService::normalize_user_code("  wdjb  mjht  "),
            "WDJBMJHT"
        );
    }

    #[test]
    fn test_generate_user_code_unique() {
        let code1 = DeviceCodeService::generate_user_code();
        let code2 = DeviceCodeService::generate_user_code();
        // With 20^8 combinations, collision is extremely unlikely
        assert_ne!(code1, code2);
    }

    #[test]
    fn test_device_code_is_url_safe() {
        let code = DeviceCodeService::generate_device_code();
        // URL-safe base64 only uses A-Z, a-z, 0-9, -, _
        for c in code.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "Invalid character in device code: {c}"
            );
        }
    }
}
