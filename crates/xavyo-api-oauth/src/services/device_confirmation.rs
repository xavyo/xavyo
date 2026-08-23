//! Device code confirmation service for Storm-2372 remediation (F117).
//!
//! Handles email confirmation flow when a user attempts to approve a device code
//! from a suspicious IP address (different from the origin IP where the code
//! was requested).

use crate::error::OAuthError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use rand::RngCore;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_api_auth::{EmailError, EmailSender};
use xavyo_db::models::{
    DeviceCodeConfirmation, NewDeviceCodeConfirmation, CONFIRMATION_EXPIRY_MINUTES,
};

/// Length of confirmation tokens in bytes (32 bytes = 256 bits of entropy).
const CONFIRMATION_TOKEN_LENGTH: usize = 32;

/// Result of validating a confirmation token.
#[derive(Debug, Clone)]
pub enum ConfirmationValidationResult {
    /// Token is valid, confirmation completed. Returns the confirmation record.
    Valid { device_code_id: Uuid, user_id: Uuid },
    /// Token not found or already confirmed.
    NotFound,
    /// Token has expired.
    Expired,
}

/// Result of creating a confirmation.
#[derive(Debug, Clone)]
pub struct ConfirmationCreated {
    /// The confirmation ID.
    pub confirmation_id: Uuid,
    /// The raw confirmation token (to be sent via email).
    pub token: String,
    /// When the confirmation expires.
    pub expires_at: chrono::DateTime<Utc>,
}

/// Service for handling device code email confirmations.
///
/// This service implements the Storm-2372 remediation by requiring email
/// confirmation when users approve device codes from suspicious IP addresses.
pub struct DeviceConfirmationService {
    pool: PgPool,
    email_sender: Arc<dyn EmailSender>,
    /// Base URL for confirmation links (e.g., "<https://api.xavyo.com>").
    base_url: String,
}

/// Build the device-confirmation URL that emails must contain.
///
/// The device router is nested at `/device`, not `/oauth/device`. An empty
/// token cannot confirm anything and must not be mailed.
pub fn confirmation_url(
    base_url: &str,
    tenant_id: Uuid,
    token: &str,
) -> Result<String, OAuthError> {
    if token.is_empty() {
        return Err(OAuthError::Internal(
            "device confirmation token must not be empty".to_string(),
        ));
    }
    Ok(format!(
        "{}/device/confirm/{}?tid={}",
        base_url.trim_end_matches('/'),
        token,
        tenant_id
    ))
}

impl DeviceConfirmationService {
    /// Create a new device confirmation service.
    pub fn new(pool: PgPool, email_sender: Arc<dyn EmailSender>, base_url: String) -> Self {
        Self {
            pool,
            email_sender,
            base_url,
        }
    }

    /// Generate a cryptographically secure confirmation token.
    fn generate_token() -> String {
        use rand::rngs::OsRng;
        let mut bytes = [0u8; CONFIRMATION_TOKEN_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    async fn lookup_user_email(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<String, OAuthError> {
        let mut conn = self.pool.acquire().await.map_err(|e| {
            OAuthError::Internal(format!("Failed to acquire connection for user email: {e}"))
        })?;
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| OAuthError::Internal(format!("Failed to set tenant context: {e}")))?;

        let email: Option<(String,)> =
            sqlx::query_as("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_optional(&mut *conn)
                .await
                .map_err(|e| OAuthError::Internal(format!("Failed to look up user email: {e}")))?;

        email.map(|(e,)| e).ok_or_else(|| {
            OAuthError::Internal("User email not found for device confirmation".to_string())
        })
    }

    /// Create a confirmation for `user_id` by looking up their tenant-scoped email.
    pub async fn create_confirmation_for_user(
        &self,
        tenant_id: Uuid,
        device_code_id: Uuid,
        user_id: Uuid,
        requested_from_ip: Option<String>,
        client_name: Option<&str>,
    ) -> Result<ConfirmationCreated, OAuthError> {
        let user_email = self.lookup_user_email(tenant_id, user_id).await?;
        self.create_confirmation(
            tenant_id,
            device_code_id,
            user_id,
            &user_email,
            requested_from_ip,
            client_name,
        )
        .await
    }

    /// Create a new confirmation and send the email.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant ID
    /// * `device_code_id` - The device code being confirmed
    /// * `user_id` - The user who needs to confirm
    /// * `user_email` - The user's email address for sending the confirmation
    /// * `requested_from_ip` - The IP address from which approval was attempted
    /// * `client_name` - Optional name of the OAuth client for the email
    ///
    /// # Returns
    ///
    /// The created confirmation with the raw token (not hashed).
    ///
    /// # Note
    ///
    /// This method invalidates any pending confirmations for the same device code
    /// before creating a new one (FR-012 compliance).
    pub async fn create_confirmation(
        &self,
        tenant_id: Uuid,
        device_code_id: Uuid,
        user_id: Uuid,
        user_email: &str,
        requested_from_ip: Option<String>,
        client_name: Option<&str>,
    ) -> Result<ConfirmationCreated, OAuthError> {
        // FR-012: Cancel any pending confirmations for this device code before creating new one
        let cancelled = DeviceCodeConfirmation::cancel_pending_for_device_code(
            &self.pool,
            tenant_id,
            device_code_id,
        )
        .await
        .map_err(|e| {
            OAuthError::Internal(format!("Failed to cancel pending confirmations: {e}"))
        })?;

        if cancelled > 0 {
            tracing::info!(
                tenant_id = %tenant_id,
                device_code_id = %device_code_id,
                cancelled_count = cancelled,
                "Cancelled pending confirmations before creating new one (FR-012)"
            );
        }

        let token = Self::generate_token();

        let new_confirmation = NewDeviceCodeConfirmation::new(
            tenant_id,
            device_code_id,
            user_id,
            &token,
            requested_from_ip.clone(),
        );

        let confirmation = DeviceCodeConfirmation::create(&self.pool, &new_confirmation)
            .await
            .map_err(|e| OAuthError::Internal(format!("Failed to create confirmation: {e}")))?;

        // Send the confirmation email
        self.send_confirmation_email(
            user_email,
            &token,
            &confirmation.id,
            tenant_id,
            client_name,
            requested_from_ip.as_deref(),
        )
        .await?;

        Ok(ConfirmationCreated {
            confirmation_id: confirmation.id,
            token,
            expires_at: confirmation.expires_at,
        })
    }

    /// Validate a confirmation token and mark as confirmed.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant ID
    /// * `token` - The raw confirmation token from the email link
    ///
    /// # Returns
    ///
    /// The validation result indicating success, not found, or expired.
    pub async fn validate_token(
        &self,
        tenant_id: Uuid,
        token: &str,
    ) -> Result<ConfirmationValidationResult, OAuthError> {
        let token_hash = DeviceCodeConfirmation::hash_token(token);

        let confirmation =
            DeviceCodeConfirmation::find_by_token_hash(&self.pool, tenant_id, &token_hash)
                .await
                .map_err(|e| OAuthError::Internal(format!("Failed to find confirmation: {e}")))?;

        match confirmation {
            None => Ok(ConfirmationValidationResult::NotFound),
            Some(c) if c.is_expired() => Ok(ConfirmationValidationResult::Expired),
            Some(c) if c.is_confirmed() => {
                // Already confirmed, return success
                Ok(ConfirmationValidationResult::Valid {
                    device_code_id: c.device_code_id,
                    user_id: c.user_id,
                })
            }
            Some(c) => {
                // Mark as confirmed
                let confirmed = DeviceCodeConfirmation::confirm(&self.pool, tenant_id, c.id)
                    .await
                    .map_err(|e| {
                        OAuthError::Internal(format!("Failed to confirm confirmation: {e}"))
                    })?;

                match confirmed {
                    Some(c) => Ok(ConfirmationValidationResult::Valid {
                        device_code_id: c.device_code_id,
                        user_id: c.user_id,
                    }),
                    None => {
                        // Race condition - confirmation expired or was confirmed between checks
                        Ok(ConfirmationValidationResult::Expired)
                    }
                }
            }
        }
    }

    /// Check if a pending confirmation exists for a device code.
    pub async fn find_pending_confirmation(
        &self,
        tenant_id: Uuid,
        device_code_id: Uuid,
    ) -> Result<Option<DeviceCodeConfirmation>, OAuthError> {
        DeviceCodeConfirmation::find_pending_for_device_code(&self.pool, tenant_id, device_code_id)
            .await
            .map_err(|e| OAuthError::Internal(format!("Failed to find pending confirmation: {e}")))
    }

    /// Resend a pending confirmation with a rotated token.
    ///
    /// Looks up the user's email, stores a new token hash, and sends a usable
    /// confirmation link. Returns `Ok(false)` when rate limited or not found.
    pub async fn resend_pending(
        &self,
        tenant_id: Uuid,
        device_code_id: Uuid,
        client_name: Option<&str>,
    ) -> Result<bool, OAuthError> {
        let pending = self
            .find_pending_confirmation(tenant_id, device_code_id)
            .await?;
        let Some(pending) = pending else {
            return Ok(false);
        };
        if !pending.can_resend() {
            return Ok(false);
        }

        let user_email = self.lookup_user_email(tenant_id, pending.user_id).await?;
        self.resend_confirmation(tenant_id, pending.id, &user_email, client_name)
            .await
    }

    /// Resend a confirmation email with rate limiting and a new raw token.
    ///
    /// # Returns
    ///
    /// Ok(true) if resend was successful, Ok(false) if rate limited.
    pub async fn resend_confirmation(
        &self,
        tenant_id: Uuid,
        confirmation_id: Uuid,
        user_email: &str,
        client_name: Option<&str>,
    ) -> Result<bool, OAuthError> {
        let new_token = Self::generate_token();
        let new_hash = DeviceCodeConfirmation::hash_token(&new_token);

        let confirmation = DeviceCodeConfirmation::record_resend_with_new_token(
            &self.pool,
            tenant_id,
            confirmation_id,
            &new_hash,
        )
        .await
        .map_err(|e| OAuthError::Internal(format!("Failed to record resend: {e}")))?;

        match confirmation {
            None => Ok(false),
            Some(c) => {
                self.send_confirmation_email(
                    user_email,
                    &new_token,
                    &c.id,
                    tenant_id,
                    client_name,
                    c.requested_from_ip.as_deref(),
                )
                .await?;
                Ok(true)
            }
        }
    }

    /// Send the confirmation email.
    async fn send_confirmation_email(
        &self,
        to: &str,
        token: &str,
        confirmation_id: &Uuid,
        tenant_id: Uuid,
        client_name: Option<&str>,
        requested_from_ip: Option<&str>,
    ) -> Result<(), OAuthError> {
        let confirmation_url = crate::services::device_confirmation::confirmation_url(
            &self.base_url,
            tenant_id,
            token,
        )?;

        let app_name = client_name.unwrap_or("an application");
        let ip_info = requested_from_ip
            .map(|ip| format!(" from IP address {ip}"))
            .unwrap_or_default();

        let subject = "Confirm your device authorization request";
        let body = format!(
            r"You requested to authorize {app_name} to access your account{ip_info}.

To confirm this request, click the link below:

{confirmation_url}

This link will expire in {CONFIRMATION_EXPIRY_MINUTES} minutes.

If you did not request this authorization, please ignore this email.
Someone may have entered your email address by mistake.

Security Notice: This confirmation was requested because the authorization
attempt came from a different location than where the device code was created.
This is a security measure to protect your account.

- The xavyo Team"
        );

        self.email_sender
            .send(to, subject, &body)
            .await
            .map_err(|e: EmailError| {
                OAuthError::Internal(format!("Failed to send confirmation email: {e}"))
            })?;

        tracing::info!(
            tenant_id = %tenant_id,
            confirmation_id = %confirmation_id,
            "Sent device code confirmation email"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_api_auth::MockEmailSender;

    // Helper to create a mock email sender for tests
    #[allow(dead_code)]
    fn mock_email_sender() -> Arc<dyn EmailSender> {
        Arc::new(MockEmailSender::new())
    }

    #[test]
    fn test_generate_token() {
        let token1 = DeviceConfirmationService::generate_token();
        let token2 = DeviceConfirmationService::generate_token();

        // Tokens should be different
        assert_ne!(token1, token2);

        // Token should be URL-safe base64 (43 chars for 32 bytes)
        assert_eq!(token1.len(), 43);
        assert!(token1
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_confirmation_validation_result_variants() {
        // Test Valid variant
        let valid = ConfirmationValidationResult::Valid {
            device_code_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
        };
        assert!(matches!(valid, ConfirmationValidationResult::Valid { .. }));

        // Test NotFound variant
        let not_found = ConfirmationValidationResult::NotFound;
        assert!(matches!(not_found, ConfirmationValidationResult::NotFound));

        // Test Expired variant
        let expired = ConfirmationValidationResult::Expired;
        assert!(matches!(expired, ConfirmationValidationResult::Expired));
    }

    #[test]
    fn test_confirmation_created_struct() {
        let created = ConfirmationCreated {
            confirmation_id: Uuid::new_v4(),
            token: "test-token".to_string(),
            expires_at: Utc::now(),
        };

        assert!(!created.token.is_empty());
        assert!(created.expires_at <= Utc::now());
    }

    #[test]
    fn confirmation_url_rejects_empty_token() {
        let err = confirmation_url("https://idp.example", Uuid::new_v4(), "")
            .expect_err("empty token must fail closed");
        assert!(err.to_string().contains("must not be empty"), "{err}");
    }

    #[test]
    fn confirmation_url_is_device_route_with_tenant() {
        let tenant_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let url = confirmation_url("https://idp.example/", tenant_id, "abc_token")
            .expect("non-empty token");
        assert!(
            url.contains("/device/confirm/abc_token"),
            "device router is /device not /oauth/device: {url}"
        );
        assert!(
            !url.contains("/oauth/device/confirm"),
            "must not advertise a 404 path: {url}"
        );
        assert!(
            url.contains(&format!("tid={tenant_id}")),
            "email link must carry tenant for RLS: {url}"
        );
    }

    #[test]
    fn resend_does_not_mail_empty_token() {
        let src = include_str!("device_confirmation.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("record_resend_with_new_token"),
            "resend must persist a new token hash"
        );
        let empty_arg = format!("{},", "\"\"");
        assert!(
            !production.contains(&empty_arg),
            "must not pass an empty token to send_confirmation_email"
        );
    }
}
