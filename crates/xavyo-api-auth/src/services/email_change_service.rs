//! Email change service (F027).
//!
//! Handles secure email change flow with verification tokens.

use crate::error::ApiAuthError;
use crate::models::{EmailChangeCompletedResponse, EmailChangeInitiatedResponse};
use crate::services::{hash_token, verify_token_hash_constant_time, EmailSender};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;
use xavyo_auth::verify_password;
use xavyo_db::{set_tenant_context, EmailChangeRequest, User};

/// Token validity in hours for email change requests.
pub const EMAIL_CHANGE_TOKEN_VALIDITY_HOURS: i64 = 24;

/// Length of the verification token in bytes.
const TOKEN_BYTES: usize = 32;

/// Email change service.
#[derive(Clone)]
pub struct EmailChangeService {
    pool: PgPool,
}

impl EmailChangeService {
    /// Create a new email change service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Generate a secure random token.
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
    fn generate_token() -> String {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut bytes = [0u8; TOKEN_BYTES];
        OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    // ========================================================================
    // User Story 2: Change Email Address
    // ========================================================================

    /// Initiate an email change request.
    ///
    /// Creates a pending request and sends a verification email to the new address.
    pub async fn initiate_email_change<E: EmailSender + ?Sized>(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        new_email: &str,
        current_password: &str,
        email_sender: &E,
    ) -> Result<EmailChangeInitiatedResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get user and verify password (include tenant_id for defense-in-depth)
        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::UserNotFound)?;

        // Verify current password
        if !verify_password(current_password, &user.password_hash)
            .map_err(|_| ApiAuthError::Internal("Password verification failed".to_string()))?
        {
            warn!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                "Email change attempt with invalid password"
            );
            return Err(ApiAuthError::InvalidCredentials);
        }

        // Check if new email is same as current
        if user.email.to_lowercase() == new_email.to_lowercase() {
            return Err(ApiAuthError::SameEmail);
        }

        // Check if new email is already in use by another user
        if let Some(_existing) = User::find_by_email(&self.pool, tenant_id, new_email)
            .await
            .map_err(ApiAuthError::Database)?
        {
            warn!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                new_email = %new_email,
                "Email change to already used email"
            );
            return Err(ApiAuthError::EmailAlreadyExists);
        }

        // Check if there's already a pending request for this email
        if EmailChangeRequest::is_email_pending(&self.pool, tenant_id, new_email)
            .await
            .map_err(ApiAuthError::Database)?
        {
            return Err(ApiAuthError::EmailAlreadyExists);
        }

        // Cancel any existing pending requests for this user
        let cancelled = EmailChangeRequest::cancel_pending_for_user(&self.pool, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?;
        if cancelled > 0 {
            info!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                cancelled_count = cancelled,
                "Cancelled previous email change requests"
            );
        }

        // Generate token and hash
        let token = Self::generate_token();
        let token_hash = hash_token(&token);

        // Calculate expiration
        let expires_at = Utc::now() + Duration::hours(EMAIL_CHANGE_TOKEN_VALIDITY_HOURS);

        // Create the request
        let request = EmailChangeRequest::create(
            &self.pool,
            tenant_id,
            user_id,
            new_email,
            &token_hash,
            expires_at,
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Send verification email to the new address
        let email_body = format!(
            "Hello,\n\n\
            You have requested to change your email address to {}.\n\n\
            Please verify this email address by clicking the link below:\n\n\
            {}?token={}\n\n\
            This link will expire in {} hours.\n\n\
            If you did not request this change, please ignore this email.\n\n\
            Best regards,\n\
            The xavyo Team",
            new_email,
            "https://example.com/verify-email", // TODO: Make configurable
            token,
            EMAIL_CHANGE_TOKEN_VALIDITY_HOURS,
        );

        email_sender
            .send(new_email, "Verify your new email address", &email_body)
            .await
            .map_err(|e| ApiAuthError::EmailSendFailed(e.to_string()))?;

        info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            request_id = %request.id,
            "Email change initiated"
        );

        Ok(EmailChangeInitiatedResponse {
            message: "Verification email sent to new address".to_string(),
            expires_at,
        })
    }

    /// Verify an email change request using the token.
    pub async fn verify_email_change(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        token: &str,
    ) -> Result<EmailChangeCompletedResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Hash the provided token
        let token_hash = hash_token(token);

        // Find the pending request
        let request = EmailChangeRequest::find_by_token_hash(&self.pool, &token_hash)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::EmailChangeTokenInvalid)?;

        // Verify the request belongs to this user
        if request.user_id != user_id {
            warn!(
                user_id = %user_id,
                request_user_id = %request.user_id,
                "Email change verification attempt for different user"
            );
            return Err(ApiAuthError::EmailChangeTokenInvalid);
        }

        // Check if expired
        if request.expires_at <= Utc::now() {
            warn!(
                user_id = %user_id,
                request_id = %request.id,
                "Email change token expired"
            );
            return Err(ApiAuthError::EmailChangeTokenExpired);
        }

        // Verify the token hash using constant-time comparison
        if !verify_token_hash_constant_time(token, &request.token_hash) {
            return Err(ApiAuthError::EmailChangeTokenInvalid);
        }

        // Check that new email is still available
        if let Some(_existing) = User::find_by_email(&self.pool, tenant_id, &request.new_email)
            .await
            .map_err(ApiAuthError::Database)?
        {
            warn!(
                user_id = %user_id,
                new_email = %request.new_email,
                "Email taken during verification"
            );
            return Err(ApiAuthError::EmailAlreadyExists);
        }

        // Update the user's email with tenant isolation
        let _updated_user = User::update_email(&self.pool, tenant_id, user_id, &request.new_email)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::UserNotFound)?;

        // Mark the request as verified
        EmailChangeRequest::mark_verified(&self.pool, request.id)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(
            user_id = %user_id,
            tenant_id = %tenant_id,
            new_email = %request.new_email,
            "Email change completed"
        );

        Ok(EmailChangeCompletedResponse {
            message: "Email changed successfully".to_string(),
            new_email: request.new_email,
        })
    }

    /// Cancel all pending email change requests for a user.
    pub async fn cancel_pending_requests(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<u64, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let cancelled = EmailChangeRequest::cancel_pending_for_user(&self.pool, tenant_id, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        if cancelled > 0 {
            info!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                cancelled_count = cancelled,
                "Cancelled pending email change requests"
            );
        }

        Ok(cancelled)
    }
}

#[cfg(test)]
mod tests {
    // Integration tests will be in the tests/ directory
}
