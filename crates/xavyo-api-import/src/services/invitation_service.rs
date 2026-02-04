//! Invitation service for email invitation flow (F086).
//!
//! Manages invitation creation, token generation, email sending,
//! resend logic, and bulk resend for import jobs.

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::ImportError;
use xavyo_api_auth::EmailSender;
use xavyo_db::models::{CreateInvitation, UserInvitation};

/// Default invitation token expiry (7 days).
const DEFAULT_EXPIRY_DAYS: i64 = 7;

/// Invitation service for managing user invitations.
pub struct InvitationService;

impl InvitationService {
    /// Create an invitation for a user and optionally send the email.
    ///
    /// Generates a cryptographically random token, stores the SHA-256 hash,
    /// and returns the raw token for inclusion in the invitation URL.
    pub async fn create_invitation(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        job_id: Option<Uuid>,
    ) -> Result<(UserInvitation, String), ImportError> {
        // Invalidate any previous active invitations for this user
        let _ = UserInvitation::invalidate_previous(pool, tenant_id, user_id).await?;

        // Generate secure token (reuse pattern from xavyo-api-auth)
        let raw_token = generate_invitation_token();
        let token_hash = hash_token(&raw_token);

        let expires_at = Utc::now() + Duration::days(DEFAULT_EXPIRY_DAYS);

        let invitation = UserInvitation::create(
            pool,
            &CreateInvitation {
                tenant_id,
                user_id,
                job_id,
                token_hash,
                expires_at,
            },
        )
        .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            invitation_id = %invitation.id,
            "Invitation created"
        );

        Ok((invitation, raw_token))
    }

    /// Send an invitation email to the user.
    pub async fn send_invitation_email(
        email_sender: &Arc<dyn EmailSender>,
        to_email: &str,
        raw_token: &str,
        frontend_base_url: &str,
    ) -> Result<(), ImportError> {
        let invitation_url = format!("{frontend_base_url}/invite/{raw_token}");

        let subject = "You're invited to set up your Xavyo account";
        let body = format!(
            r"Hi,

You have been invited to set up your Xavyo account.

Click the link below to set your password and activate your account:
{invitation_url}

This link will expire in {DEFAULT_EXPIRY_DAYS} days.

If you didn't expect this invitation, you can safely ignore this email.

- The xavyo Team"
        );

        email_sender
            .send(to_email, subject, &body)
            .await
            .map_err(|e| {
                ImportError::Internal(format!("Failed to send invitation email: {e}"))
            })?;

        Ok(())
    }

    /// Resend an invitation for a specific user.
    ///
    /// Invalidates previous tokens and creates a new one.
    pub async fn resend_invitation(
        pool: &PgPool,
        email_sender: &Arc<dyn EmailSender>,
        tenant_id: Uuid,
        user_id: Uuid,
        user_email: &str,
        frontend_base_url: &str,
    ) -> Result<UserInvitation, ImportError> {
        let (invitation, raw_token) =
            Self::create_invitation(pool, tenant_id, user_id, None).await?;

        Self::send_invitation_email(email_sender, user_email, &raw_token, frontend_base_url)
            .await?;

        // Mark as sent
        let updated = UserInvitation::mark_sent(pool, tenant_id, invitation.id).await?;

        Ok(updated.unwrap_or(invitation))
    }

    /// Bulk resend invitations for all pending/sent users in an import job.
    ///
    /// Returns (`resent_count`, `skipped_count`).
    pub async fn bulk_resend_for_job(
        pool: &PgPool,
        email_sender: &Arc<dyn EmailSender>,
        tenant_id: Uuid,
        job_id: Uuid,
        frontend_base_url: &str,
    ) -> Result<(i32, i32), ImportError> {
        let statuses: &[&str] = &["pending", "sent"];
        let invitations =
            UserInvitation::list_by_job(pool, tenant_id, job_id, Some(statuses)).await?;

        let mut resent = 0i32;
        let mut skipped = 0i32;

        for inv in &invitations {
            // Skip invitations without a user_id (admin invitations use email instead)
            let user_id = if let Some(uid) = inv.user_id { uid } else {
                skipped += 1;
                continue;
            };

            // Look up user email
            let user_email: Option<String> =
                sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                    .bind(user_id)
                    .bind(tenant_id)
                    .fetch_optional(pool)
                    .await?;

            let email = if let Some(e) = user_email { e } else {
                skipped += 1;
                continue;
            };

            match Self::resend_invitation(
                pool,
                email_sender,
                tenant_id,
                user_id,
                &email,
                frontend_base_url,
            )
            .await
            {
                Ok(_) => resent += 1,
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "Failed to resend invitation"
                    );
                    skipped += 1;
                }
            }
        }

        Ok((resent, skipped))
    }
}

/// Generate a cryptographically random invitation token.
///
/// Uses 32 bytes of random data encoded as URL-safe base64 (no padding).
///
/// SECURITY: Uses `OsRng` (CSPRNG) for cryptographic randomness.
fn generate_invitation_token() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::{rngs::OsRng, RngCore};

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token using SHA-256 and return hex-encoded string.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
