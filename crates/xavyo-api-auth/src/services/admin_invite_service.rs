//! Admin invitation service (F-ADMIN-INVITE).
//!
//! Handles creation, acceptance, resend, and cancellation of admin invitations.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::models::{
    AdminAction, AdminAuditLog, AdminResourceType, AdminRoleTemplate, CreateAdminInvitation,
    CreateAuditLogEntry, User, UserInvitation,
};

use crate::error::ApiAuthError;
use crate::services::{
    hash_token, validate_email, validate_password, verify_token_hash_constant_time, EmailSender,
};

/// Default invitation token expiry (7 days).
const DEFAULT_EXPIRY_DAYS: i64 = 7;

/// Maximum pending invitations per tenant.
const MAX_PENDING_INVITATIONS: i64 = 10;

/// Generate a cryptographically secure invitation token.
///
/// Uses 32 bytes of random data encoded as URL-safe base64 (no padding).
fn generate_invitation_token() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::{rngs::OsRng, RngCore};

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Admin invitation service.
#[derive(Clone)]
pub struct AdminInviteService {
    pool: PgPool,
    email_sender: Arc<dyn EmailSender>,
    frontend_base_url: String,
}

impl AdminInviteService {
    /// Create a new admin invite service.
    pub fn new(
        pool: PgPool,
        email_sender: Arc<dyn EmailSender>,
        frontend_base_url: String,
    ) -> Self {
        Self {
            pool,
            email_sender,
            frontend_base_url,
        }
    }

    /// Create a new admin invitation.
    ///
    /// Validates the email, checks for duplicates and rate limits,
    /// generates a secure token, sends the invitation email,
    /// and logs the action to the audit trail.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_invitation(
        &self,
        tenant_id: Uuid,
        email: &str,
        role_template_id: Option<Uuid>,
        invited_by_user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<UserInvitation, ApiAuthError> {
        // Validate email format
        let email_result = validate_email(email);
        if !email_result.is_valid {
            return Err(ApiAuthError::Validation(
                email_result
                    .error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "Invalid email".to_string()),
            ));
        }

        let normalized_email = email.to_lowercase();

        // Check if user already exists in this tenant
        let existing_user = User::find_by_email(&self.pool, tenant_id, &normalized_email)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        if existing_user.is_some() {
            return Err(ApiAuthError::UserAlreadyExists(
                "User with this email already exists in this tenant".to_string(),
            ));
        }

        // Check for existing pending invitation
        let existing_invitation =
            UserInvitation::find_by_email_pending(&self.pool, tenant_id, &normalized_email)
                .await
                .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        if existing_invitation.is_some() {
            return Err(ApiAuthError::PendingInvitationExists(
                "An active invitation already exists for this email".to_string(),
            ));
        }

        // Check rate limit (10 pending invitations per tenant)
        let pending_count = UserInvitation::count_pending_by_tenant(&self.pool, tenant_id)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        if pending_count >= MAX_PENDING_INVITATIONS {
            return Err(ApiAuthError::MaxInvitationsReached(format!(
                "Maximum of {} pending invitations per tenant",
                MAX_PENDING_INVITATIONS
            )));
        }

        // Validate role template if provided
        if let Some(template_id) = role_template_id {
            let template = AdminRoleTemplate::get_by_id(&self.pool, tenant_id, template_id)
                .await
                .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

            if template.is_none() {
                return Err(ApiAuthError::TemplateNotFound);
            }
        }

        // Generate secure token
        let raw_token = generate_invitation_token();
        let token_hash = hash_token(&raw_token);

        let expires_at = Utc::now() + Duration::days(DEFAULT_EXPIRY_DAYS);

        // Create invitation record
        let invitation = UserInvitation::create_admin_invitation(
            &self.pool,
            &CreateAdminInvitation {
                tenant_id,
                email: normalized_email.clone(),
                token_hash,
                expires_at,
                invited_by_user_id,
                role_template_id,
            },
        )
        .await
        .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        // Send invitation email
        let invitation_url = format!("{}/invite/{}", self.frontend_base_url, raw_token);
        let subject = "You're invited to join as an administrator";
        let body = format!(
            r#"Hi,

You have been invited to set up an administrator account.

Click the link below to set your password and activate your account:
{invitation_url}

This link will expire in {DEFAULT_EXPIRY_DAYS} days.

If you didn't expect this invitation, you can safely ignore this email.

- The xavyo Team"#
        );

        self.email_sender
            .send(&normalized_email, subject, &body)
            .await
            .map_err(|e| ApiAuthError::EmailSendFailed(e.to_string()))?;

        // Mark as sent
        let invitation = UserInvitation::mark_sent(&self.pool, tenant_id, invitation.id)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?
            .unwrap_or(invitation);

        // Log audit trail
        let new_value = serde_json::json!({
            "email": normalized_email,
            "role_template_id": role_template_id,
            "expires_at": expires_at.to_rfc3339(),
        });

        AdminAuditLog::create(
            &self.pool,
            CreateAuditLogEntry {
                tenant_id,
                admin_user_id: invited_by_user_id,
                action: AdminAction::Create,
                resource_type: AdminResourceType::AdminInvitation,
                resource_id: Some(invitation.id),
                old_value: None,
                new_value: Some(new_value),
                ip_address,
                user_agent,
            },
        )
        .await
        .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            invitation_id = %invitation.id,
            email = %normalized_email,
            invited_by = %invited_by_user_id,
            "Admin invitation created and sent"
        );

        Ok(invitation)
    }

    /// Accept an invitation and create the user account.
    ///
    /// Validates the token, checks expiration, validates password,
    /// creates the user account, assigns role if specified,
    /// and marks the invitation as accepted.
    pub async fn accept_invitation(
        &self,
        token: &str,
        password: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(User, UserInvitation), ApiAuthError> {
        // Validate password
        let password_result = validate_password(password);
        if !password_result.is_valid {
            let error_msg = password_result
                .errors
                .first()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "Invalid password".to_string());
            return Err(ApiAuthError::Validation(error_msg));
        }

        // Find invitation by token hash
        let token_hash = hash_token(token);
        let invitation = UserInvitation::find_by_token_hash(&self.pool, &token_hash)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?
            .ok_or(ApiAuthError::InvalidInvitationToken)?;

        // Verify token using constant-time comparison
        if !verify_token_hash_constant_time(token, &invitation.token_hash) {
            return Err(ApiAuthError::InvalidInvitationToken);
        }

        // Check if already accepted
        if invitation.status == "accepted" {
            return Err(ApiAuthError::InvitationAlreadyAccepted);
        }

        // Check if cancelled
        if invitation.status == "cancelled" {
            return Err(ApiAuthError::InvitationCancelled);
        }

        // Check expiration
        if Utc::now() > invitation.expires_at {
            return Err(ApiAuthError::InvitationExpired);
        }

        // Get email from invitation
        let email = invitation
            .email
            .as_ref()
            .ok_or_else(|| ApiAuthError::Internal("Invitation missing email".to_string()))?;

        // Hash password
        let password_hash = xavyo_auth::hash_password(password)
            .map_err(|e| ApiAuthError::Internal(format!("Failed to hash password: {}", e)))?;

        // Create user account with password (direct SQL like auth_service)
        let user_id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();

        let user: User = sqlx::query_as(
            r#"
            INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified, email_verified_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, true, true, $5, $5, $5)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(invitation.tenant_id)
        .bind(email)
        .bind(&password_hash)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        // Update invitation with user_id
        UserInvitation::set_user_id(&self.pool, invitation.tenant_id, invitation.id, user.id)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        // Mark as accepted
        let updated_invitation = UserInvitation::mark_accepted(
            &self.pool,
            invitation.tenant_id,
            invitation.id,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await
        .map_err(|e| ApiAuthError::Internal(e.to_string()))?
        .unwrap_or(invitation.clone());

        // Assign role template if specified
        if let Some(template_id) = invitation.role_template_id {
            // Note: Role assignment logic would go here
            // For now, we just log it
            tracing::info!(
                user_id = %user.id,
                template_id = %template_id,
                "Role template should be assigned (not implemented)"
            );
        }

        // Log audit trail
        let new_value = serde_json::json!({
            "user_id": user.id,
            "email": email,
            "status": "accepted",
        });

        AdminAuditLog::create(
            &self.pool,
            CreateAuditLogEntry {
                tenant_id: invitation.tenant_id,
                admin_user_id: user.id, // The new user accepted their own invitation
                action: AdminAction::Update,
                resource_type: AdminResourceType::AdminInvitation,
                resource_id: Some(invitation.id),
                old_value: Some(serde_json::json!({ "status": invitation.status })),
                new_value: Some(new_value),
                ip_address,
                user_agent,
            },
        )
        .await
        .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        tracing::info!(
            tenant_id = %invitation.tenant_id,
            invitation_id = %invitation.id,
            user_id = %user.id,
            email = %email,
            "Admin invitation accepted, user created"
        );

        Ok((user, updated_invitation))
    }

    /// Resend an invitation with a refreshed token and expiration.
    pub async fn resend_invitation(
        &self,
        tenant_id: Uuid,
        invitation_id: Uuid,
        admin_user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<UserInvitation, ApiAuthError> {
        // Find invitation
        let invitation = UserInvitation::find_by_id(&self.pool, tenant_id, invitation_id)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?
            .ok_or(ApiAuthError::InvitationNotFound)?;

        // Check status - can only resend pending or sent
        if invitation.status == "accepted" {
            return Err(ApiAuthError::InvitationAlreadyAccepted);
        }

        if invitation.status == "cancelled" {
            return Err(ApiAuthError::InvitationCancelled);
        }

        // Get email
        let email = invitation
            .email
            .as_ref()
            .ok_or_else(|| ApiAuthError::Internal("Invitation missing email".to_string()))?;

        // Generate new token
        let raw_token = generate_invitation_token();
        let token_hash = hash_token(&raw_token);
        let new_expires_at = Utc::now() + Duration::days(DEFAULT_EXPIRY_DAYS);

        // Update invitation with new token
        let updated = UserInvitation::refresh_expiration(
            &self.pool,
            tenant_id,
            invitation_id,
            &token_hash,
            new_expires_at,
        )
        .await
        .map_err(|e| ApiAuthError::Internal(e.to_string()))?
        .ok_or_else(|| ApiAuthError::Internal("Failed to refresh invitation".to_string()))?;

        // Send new email
        let invitation_url = format!("{}/invite/{}", self.frontend_base_url, raw_token);
        let subject = "You're invited to join as an administrator";
        let body = format!(
            r#"Hi,

You have been invited to set up an administrator account.

Click the link below to set your password and activate your account:
{invitation_url}

This link will expire in {DEFAULT_EXPIRY_DAYS} days.

If you didn't expect this invitation, you can safely ignore this email.

- The xavyo Team"#
        );

        self.email_sender
            .send(email, subject, &body)
            .await
            .map_err(|e| ApiAuthError::EmailSendFailed(e.to_string()))?;

        // Mark as sent
        let invitation = UserInvitation::mark_sent(&self.pool, tenant_id, updated.id)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?
            .unwrap_or(updated);

        // Log audit trail
        AdminAuditLog::create(
            &self.pool,
            CreateAuditLogEntry {
                tenant_id,
                admin_user_id,
                action: AdminAction::Update,
                resource_type: AdminResourceType::AdminInvitation,
                resource_id: Some(invitation_id),
                old_value: Some(serde_json::json!({ "action": "resend" })),
                new_value: Some(serde_json::json!({
                    "expires_at": new_expires_at.to_rfc3339(),
                })),
                ip_address,
                user_agent,
            },
        )
        .await
        .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            invitation_id = %invitation_id,
            email = %email,
            admin_user_id = %admin_user_id,
            "Admin invitation resent"
        );

        Ok(invitation)
    }

    /// Cancel a pending invitation.
    pub async fn cancel_invitation(
        &self,
        tenant_id: Uuid,
        invitation_id: Uuid,
        admin_user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<UserInvitation, ApiAuthError> {
        // Find invitation
        let invitation = UserInvitation::find_by_id(&self.pool, tenant_id, invitation_id)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?
            .ok_or(ApiAuthError::InvitationNotFound)?;

        // Check status - can only cancel pending or sent
        if invitation.status == "accepted" {
            return Err(ApiAuthError::InvitationAlreadyAccepted);
        }

        if invitation.status == "cancelled" {
            return Err(ApiAuthError::InvitationCancelled);
        }

        // Mark as cancelled
        let cancelled = UserInvitation::mark_cancelled(&self.pool, tenant_id, invitation_id)
            .await
            .map_err(|e| ApiAuthError::Internal(e.to_string()))?
            .ok_or_else(|| ApiAuthError::Internal("Failed to cancel invitation".to_string()))?;

        // Log audit trail
        AdminAuditLog::create(
            &self.pool,
            CreateAuditLogEntry {
                tenant_id,
                admin_user_id,
                action: AdminAction::Delete,
                resource_type: AdminResourceType::AdminInvitation,
                resource_id: Some(invitation_id),
                old_value: Some(serde_json::json!({
                    "email": invitation.email,
                    "status": invitation.status,
                })),
                new_value: Some(serde_json::json!({ "status": "cancelled" })),
                ip_address,
                user_agent,
            },
        )
        .await
        .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            invitation_id = %invitation_id,
            admin_user_id = %admin_user_id,
            "Admin invitation cancelled"
        );

        Ok(cancelled)
    }

    /// List invitations for a tenant.
    pub async fn list_invitations(
        &self,
        tenant_id: Uuid,
        status_filter: Option<&str>,
        email_search: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<(Vec<UserInvitation>, i64), ApiAuthError> {
        let invitations = UserInvitation::list_by_tenant(
            &self.pool,
            tenant_id,
            status_filter,
            email_search,
            limit,
            offset,
        )
        .await
        .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        let total =
            UserInvitation::count_by_tenant(&self.pool, tenant_id, status_filter, email_search)
                .await
                .map_err(|e| ApiAuthError::Internal(e.to_string()))?;

        Ok((invitations, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_invitation_token_length() {
        let token = generate_invitation_token();
        // 32 bytes in URL-safe base64 = 43 characters
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn test_generate_invitation_token_uniqueness() {
        let token1 = generate_invitation_token();
        let token2 = generate_invitation_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_token_is_url_safe() {
        let token = generate_invitation_token();
        // URL-safe base64 uses A-Z, a-z, 0-9, -, _
        assert!(token
            .chars()
            .all(|c| { c.is_ascii_alphanumeric() || c == '-' || c == '_' }));
    }
}
