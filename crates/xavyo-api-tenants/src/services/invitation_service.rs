//! Tenant invitation service (F-057).
//!
//! Provides business logic for tenant user invitations, wrapping the
//! existing `UserInvitation` model from xavyo-db.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_core::TenantId;
use xavyo_db::models::{CreateAdminInvitation, User, UserInvitation};
use xavyo_db::set_tenant_context;

use crate::error::TenantError;

/// Default invitation token expiry (7 days per FR-003).
const DEFAULT_EXPIRY_DAYS: i64 = 7;

/// Generate a cryptographically secure invitation token.
///
/// Uses 32 bytes of random data encoded as URL-safe base64 (no padding).
/// This provides 256-bit entropy per SC-002.
fn generate_invitation_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token using SHA-256.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Tenant invitation service.
///
/// Provides methods for creating, listing, cancelling, and accepting
/// tenant user invitations.
#[derive(Clone)]
pub struct TenantInvitationService {
    pool: PgPool,
}

impl TenantInvitationService {
    /// Create a new tenant invitation service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new invitation for a user to join a tenant.
    ///
    /// FR-001: Allow tenant administrators to create invitations
    /// FR-002: Generate cryptographically secure token (256-bit)
    /// FR-003: Set expiration to 7 days
    /// FR-004: Prevent duplicate pending invitations
    /// FR-005: Prevent invitations to existing members
    pub async fn create_invitation(
        &self,
        tenant_id: Uuid,
        email: &str,
        role: &str,
        invited_by_user_id: Uuid,
    ) -> Result<(UserInvitation, String), TenantError> {
        let normalized_email = email.to_lowercase();

        // FR-005: Check if user already exists in this tenant
        let existing_user = User::find_by_email(&self.pool, tenant_id, &normalized_email)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        if existing_user.is_some() {
            return Err(TenantError::Conflict(
                "User is already a member of this tenant".to_string(),
            ));
        }

        // FR-004: Check for existing pending invitation
        let existing_invitation =
            UserInvitation::find_by_email_pending(&self.pool, tenant_id, &normalized_email)
                .await
                .map_err(|e| TenantError::Database(e.to_string()))?;

        if existing_invitation.is_some() {
            return Err(TenantError::Conflict(
                "A pending invitation already exists for this email".to_string(),
            ));
        }

        // FR-002: Generate secure token (256-bit entropy)
        let raw_token = generate_invitation_token();
        let token_hash = hash_token(&raw_token);

        // FR-003: Set expiration to 7 days
        let expires_at = Utc::now() + Duration::days(DEFAULT_EXPIRY_DAYS);

        let invitation = UserInvitation::create_admin_invitation(
            &self.pool,
            &CreateAdminInvitation {
                tenant_id,
                email: normalized_email.clone(),
                token_hash,
                expires_at,
                invited_by_user_id,
                role_template_id: None,
                role: role.to_string(),
            },
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            invitation_id = %invitation.id,
            email = %normalized_email,
            role = %role,
            invited_by = %invited_by_user_id,
            "Tenant invitation created"
        );

        // Return both the invitation and the raw token (for email)
        Ok((invitation, raw_token))
    }

    /// List invitations for a tenant.
    ///
    /// FR-006: Allow tenant administrators to list invitations
    /// FR-014: Enforce tenant isolation
    pub async fn list_invitations(
        &self,
        tenant_id: Uuid,
        status_filter: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<(Vec<UserInvitation>, i64), TenantError> {
        let invitations = UserInvitation::list_by_tenant(
            &self.pool,
            tenant_id,
            status_filter,
            None, // No email search for now
            limit,
            offset,
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        let total = UserInvitation::count_by_tenant(&self.pool, tenant_id, status_filter, None)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        Ok((invitations, total))
    }

    /// Cancel a pending invitation.
    ///
    /// FR-007: Allow tenant administrators to cancel invitations
    /// FR-014: Enforce tenant isolation
    pub async fn cancel_invitation(
        &self,
        tenant_id: Uuid,
        invitation_id: Uuid,
        admin_user_id: Uuid,
    ) -> Result<UserInvitation, TenantError> {
        // Find the invitation first to check its state
        let invitation = UserInvitation::find_by_id(&self.pool, tenant_id, invitation_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .ok_or_else(|| TenantError::NotFoundWithMessage("Invitation not found".to_string()))?;

        // Check if already accepted
        if invitation.status == "accepted" {
            return Err(TenantError::Validation(
                "Cannot cancel an already accepted invitation".to_string(),
            ));
        }

        // Check if already cancelled
        if invitation.status == "cancelled" {
            return Err(TenantError::Validation(
                "Invitation is already cancelled".to_string(),
            ));
        }

        // Mark as cancelled
        let cancelled = UserInvitation::mark_cancelled(&self.pool, tenant_id, invitation_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .ok_or_else(|| TenantError::Internal("Failed to cancel invitation".to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            invitation_id = %invitation_id,
            admin_user_id = %admin_user_id,
            "Tenant invitation cancelled"
        );

        Ok(cancelled)
    }

    /// Accept an invitation and add user to tenant.
    ///
    /// FR-008: Allow invited users to accept invitations
    /// FR-009: Reject expired invitations
    /// FR-010: Reject cancelled invitations
    /// FR-011: Add user to tenant with specified role
    pub async fn accept_invitation(
        &self,
        token: &str,
        password: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(Uuid, Uuid, String), TenantError> {
        // Find invitation by token hash
        let token_hash = hash_token(token);
        let invitation = UserInvitation::find_by_token_hash(&self.pool, &token_hash)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .ok_or_else(|| {
                TenantError::NotFoundWithMessage("Invalid invitation token".to_string())
            })?;

        // FR-010: Check if cancelled
        if invitation.status == "cancelled" {
            return Err(TenantError::Gone(
                "This invitation is no longer valid".to_string(),
            ));
        }

        // Check if already accepted
        if invitation.status == "accepted" {
            return Err(TenantError::Gone(
                "This invitation has already been used".to_string(),
            ));
        }

        // FR-009: Check expiration
        if Utc::now() > invitation.expires_at {
            return Err(TenantError::Gone("This invitation has expired".to_string()));
        }

        // Get email from invitation
        let email = invitation
            .email
            .as_ref()
            .ok_or_else(|| TenantError::Internal("Invitation missing email".to_string()))?;

        // Use a transaction with tenant context for RLS-protected tables
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;
        set_tenant_context(&mut *tx, TenantId::from_uuid(invitation.tenant_id))
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        // Check if user already exists in this tenant
        let existing_user: Option<User> =
            sqlx::query_as("SELECT * FROM users WHERE tenant_id = $1 AND email = $2 LIMIT 1")
                .bind(invitation.tenant_id)
                .bind(email)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| TenantError::Database(e.to_string()))?;

        let user_id = if let Some(user) = existing_user {
            // User already exists - just add to tenant membership
            user.id
        } else {
            // Create new user (requires password)
            let password = password.ok_or_else(|| {
                TenantError::Validation("Password is required for new users".to_string())
            })?;

            // Hash password
            let password_hash = xavyo_auth::hash_password(password)
                .map_err(|e| TenantError::Internal(format!("Failed to hash password: {e}")))?;

            // Create user account
            let new_user_id = Uuid::new_v4();
            let now = Utc::now();

            let _user: User = sqlx::query_as(
                r"
                INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified, email_verified_at, created_at, updated_at)
                VALUES ($1, $2, $3, $4, true, true, $5, $5, $5)
                RETURNING *
                ",
            )
            .bind(new_user_id)
            .bind(invitation.tenant_id)
            .bind(email)
            .bind(&password_hash)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

            new_user_id
        };

        // Use the role stored on the invitation
        let role = invitation.role.clone();

        // Assign the role to the user in user_roles table
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_name, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(&role)
        .execute(&mut *tx)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        // Commit user + role creation before updating invitation status
        tx.commit()
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        // Update invitation with user_id (user_invitations has permissive RLS)
        UserInvitation::set_user_id(&self.pool, invitation.tenant_id, invitation.id, user_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;

        // Mark as accepted (user_invitations has permissive RLS)
        UserInvitation::mark_accepted(
            &self.pool,
            invitation.tenant_id,
            invitation.id,
            ip_address,
            user_agent,
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        tracing::info!(
            tenant_id = %invitation.tenant_id,
            invitation_id = %invitation.id,
            user_id = %user_id,
            email = %email,
            "Tenant invitation accepted"
        );

        Ok((user_id, invitation.tenant_id, role))
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

    #[test]
    fn test_hash_token_consistency() {
        let token = "test-token-123";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_different_inputs() {
        let hash1 = hash_token("token1");
        let hash2 = hash_token("token2");
        assert_ne!(hash1, hash2);
    }
}
