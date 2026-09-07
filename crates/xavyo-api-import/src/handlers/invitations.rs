//! Invitation handlers (F086).
//!
//! Admin endpoints:
//! - POST /`admin/users/:user_id/invite` — Resend invitation for a user
//! - POST /admin/users/imports/:job_id/resend-invitations — Bulk resend
//!
//! Public endpoints (no auth):
//! - GET  /invite/:token — Validate invitation token
//! - POST /invite/:token — Accept invitation (set password)

use axum::{extract::Path, Extension, Json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_api_auth::EmailSender;
use xavyo_auth::JwtClaims;

use crate::error::ImportError;
use crate::models::{
    AcceptInvitationRequest, AcceptInvitationResponse, BulkResendResponse, InvitationResponse,
    InvitationValidationResponse,
};
use crate::services::import_service::ImportService;
use crate::services::invitation_service::InvitationService;
use xavyo_db::models::{User, UserInvitation};

/// POST /`admin/users/:user_id/invite`
///
/// Send or resend an invitation for a specific user.
#[utoipa::path(
    post,
    path = "/admin/users/{user_id}/invite",
    tag = "Import",
    params(
        ("user_id" = Uuid, Path, description = "User ID to invite"),
    ),
    responses(
        (status = 200, description = "Invitation sent", body = InvitationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "User not found"),
    ),
)]
pub async fn resend_user_invitation(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<InvitationResponse>, ImportError> {
    let tenant_id = extract_tenant_id(&claims)?;
    if !claims.has_role("admin") {
        return Err(ImportError::Forbidden);
    }

    // Verify user exists and belongs to tenant (tenant-scoped lookup)
    let user = User::find_by_id_in_tenant(&pool, user_id, tenant_id)
        .await?
        .ok_or(ImportError::UserNotFound)?;

    let frontend_base_url = get_frontend_base_url();

    let invitation = InvitationService::resend_invitation(
        &pool,
        &email_sender,
        tenant_id,
        user_id,
        &user.email,
        &frontend_base_url,
    )
    .await?;

    Ok(Json(InvitationResponse::from(invitation)))
}

/// POST /admin/users/imports/:job_id/resend-invitations
///
/// Bulk resend invitations for all pending/sent users in an import job.
#[utoipa::path(
    post,
    path = "/admin/users/imports/{job_id}/resend-invitations",
    tag = "Import",
    params(
        ("job_id" = Uuid, Path, description = "Import job ID"),
    ),
    responses(
        (status = 200, description = "Invitations resent", body = BulkResendResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Job not found"),
    ),
)]
pub async fn bulk_resend_invitations(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<BulkResendResponse>, ImportError> {
    let tenant_id = extract_tenant_id(&claims)?;
    if !claims.has_role("admin") {
        return Err(ImportError::Forbidden);
    }

    // Verify job exists and belongs to tenant
    let _ = ImportService::get_job(&pool, tenant_id, job_id).await?;

    let frontend_base_url = get_frontend_base_url();

    let (resent_count, skipped_count) = InvitationService::bulk_resend_for_job(
        &pool,
        &email_sender,
        tenant_id,
        job_id,
        &frontend_base_url,
    )
    .await?;

    Ok(Json(BulkResendResponse {
        resent_count,
        skipped_count,
        message: Some(format!(
            "Resent {resent_count} invitations, skipped {skipped_count}"
        )),
    }))
}

/// GET /invite/:token (PUBLIC — no auth required)
///
/// Validate an invitation token and return status.
#[utoipa::path(
    get,
    path = "/invite/{token}",
    tag = "Import",
    params(
        ("token" = String, Path, description = "Invitation token"),
    ),
    responses(
        (status = 200, description = "Token validation result", body = InvitationValidationResponse),
    ),
)]
pub async fn validate_invitation_token(
    Extension(pool): Extension<PgPool>,
    Path(token): Path<String>,
) -> Result<Json<InvitationValidationResponse>, ImportError> {
    let token_hash = hash_token(&token);

    let invitation = UserInvitation::find_by_token_hash(&pool, &token_hash).await?;

    let invitation = match invitation {
        Some(inv) => inv,
        None => {
            return Ok(Json(InvitationValidationResponse {
                valid: false,
                email: None,
                tenant_name: None,
                reason: Some("invalid".to_string()),
                message: Some("Invalid invitation token.".to_string()),
            }));
        }
    };

    // Check if already accepted
    if invitation.status == "accepted" {
        return Ok(Json(InvitationValidationResponse {
            valid: false,
            email: None,
            tenant_name: None,
            reason: Some("already_accepted".to_string()),
            message: Some("This invitation has already been accepted.".to_string()),
        }));
    }

    // Check expiry
    if invitation.expires_at < chrono::Utc::now() {
        return Ok(Json(InvitationValidationResponse {
            valid: false,
            email: None,
            tenant_name: None,
            reason: Some("expired".to_string()),
            message: Some("This invitation has expired. Please request a new one.".to_string()),
        }));
    }

    // Look up user email
    let user_email: Option<String> =
        sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
            .bind(invitation.user_id)
            .bind(invitation.tenant_id)
            .fetch_optional(&pool)
            .await?;

    // Look up tenant name
    let tenant_name: Option<String> = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(invitation.tenant_id)
        .fetch_optional(&pool)
        .await?;

    Ok(Json(InvitationValidationResponse {
        valid: true,
        email: user_email,
        tenant_name,
        reason: None,
        message: Some("Invitation is valid. Please set your password.".to_string()),
    }))
}

/// POST /invite/:token (PUBLIC — no auth required)
///
/// Accept an invitation by setting a password and activating the account.
#[utoipa::path(
    post,
    path = "/invite/{token}",
    tag = "Import",
    params(
        ("token" = String, Path, description = "Invitation token"),
    ),
    request_body = AcceptInvitationRequest,
    responses(
        (status = 200, description = "Invitation accepted", body = AcceptInvitationResponse),
        (status = 400, description = "Invalid token or password"),
        (status = 409, description = "Token already used"),
        (status = 410, description = "Token expired"),
    ),
)]
pub async fn accept_invitation(
    Extension(pool): Extension<PgPool>,
    Path(token): Path<String>,
    Json(body): Json<AcceptInvitationRequest>,
) -> Result<Json<AcceptInvitationResponse>, ImportError> {
    let token_hash = hash_token(&token);

    // Find invitation
    let invitation = UserInvitation::find_by_token_hash(&pool, &token_hash)
        .await?
        .ok_or(ImportError::InvalidToken)?;

    // Check if already accepted
    if invitation.status == "accepted" {
        return Err(ImportError::TokenAlreadyUsed);
    }

    // Check expiry
    if invitation.expires_at < chrono::Utc::now() {
        return Err(ImportError::TokenExpired);
    }

    // Validate password length
    if body.password.len() < 8 {
        return Err(ImportError::PasswordPolicyViolation(
            "Password must be at least 8 characters".to_string(),
        ));
    }
    if body.password.len() > 128 {
        return Err(ImportError::PasswordPolicyViolation(
            "Password must be at most 128 characters".to_string(),
        ));
    }

    // Hash password
    let password_hash = xavyo_auth::hash_password(&body.password)
        .map_err(|e| ImportError::Internal(format!("Failed to hash password: {e}")))?;

    // Two invitation shapes share this endpoint:
    //  - Bulk-import invitations pre-create the user (user_id set): activate + set password.
    //  - Admin invitations have no user yet (user_id NULL): create the account and
    //    assign the invited role. Previously the UPDATE below matched zero rows for
    //    admin invitations, so acceptance reported success but never created the
    //    account — the invited user could never log in.
    if let Some(existing_user_id) = invitation.user_id {
        // Atomically mark invitation as accepted (prevents concurrent double-acceptance)
        let accepted =
            UserInvitation::mark_accepted(&pool, invitation.tenant_id, invitation.id, None, None)
                .await?;
        if accepted.is_none() {
            return Err(ImportError::TokenAlreadyUsed);
        }

        sqlx::query(
            r"
            UPDATE users
            SET password_hash = $3, is_active = true, email_verified = true,
                email_verified_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(existing_user_id)
        .bind(invitation.tenant_id)
        .bind(&password_hash)
        .execute(&pool)
        .await?;

        tracing::info!(
            user_id = %existing_user_id,
            invitation_id = %invitation.id,
            "Invitation accepted, existing account activated"
        );
    } else {
        // Admin invitation: create the user and assign the invited role atomically.
        let email = invitation
            .email
            .as_ref()
            .ok_or_else(|| ImportError::Internal("Invitation missing email".to_string()))?;

        let mut tx = pool
            .begin()
            .await
            .map_err(|e| ImportError::Internal(format!("Failed to begin transaction: {e}")))?;

        // RLS tenant context for the transaction.
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(invitation.tenant_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| ImportError::Internal(format!("Failed to set tenant context: {e}")))?;

        // Atomic single-use guard.
        let status: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM user_invitations WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(invitation.id)
        .bind(invitation.tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        match status {
            Some((s,)) if s == "pending" || s == "sent" => {}
            Some(_) => return Err(ImportError::TokenAlreadyUsed),
            None => return Err(ImportError::InvalidToken),
        }

        let new_user_id = uuid::Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified, email_verified_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, true, true, NOW(), NOW(), NOW())
            ",
        )
        .bind(new_user_id)
        .bind(invitation.tenant_id)
        .bind(email)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await?;

        sqlx::query("INSERT INTO user_roles (user_id, role_name) VALUES ($1, $2)")
            .bind(new_user_id)
            .bind(&invitation.role)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r"
            UPDATE user_invitations
            SET status = 'accepted', accepted_at = NOW(), user_id = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(invitation.id)
        .bind(invitation.tenant_id)
        .bind(new_user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit()
            .await
            .map_err(|e| ImportError::Internal(format!("Failed to commit: {e}")))?;

        tracing::info!(
            user_id = %new_user_id,
            invitation_id = %invitation.id,
            role = %invitation.role,
            "Admin invitation accepted, account created and role assigned"
        );
    }

    Ok(Json(AcceptInvitationResponse {
        success: true,
        message: Some("Account activated successfully. You can now log in.".to_string()),
        redirect_url: Some("/auth/login".to_string()),
    }))
}

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ImportError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ImportError::Unauthorized)
}

/// Hash a token using SHA-256.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Get frontend base URL from environment.
fn get_frontend_base_url() -> String {
    std::env::var("FRONTEND_BASE_URL").unwrap_or_else(|_| "https://app.xavyo.com".to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn accept_creates_user_and_role_for_admin_invitation() {
        // Admin invitations have user_id = NULL (no pre-created user). The accept
        // handler must CREATE the user and assign the invited role for that case —
        // otherwise acceptance silently no-ops (the old UPDATE ... WHERE id = NULL
        // matched zero rows) and the invited user can never log in.
        let src = include_str!("invitations.rs");
        let production = src.split("mod tests").next().expect("production source");
        let accept = production
            .split("pub async fn accept_invitation")
            .nth(1)
            .expect("accept_invitation handler");
        assert!(
            accept.contains("if let Some(existing_user_id) = invitation.user_id"),
            "accept must branch on whether the invitation has a pre-created user"
        );
        assert!(
            accept.contains("INSERT INTO users"),
            "accept must create the user for admin invitations (user_id NULL)"
        );
        assert!(
            accept.contains("INSERT INTO user_roles (user_id, role_name)")
                && accept.contains("&invitation.role"),
            "accept must assign the invited role for admin invitations"
        );
    }
}
