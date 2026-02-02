//! Handlers for passwordless policy management endpoints (F079).
//!
//! - GET /auth/passwordless/policy — Get tenant passwordless policy (admin)
//! - PUT /auth/passwordless/policy — Update tenant passwordless policy (admin)
//! - GET /auth/passwordless/methods — Get available methods (public)

use crate::error::ApiAuthError;
use crate::models::{
    AvailableMethodsResponse, PasswordlessPolicyResponse, UpdatePasswordlessPolicyRequest,
};
use axum::{Extension, Json};
use sqlx::PgPool;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::{EnabledMethods, PasswordlessPolicy};

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<uuid::Uuid, ApiAuthError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAuthError::Unauthorized)
}

/// Check if the user has admin role.
fn require_admin(claims: &JwtClaims) -> Result<(), ApiAuthError> {
    if claims
        .roles
        .iter()
        .any(|r| r == "admin" || r == "super_admin")
    {
        Ok(())
    } else {
        Err(ApiAuthError::PermissionDenied(
            "Admin role required to manage passwordless policy.".to_string(),
        ))
    }
}

/// GET /auth/passwordless/policy
///
/// Get the current passwordless policy for the tenant.
/// Requires admin role.
#[utoipa::path(
    get,
    path = "/auth/passwordless/policy",
    responses(
        (status = 200, description = "Passwordless policy", body = PasswordlessPolicyResponse),
        (status = 403, description = "Admin role required"),
    ),
    tag = "Passwordless Policy"
)]
pub async fn get_passwordless_policy_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<PasswordlessPolicyResponse>, ApiAuthError> {
    require_admin(&claims)?;
    let tenant_id = extract_tenant_id(&claims)?;

    let policy = PasswordlessPolicy::get_or_default(&pool, tenant_id)
        .await
        .map_err(|e| ApiAuthError::Internal(format!("Failed to get policy: {e}")))?;

    Ok(Json(PasswordlessPolicyResponse::from(policy)))
}

/// PUT /auth/passwordless/policy
///
/// Create or update the passwordless policy for the tenant.
/// Requires admin role.
#[utoipa::path(
    put,
    path = "/auth/passwordless/policy",
    request_body = UpdatePasswordlessPolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = PasswordlessPolicyResponse),
        (status = 403, description = "Admin role required"),
        (status = 422, description = "Validation error"),
    ),
    tag = "Passwordless Policy"
)]
pub async fn update_passwordless_policy_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Json(body): Json<UpdatePasswordlessPolicyRequest>,
) -> Result<Json<PasswordlessPolicyResponse>, ApiAuthError> {
    require_admin(&claims)?;
    let tenant_id = extract_tenant_id(&claims)?;

    body.validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    // Validate enabled_methods is a valid value
    if EnabledMethods::parse(&body.enabled_methods).is_none() {
        return Err(ApiAuthError::Validation(format!(
            "Invalid enabled_methods value: '{}'. Valid values: disabled, magic_link_only, otp_only, all_methods",
            body.enabled_methods
        )));
    }

    let policy = PasswordlessPolicy::upsert(
        &pool,
        tenant_id,
        &body.enabled_methods,
        body.magic_link_expiry_minutes,
        body.otp_expiry_minutes,
        body.otp_max_attempts,
        body.require_mfa_after_passwordless,
    )
    .await
    .map_err(|e| ApiAuthError::Internal(format!("Failed to update policy: {e}")))?;

    Ok(Json(PasswordlessPolicyResponse::from(policy)))
}

/// GET /auth/passwordless/methods
///
/// Get available passwordless methods for the tenant.
/// This is a public endpoint (no authentication required).
#[utoipa::path(
    get,
    path = "/auth/passwordless/methods",
    responses(
        (status = 200, description = "Available methods", body = AvailableMethodsResponse),
    ),
    tag = "Passwordless Authentication"
)]
pub async fn get_available_methods_handler(
    Extension(tid): Extension<TenantId>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<AvailableMethodsResponse>, ApiAuthError> {
    let tenant_id = *tid.as_uuid();

    let policy = PasswordlessPolicy::get_or_default(&pool, tenant_id)
        .await
        .map_err(|e| ApiAuthError::Internal(format!("Failed to get policy: {e}")))?;

    Ok(Json(AvailableMethodsResponse {
        magic_link: policy.magic_link_enabled(),
        email_otp: policy.email_otp_enabled(),
    }))
}
