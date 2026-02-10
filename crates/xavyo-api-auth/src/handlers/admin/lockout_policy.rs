//! Lockout policy admin handlers.
//!
//! GET/PUT /admin/tenants/:tenant_id/lockout-policy

use crate::error::ApiAuthError;
use crate::models::{LockoutPolicyResponse, UpdateLockoutPolicyRequest};
use crate::services::LockoutService;
use axum::http::StatusCode;
use axum::{extract::Path, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

/// Get lockout policy for a tenant.
///
/// GET /admin/tenants/:tenant_id/lockout-policy
#[utoipa::path(
    get,
    path = "/admin/tenants/{id}/lockout-policy",
    params(
        ("id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Lockout policy retrieved", body = LockoutPolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot access other tenant's policy"),
    ),
    tag = "Admin - Lockout Policy"
)]
pub async fn get_lockout_policy(
    Extension(lockout_service): Extension<Arc<LockoutService>>,
    Extension(tenant_id): Extension<TenantId>,
    Path(path_tenant_id): Path<Uuid>,
) -> Result<(StatusCode, Json<LockoutPolicyResponse>), ApiAuthError> {
    if *tenant_id.as_uuid() != path_tenant_id {
        return Err(ApiAuthError::PermissionDenied(
            "Cannot access other tenant's policy".to_string(),
        ));
    }
    let policy = lockout_service.get_lockout_policy(path_tenant_id).await?;
    Ok((StatusCode::OK, Json(LockoutPolicyResponse::from(policy))))
}

/// Update lockout policy for a tenant.
///
/// PUT /admin/tenants/:tenant_id/lockout-policy
#[utoipa::path(
    put,
    path = "/admin/tenants/{id}/lockout-policy",
    params(
        ("id" = Uuid, Path, description = "Tenant ID"),
    ),
    request_body = UpdateLockoutPolicyRequest,
    responses(
        (status = 200, description = "Lockout policy updated", body = LockoutPolicyResponse),
        (status = 400, description = "Invalid policy values"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    ),
    tag = "Admin - Lockout Policy"
)]
pub async fn update_lockout_policy(
    Extension(claims): Extension<JwtClaims>,
    Extension(lockout_service): Extension<Arc<LockoutService>>,
    Extension(tenant_id): Extension<TenantId>,
    Path(path_tenant_id): Path<Uuid>,
    Json(request): Json<UpdateLockoutPolicyRequest>,
) -> Result<(StatusCode, Json<LockoutPolicyResponse>), ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    if *tenant_id.as_uuid() != path_tenant_id {
        return Err(ApiAuthError::PermissionDenied(
            "Cannot access other tenant's policy".to_string(),
        ));
    }
    // Validate request
    request.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .values()
            .flat_map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(std::string::ToString::to_string))
            })
            .collect();
        ApiAuthError::Validation(if errors.is_empty() {
            "Invalid lockout policy values".to_string()
        } else {
            errors.join(", ")
        })
    })?;

    let policy = lockout_service
        .update_lockout_policy(path_tenant_id, request.into_upsert())
        .await?;

    Ok((StatusCode::OK, Json(LockoutPolicyResponse::from(policy))))
}
