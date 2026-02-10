//! Password policy admin handlers.
//!
//! GET/PUT /admin/tenants/:tenant_id/password-policy

use crate::error::ApiAuthError;
use crate::models::{PasswordPolicyResponse, UpdatePasswordPolicyRequest};
use crate::services::PasswordPolicyService;
use axum::http::StatusCode;
use axum::{extract::Path, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

/// Get password policy for a tenant.
///
/// GET /admin/tenants/:tenant_id/password-policy
#[utoipa::path(
    get,
    path = "/admin/tenants/{id}/password-policy",
    params(
        ("id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Password policy retrieved", body = PasswordPolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot access other tenant's policy"),
    ),
    tag = "Admin - Password Policy"
)]
pub async fn get_password_policy(
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Extension(tenant_id): Extension<TenantId>,
    Path(path_tenant_id): Path<Uuid>,
) -> Result<(StatusCode, Json<PasswordPolicyResponse>), ApiAuthError> {
    if *tenant_id.as_uuid() != path_tenant_id {
        return Err(ApiAuthError::PermissionDenied(
            "Cannot access other tenant's policy".to_string(),
        ));
    }
    let policy = password_policy_service
        .get_password_policy(path_tenant_id)
        .await?;
    Ok((StatusCode::OK, Json(PasswordPolicyResponse::from(policy))))
}

/// Update password policy for a tenant.
///
/// PUT /admin/tenants/:tenant_id/password-policy
#[utoipa::path(
    put,
    path = "/admin/tenants/{id}/password-policy",
    params(
        ("id" = Uuid, Path, description = "Tenant ID"),
    ),
    request_body = UpdatePasswordPolicyRequest,
    responses(
        (status = 200, description = "Password policy updated", body = PasswordPolicyResponse),
        (status = 400, description = "Invalid policy values"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    ),
    tag = "Admin - Password Policy"
)]
pub async fn update_password_policy(
    Extension(claims): Extension<JwtClaims>,
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Extension(tenant_id): Extension<TenantId>,
    Path(path_tenant_id): Path<Uuid>,
    Json(request): Json<UpdatePasswordPolicyRequest>,
) -> Result<(StatusCode, Json<PasswordPolicyResponse>), ApiAuthError> {
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
            "Invalid password policy values".to_string()
        } else {
            errors.join(", ")
        })
    })?;

    // Additional validation: max_length >= min_length
    if let (Some(min), Some(max)) = (request.min_length, request.max_length) {
        if max < min {
            return Err(ApiAuthError::Validation(
                "max_length must be greater than or equal to min_length".to_string(),
            ));
        }
    }

    let policy = password_policy_service
        .update_password_policy(path_tenant_id, request.into_upsert())
        .await?;

    Ok((StatusCode::OK, Json(PasswordPolicyResponse::from(policy))))
}
