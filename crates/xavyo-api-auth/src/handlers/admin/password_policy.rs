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

/// Get password policy for a tenant.
///
/// GET /admin/tenants/:tenant_id/password-policy
pub async fn get_password_policy(
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Path(tenant_id): Path<Uuid>,
) -> Result<(StatusCode, Json<PasswordPolicyResponse>), ApiAuthError> {
    let policy = password_policy_service
        .get_password_policy(tenant_id)
        .await?;
    Ok((StatusCode::OK, Json(PasswordPolicyResponse::from(policy))))
}

/// Update password policy for a tenant.
///
/// PUT /admin/tenants/:tenant_id/password-policy
pub async fn update_password_policy(
    Extension(password_policy_service): Extension<Arc<PasswordPolicyService>>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<UpdatePasswordPolicyRequest>,
) -> Result<(StatusCode, Json<PasswordPolicyResponse>), ApiAuthError> {
    // Validate request
    request.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .values()
            .flat_map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(|m| m.to_string()))
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
        .update_password_policy(tenant_id, request.into_upsert())
        .await?;

    Ok((StatusCode::OK, Json(PasswordPolicyResponse::from(policy))))
}
