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

/// Get lockout policy for a tenant.
///
/// GET /admin/tenants/:tenant_id/lockout-policy
pub async fn get_lockout_policy(
    Extension(lockout_service): Extension<Arc<LockoutService>>,
    Path(tenant_id): Path<Uuid>,
) -> Result<(StatusCode, Json<LockoutPolicyResponse>), ApiAuthError> {
    let policy = lockout_service.get_lockout_policy(tenant_id).await?;
    Ok((StatusCode::OK, Json(LockoutPolicyResponse::from(policy))))
}

/// Update lockout policy for a tenant.
///
/// PUT /admin/tenants/:tenant_id/lockout-policy
pub async fn update_lockout_policy(
    Extension(lockout_service): Extension<Arc<LockoutService>>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<UpdateLockoutPolicyRequest>,
) -> Result<(StatusCode, Json<LockoutPolicyResponse>), ApiAuthError> {
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
            "Invalid lockout policy values".to_string()
        } else {
            errors.join(", ")
        })
    })?;

    let policy = lockout_service
        .update_lockout_policy(tenant_id, request.into_upsert())
        .await?;

    Ok((StatusCode::OK, Json(LockoutPolicyResponse::from(policy))))
}
