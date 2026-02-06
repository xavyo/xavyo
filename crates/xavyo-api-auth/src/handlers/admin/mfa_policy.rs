//! MFA policy management handlers.
//!
//! Endpoints for managing tenant MFA policy (disabled, optional, required).

use axum::{extract::Path, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::info;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::{MfaPolicy, TenantMfaPolicy};

use crate::error::ApiAuthError;

/// Response for MFA policy endpoints.
#[derive(Debug, Serialize)]
pub struct MfaPolicyResponse {
    pub tenant_id: uuid::Uuid,
    pub mfa_policy: MfaPolicy,
}

/// Request to update MFA policy.
#[derive(Debug, Deserialize)]
pub struct UpdateMfaPolicyRequest {
    pub mfa_policy: MfaPolicy,
}

/// GET /admin/tenants/:tenant_id/mfa-policy
///
/// Get the MFA policy for a tenant.
pub async fn get_mfa_policy(
    Extension(pool): Extension<PgPool>,
    Extension(tenant_id): Extension<TenantId>,
    Path(path_tenant_id): Path<uuid::Uuid>,
) -> Result<(StatusCode, Json<MfaPolicyResponse>), ApiAuthError> {
    if *tenant_id.as_uuid() != path_tenant_id {
        return Err(ApiAuthError::PermissionDenied(
            "Cannot access other tenant's policy".to_string(),
        ));
    }

    // Get MFA policy
    let policy = TenantMfaPolicy::get(&pool, path_tenant_id)
        .await
        .map_err(ApiAuthError::Database)?;

    Ok((
        StatusCode::OK,
        Json(MfaPolicyResponse {
            tenant_id: policy.tenant_id,
            mfa_policy: policy.mfa_policy,
        }),
    ))
}

/// PUT /admin/tenants/:tenant_id/mfa-policy
///
/// Update the MFA policy for a tenant.
pub async fn update_mfa_policy(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Extension(tenant_id): Extension<TenantId>,
    Path(path_tenant_id): Path<uuid::Uuid>,
    Json(request): Json<UpdateMfaPolicyRequest>,
) -> Result<(StatusCode, Json<MfaPolicyResponse>), ApiAuthError> {
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

    // Update MFA policy
    let policy = TenantMfaPolicy::update(&pool, path_tenant_id, request.mfa_policy)
        .await
        .map_err(ApiAuthError::Database)?;

    info!(
        tenant_id = %path_tenant_id,
        mfa_policy = %policy.mfa_policy,
        updated_by = %claims.sub,
        "MFA policy updated"
    );

    Ok((
        StatusCode::OK,
        Json(MfaPolicyResponse {
            tenant_id: policy.tenant_id,
            mfa_policy: policy.mfa_policy,
        }),
    ))
}
