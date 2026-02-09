//! Session policy handlers (admin).

use axum::{extract::Path, http::StatusCode, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_db::UpsertSessionPolicy;

use crate::{
    error::ApiAuthError,
    models::{SessionPolicyResponse, UpdateSessionPolicyRequest},
    services::SessionService,
};

/// GET /admin/tenants/:id/session-policy
///
/// Get session policy for a tenant (admin only).
pub async fn get_session_policy(
    Extension(claims): Extension<JwtClaims>,
    Extension(session_service): Extension<Arc<SessionService>>,
    Path(tenant_id): Path<Uuid>,
) -> Result<(StatusCode, Json<SessionPolicyResponse>), ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    let caller_tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or_else(|| ApiAuthError::PermissionDenied("Missing tenant_id in claims".to_string()))?;
    if caller_tenant_id != tenant_id {
        return Err(ApiAuthError::PermissionDenied(
            "Cannot access other tenant's session policy".to_string(),
        ));
    }

    let policy = session_service.get_tenant_policy(tenant_id).await?;

    Ok((StatusCode::OK, Json(policy.into())))
}

/// PUT /admin/tenants/:id/session-policy
///
/// Update session policy for a tenant (admin only).
pub async fn update_session_policy(
    Extension(claims): Extension<JwtClaims>,
    Extension(session_service): Extension<Arc<SessionService>>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<UpdateSessionPolicyRequest>,
) -> Result<(StatusCode, Json<SessionPolicyResponse>), ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    let caller_tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or_else(|| ApiAuthError::PermissionDenied("Missing tenant_id in claims".to_string()))?;
    if caller_tenant_id != tenant_id {
        return Err(ApiAuthError::PermissionDenied(
            "Cannot access other tenant's session policy".to_string(),
        ));
    }

    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let upsert_data = UpsertSessionPolicy {
        access_token_ttl_minutes: request.access_token_ttl_minutes,
        refresh_token_ttl_days: request.refresh_token_ttl_days,
        idle_timeout_minutes: request.idle_timeout_minutes,
        absolute_timeout_hours: request.absolute_timeout_hours,
        max_concurrent_sessions: request.max_concurrent_sessions,
        track_device_info: request.track_device_info,
        remember_me_ttl_days: request.remember_me_ttl_days,
    };

    let policy = session_service
        .update_tenant_policy(tenant_id, upsert_data)
        .await?;

    Ok((StatusCode::OK, Json(policy.into())))
}
