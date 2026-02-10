//! User unlock admin handler.
//!
//! POST /`admin/users/:user_id/unlock`

use crate::error::ApiAuthError;
use crate::models::UnlockUserResponse;
use crate::services::LockoutService;
use axum::http::StatusCode;
use axum::{extract::Path, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

/// Unlock a user account (admin action).
///
/// POST /`admin/users/:user_id/unlock`
#[utoipa::path(
    post,
    path = "/admin/users/{id}/unlock",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User unlocked", body = UnlockUserResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    ),
    tag = "Admin - Lockout Policy"
)]
pub async fn unlock_user(
    Extension(claims): Extension<JwtClaims>,
    Extension(lockout_service): Extension<Arc<LockoutService>>,
    Extension(tenant_id): Extension<TenantId>,
    Path(user_id): Path<Uuid>,
) -> Result<(StatusCode, Json<UnlockUserResponse>), ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    let was_locked = lockout_service
        .unlock_user(user_id, *tenant_id.as_uuid())
        .await?;

    let response = if was_locked {
        UnlockUserResponse::unlocked(user_id)
    } else {
        UnlockUserResponse::not_locked(user_id)
    };

    Ok((StatusCode::OK, Json(response)))
}
