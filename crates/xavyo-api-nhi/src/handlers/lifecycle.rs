//! NHI lifecycle transition handlers.
//!
//! Provides endpoints for lifecycle state changes:
//! - `POST /nhi/{id}/suspend` — Suspend an NHI
//! - `POST /nhi/{id}/reactivate` — Reactivate a suspended NHI
//! - `POST /nhi/{id}/deprecate` — Mark an NHI as deprecated
//! - `POST /nhi/{id}/archive` — Archive a deprecated NHI
//! - `POST /nhi/{id}/deactivate` — Deactivate an active NHI
//! - `POST /nhi/{id}/activate` — Activate an inactive NHI

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Extension, Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_nhi::NhiLifecycleState;

use crate::error::NhiApiError;
use crate::services::nhi_lifecycle_service::NhiLifecycleService;
use crate::services::nhi_user_permission_service::NhiUserPermissionService;
use crate::state::NhiState;

/// Request body for the suspend endpoint.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SuspendRequest {
    pub reason: Option<String>,
}

/// POST /nhi/{id}/suspend — Suspend an NHI identity.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/suspend",
    tag = "NHI Lifecycle",
    operation_id = "suspendNhi",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID")
    ),
    request_body = SuspendRequest,
    responses(
        (status = 200, description = "NHI suspended successfully", body = NhiIdentity),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI identity not found"),
        (status = 409, description = "Invalid lifecycle transition")
    ),
    security(("bearerAuth" = []))
))]
pub async fn suspend(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    body: Option<Json<SuspendRequest>>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, id, "manage")
        .await?;
    let reason = body.and_then(|b| b.0.reason);

    let updated = NhiLifecycleService::transition(
        &state.pool,
        tenant_uuid,
        id,
        NhiLifecycleState::Suspended,
        reason,
    )
    .await?;

    Ok((StatusCode::OK, Json(updated)))
}

/// POST /nhi/{id}/reactivate — Reactivate a suspended NHI identity.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/reactivate",
    tag = "NHI Lifecycle",
    operation_id = "reactivateNhi",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID")
    ),
    responses(
        (status = 200, description = "NHI reactivated successfully", body = NhiIdentity),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI identity not found"),
        (status = 409, description = "Invalid lifecycle transition")
    ),
    security(("bearerAuth" = []))
))]
pub async fn reactivate(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, id, "manage")
        .await?;

    let updated = NhiLifecycleService::transition(
        &state.pool,
        tenant_uuid,
        id,
        NhiLifecycleState::Active,
        None,
    )
    .await?;

    Ok((StatusCode::OK, Json(updated)))
}

/// POST /nhi/{id}/deprecate — Mark an NHI identity as deprecated.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/deprecate",
    tag = "NHI Lifecycle",
    operation_id = "deprecateNhi",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID")
    ),
    responses(
        (status = 200, description = "NHI deprecated successfully", body = NhiIdentity),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI identity not found"),
        (status = 409, description = "Invalid lifecycle transition")
    ),
    security(("bearerAuth" = []))
))]
pub async fn deprecate(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, id, "manage")
        .await?;

    let updated = NhiLifecycleService::transition(
        &state.pool,
        tenant_uuid,
        id,
        NhiLifecycleState::Deprecated,
        None,
    )
    .await?;

    Ok((StatusCode::OK, Json(updated)))
}

/// POST /nhi/{id}/archive — Archive a deprecated NHI identity (terminal).
///
/// This cascade-revokes all tool permissions.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/archive",
    tag = "NHI Lifecycle",
    operation_id = "archiveNhi",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID")
    ),
    responses(
        (status = 200, description = "NHI archived successfully", body = NhiIdentity),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI identity not found"),
        (status = 409, description = "Invalid lifecycle transition")
    ),
    security(("bearerAuth" = []))
))]
pub async fn archive(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, id, "manage")
        .await?;

    let updated = NhiLifecycleService::transition(
        &state.pool,
        tenant_uuid,
        id,
        NhiLifecycleState::Archived,
        None,
    )
    .await?;

    Ok((StatusCode::OK, Json(updated)))
}

/// POST /nhi/{id}/deactivate — Deactivate an active NHI identity.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/deactivate",
    tag = "NHI Lifecycle",
    operation_id = "deactivateNhi",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID")
    ),
    responses(
        (status = 200, description = "NHI deactivated successfully", body = NhiIdentity),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI identity not found"),
        (status = 409, description = "Invalid lifecycle transition")
    ),
    security(("bearerAuth" = []))
))]
pub async fn deactivate(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, id, "manage")
        .await?;

    let updated = NhiLifecycleService::transition(
        &state.pool,
        tenant_uuid,
        id,
        NhiLifecycleState::Inactive,
        None,
    )
    .await?;

    Ok((StatusCode::OK, Json(updated)))
}

/// POST /nhi/{id}/activate — Activate an inactive NHI identity.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/{id}/activate",
    tag = "NHI Lifecycle",
    operation_id = "activateNhi",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID")
    ),
    responses(
        (status = 200, description = "NHI activated successfully", body = NhiIdentity),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI identity not found"),
        (status = 409, description = "Invalid lifecycle transition")
    ),
    security(("bearerAuth" = []))
))]
pub async fn activate(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, id, "manage")
        .await?;

    let updated = NhiLifecycleService::transition(
        &state.pool,
        tenant_uuid,
        id,
        NhiLifecycleState::Active,
        None,
    )
    .await?;

    Ok((StatusCode::OK, Json(updated)))
}

/// Creates the lifecycle routes sub-router.
///
/// Routes:
/// - `POST /:id/suspend`
/// - `POST /:id/reactivate`
/// - `POST /:id/deprecate`
/// - `POST /:id/archive`
/// - `POST /:id/deactivate`
/// - `POST /:id/activate`
pub fn lifecycle_routes(state: NhiState) -> Router {
    Router::new()
        .route("/:id/suspend", post(suspend))
        .route("/:id/reactivate", post(reactivate))
        .route("/:id/deprecate", post(deprecate))
        .route("/:id/archive", post(archive))
        .route("/:id/deactivate", post(deactivate))
        .route("/:id/activate", post(activate))
        .with_state(state)
}
