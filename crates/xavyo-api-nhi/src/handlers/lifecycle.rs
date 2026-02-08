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
use crate::state::NhiState;

/// Request body for the suspend endpoint.
#[derive(Debug, Deserialize)]
pub struct SuspendRequest {
    pub reason: Option<String>,
}

/// POST /nhi/{id}/suspend — Suspend an NHI identity.
pub async fn suspend(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    body: Option<Json<SuspendRequest>>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();
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
pub async fn reactivate(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

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
pub async fn deprecate(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

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
/// This cascade-revokes all tool permissions and deactivates all credentials.
pub async fn archive(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

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
pub async fn deactivate(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

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
pub async fn activate(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

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
