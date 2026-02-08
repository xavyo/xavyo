//! Inactivity detection and orphan management handlers.
//!
//! Provides endpoints for NHI inactivity management:
//! - `GET /inactivity/detect` — Detect inactive entities
//! - `POST /inactivity/grace-period/{id}` — Initiate grace period
//! - `POST /inactivity/auto-suspend` — Auto-suspend expired grace periods
//! - `GET /orphans/detect` — Detect orphaned entities

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::NhiApiError;
use crate::services::nhi_inactivity_service::NhiInactivityService;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Request body for initiating a grace period.
#[derive(Debug, Deserialize)]
pub struct GracePeriodRequest {
    pub grace_days: i32,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /inactivity/detect — Detect inactive NHI entities.
///
/// Returns entities that have exceeded their configured inactivity threshold
/// but do not yet have a grace period set.
async fn detect_inactive(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let entities = NhiInactivityService::detect_inactive(&state.pool, tenant_uuid).await?;

    Ok(Json(entities))
}

/// POST /inactivity/grace-period/{id} — Initiate a grace period for an entity.
///
/// Sets a deadline after which the entity will be auto-suspended if still inactive.
async fn initiate_grace_period(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<GracePeriodRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    NhiInactivityService::initiate_grace_period(&state.pool, tenant_uuid, id, request.grace_days)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /inactivity/auto-suspend — Auto-suspend entities with expired grace periods.
///
/// Admin-only endpoint that finds all entities with expired grace periods
/// and transitions them to suspended state.
async fn auto_suspend(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let result = NhiInactivityService::auto_suspend_expired(&state.pool, tenant_uuid).await?;

    Ok(Json(result))
}

/// GET /orphans/detect — Detect orphaned NHI entities.
///
/// Returns active entities whose owner is missing, deleted, or inactive,
/// and that have no backup owner configured.
async fn detect_orphans(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let entities = NhiInactivityService::detect_orphans(&state.pool, tenant_uuid).await?;

    Ok(Json(entities))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn inactivity_routes(state: NhiState) -> Router {
    Router::new()
        .route("/inactivity/detect", get(detect_inactive))
        .route("/inactivity/grace-period/:id", post(initiate_grace_period))
        .route("/inactivity/auto-suspend", post(auto_suspend))
        .route("/orphans/detect", get(detect_orphans))
        .with_state(state)
}
