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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/inactivity/detect",
    tag = "NHI Inactivity",
    operation_id = "detectInactiveNhis",
    responses(
        (status = 200, description = "List of inactive NHI entities", body = Vec<InactiveEntity>),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden")
    ),
    security(("bearerAuth" = []))
))]
pub async fn detect_inactive(
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
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/inactivity/grace-period/{id}",
    tag = "NHI Inactivity",
    operation_id = "initiateNhiGracePeriod",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID")
    ),
    request_body = GracePeriodRequest,
    responses(
        (status = 204, description = "Grace period initiated"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "NHI identity not found"),
        (status = 409, description = "Grace period already active")
    ),
    security(("bearerAuth" = []))
))]
pub async fn initiate_grace_period(
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
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/inactivity/auto-suspend",
    tag = "NHI Inactivity",
    operation_id = "autoSuspendNhis",
    responses(
        (status = 200, description = "Auto-suspend results", body = AutoSuspendResult),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden")
    ),
    security(("bearerAuth" = []))
))]
pub async fn auto_suspend(
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
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/orphans/detect",
    tag = "NHI Inactivity",
    operation_id = "detectOrphanNhis",
    responses(
        (status = 200, description = "List of orphaned NHI entities", body = Vec<OrphanEntity>),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden")
    ),
    security(("bearerAuth" = []))
))]
pub async fn detect_orphans(
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
