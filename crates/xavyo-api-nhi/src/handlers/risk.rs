//! Risk scoring and inactivity detection handlers.
//!
//! Provides endpoints for NHI risk management:
//! - `GET /nhi/{id}/risk` — Compute and return risk breakdown for a specific NHI
//! - `GET /nhi/risk-summary` — Aggregate risk summary for tenant

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
    Extension, Json, Router,
};
use uuid::Uuid;
use xavyo_core::TenantId;

use crate::error::NhiApiError;
use crate::services::nhi_risk_service::NhiRiskService;
use crate::state::NhiState;

/// GET /{id}/risk — Compute and return risk breakdown for a specific NHI.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/{id}/risk",
    tag = "NHI Risk",
    operation_id = "getNhiRisk",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID")
    ),
    responses(
        (status = 200, description = "Risk breakdown computed", body = RiskBreakdown),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "NHI identity not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_risk(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let breakdown = NhiRiskService::compute(&state.pool, tenant_uuid, id).await?;
    Ok(Json(breakdown))
}

/// GET /risk-summary — Aggregate risk summary for tenant.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/risk-summary",
    tag = "NHI Risk",
    operation_id = "getNhiRiskSummary",
    responses(
        (status = 200, description = "Aggregate risk summary", body = RiskSummary),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_risk_summary(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let summary = NhiRiskService::summary(&state.pool, tenant_uuid).await?;
    Ok(Json(summary))
}

/// Creates the risk routes sub-router.
///
/// Routes:
/// - `GET /:id/risk`
/// - `GET /risk-summary`
pub fn risk_routes(state: NhiState) -> Router {
    Router::new()
        .route("/risk-summary", get(get_risk_summary))
        .route("/:id/risk", get(get_risk))
        .with_state(state)
}
