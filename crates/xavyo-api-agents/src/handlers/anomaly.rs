//! HTTP handlers for the Behavioral Anomaly Detection API (F094).
//!
//! Provides endpoints for listing anomalies, managing baselines, and configuring thresholds.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::ApiAgentsError;
use crate::models::anomaly_models::{
    AnomalyListResponse, BaselineResponse, ListAnomaliesQuery, SetThresholdsRequest,
    ThresholdsResponse,
};
use crate::router::AgentsState;
use crate::services::{AnomalyService, BaselineService};

/// State for anomaly handlers (used for nested router if needed).
#[derive(Clone)]
pub struct AnomalyState {
    pub anomaly_service: AnomalyService,
    pub baseline_service: BaselineService,
}

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenantId)
}

/// GET /`agents/{agent_id}/anomalies`
///
/// List detected anomalies for an agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{agent_id}/anomalies",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID"),
        ("since" = Option<String>, Query, description = "Filter anomalies since this timestamp"),
        ("anomaly_type" = Option<String>, Query, description = "Filter by anomaly type"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("limit" = Option<i64>, Query, description = "Max results (default 50)"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "List of anomalies", body = AnomalyListResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearer" = [])),
    tag = "Behavioral Anomaly Detection"
))]
pub async fn list_agent_anomalies(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<ListAnomaliesQuery>,
) -> Result<Json<AnomalyListResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .anomaly_service
        .list_anomalies(tenant_id, agent_id, &query)
        .await?;
    Ok(Json(response))
}

/// GET /`agents/{agent_id}/baseline`
///
/// Get the current behavioral baseline for an agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{agent_id}/baseline",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent baseline", body = BaselineResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearer" = [])),
    tag = "Behavioral Anomaly Detection"
))]
pub async fn get_agent_baseline(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<BaselineResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .baseline_service
        .get_baseline(tenant_id, agent_id)
        .await?;
    Ok(Json(response))
}

/// GET /`agents/{agent_id}/thresholds`
///
/// Get anomaly detection thresholds for an agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{agent_id}/thresholds",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent thresholds", body = ThresholdsResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearer" = [])),
    tag = "Behavioral Anomaly Detection"
))]
pub async fn get_agent_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<ThresholdsResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .anomaly_service
        .get_agent_thresholds(tenant_id, agent_id)
        .await?;
    Ok(Json(response))
}

/// PUT /`agents/{agent_id}/thresholds`
///
/// Set anomaly detection thresholds for an agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/agents/{agent_id}/thresholds",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = SetThresholdsRequest,
    responses(
        (status = 200, description = "Thresholds updated", body = ThresholdsResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearer" = [])),
    tag = "Behavioral Anomaly Detection"
))]
pub async fn set_agent_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<SetThresholdsRequest>,
) -> Result<Json<ThresholdsResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .anomaly_service
        .set_agent_thresholds(tenant_id, agent_id, request)
        .await?;
    Ok(Json(response))
}

/// DELETE /`agents/{agent_id}/thresholds`
///
/// Reset agent thresholds to tenant defaults.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/agents/{agent_id}/thresholds",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Thresholds reset to tenant defaults", body = ThresholdsResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearer" = [])),
    tag = "Behavioral Anomaly Detection"
))]
pub async fn reset_agent_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<ThresholdsResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .anomaly_service
        .reset_agent_thresholds(tenant_id, agent_id)
        .await?;
    Ok(Json(response))
}

/// GET /agents/thresholds
///
/// Get tenant-wide default anomaly detection thresholds.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/thresholds",
    responses(
        (status = 200, description = "Tenant default thresholds", body = ThresholdsResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearer" = [])),
    tag = "Behavioral Anomaly Detection"
))]
pub async fn get_tenant_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<ThresholdsResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .anomaly_service
        .get_tenant_thresholds(tenant_id)
        .await?;
    Ok(Json(response))
}

/// PUT /agents/thresholds
///
/// Set tenant-wide default anomaly detection thresholds.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    path = "/agents/thresholds",
    request_body = SetThresholdsRequest,
    responses(
        (status = 200, description = "Tenant thresholds updated", body = ThresholdsResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearer" = [])),
    tag = "Behavioral Anomaly Detection"
))]
pub async fn set_tenant_thresholds(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<SetThresholdsRequest>,
) -> Result<Json<ThresholdsResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let response = state
        .anomaly_service
        .set_tenant_thresholds(tenant_id, request)
        .await?;
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    // Integration tests will be in tests/anomaly_test.rs
}
