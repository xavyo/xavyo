//! Risk threshold handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateRiskThresholdRequest, ListRiskThresholdsQuery, RiskThresholdListResponse,
    RiskThresholdResponse, UpdateRiskThresholdRequest,
};
use crate::router::GovernanceState;

/// List all risk thresholds with filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/risk-thresholds",
    tag = "Governance - Risk Thresholds",
    params(ListRiskThresholdsQuery),
    responses(
        (status = 200, description = "List of risk thresholds", body = RiskThresholdListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_risk_thresholds(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListRiskThresholdsQuery>,
) -> ApiResult<Json<RiskThresholdListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state.risk_threshold_service.list(tenant_id, query).await?;

    Ok(Json(response))
}

/// Create a new risk threshold.
#[utoipa::path(
    post,
    path = "/governance/risk-thresholds",
    tag = "Governance - Risk Thresholds",
    request_body = CreateRiskThresholdRequest,
    responses(
        (status = 201, description = "Risk threshold created", body = RiskThresholdResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Threshold with name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_risk_threshold(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateRiskThresholdRequest>,
) -> ApiResult<(StatusCode, Json<RiskThresholdResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let threshold = state
        .risk_threshold_service
        .create(tenant_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(threshold)))
}

/// Get a risk threshold by ID.
#[utoipa::path(
    get,
    path = "/governance/risk-thresholds/{threshold_id}",
    tag = "Governance - Risk Thresholds",
    params(
        ("threshold_id" = Uuid, Path, description = "Threshold ID")
    ),
    responses(
        (status = 200, description = "Risk threshold details", body = RiskThresholdResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threshold not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_risk_threshold(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(threshold_id): Path<Uuid>,
) -> ApiResult<Json<RiskThresholdResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let threshold = state
        .risk_threshold_service
        .get(tenant_id, threshold_id)
        .await?;

    Ok(Json(threshold))
}

/// Update a risk threshold.
#[utoipa::path(
    put,
    path = "/governance/risk-thresholds/{threshold_id}",
    tag = "Governance - Risk Thresholds",
    params(
        ("threshold_id" = Uuid, Path, description = "Threshold ID")
    ),
    request_body = UpdateRiskThresholdRequest,
    responses(
        (status = 200, description = "Risk threshold updated", body = RiskThresholdResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threshold not found"),
        (status = 409, description = "Threshold with name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_risk_threshold(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(threshold_id): Path<Uuid>,
    Json(request): Json<UpdateRiskThresholdRequest>,
) -> ApiResult<Json<RiskThresholdResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let threshold = state
        .risk_threshold_service
        .update(tenant_id, threshold_id, request)
        .await?;

    Ok(Json(threshold))
}

/// Delete a risk threshold.
#[utoipa::path(
    delete,
    path = "/governance/risk-thresholds/{threshold_id}",
    tag = "Governance - Risk Thresholds",
    params(
        ("threshold_id" = Uuid, Path, description = "Threshold ID")
    ),
    responses(
        (status = 204, description = "Threshold deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threshold not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_risk_threshold(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(threshold_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .risk_threshold_service
        .delete(tenant_id, threshold_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable a risk threshold.
#[utoipa::path(
    post,
    path = "/governance/risk-thresholds/{threshold_id}/enable",
    tag = "Governance - Risk Thresholds",
    params(
        ("threshold_id" = Uuid, Path, description = "Threshold ID")
    ),
    responses(
        (status = 200, description = "Threshold enabled", body = RiskThresholdResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threshold not found or already enabled"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_risk_threshold(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(threshold_id): Path<Uuid>,
) -> ApiResult<Json<RiskThresholdResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let threshold = state
        .risk_threshold_service
        .enable(tenant_id, threshold_id)
        .await?;

    Ok(Json(threshold))
}

/// Disable a risk threshold.
#[utoipa::path(
    post,
    path = "/governance/risk-thresholds/{threshold_id}/disable",
    tag = "Governance - Risk Thresholds",
    params(
        ("threshold_id" = Uuid, Path, description = "Threshold ID")
    ),
    responses(
        (status = 200, description = "Threshold disabled", body = RiskThresholdResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threshold not found or already disabled"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_risk_threshold(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(threshold_id): Path<Uuid>,
) -> ApiResult<Json<RiskThresholdResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let threshold = state
        .risk_threshold_service
        .disable(tenant_id, threshold_id)
        .await?;

    Ok(Json(threshold))
}
