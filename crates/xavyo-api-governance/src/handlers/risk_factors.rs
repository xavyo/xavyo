//! Risk factor handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateRiskFactorRequest, ListRiskFactorsQuery, RiskFactorListResponse, RiskFactorResponse,
    UpdateRiskFactorRequest,
};
use crate::router::GovernanceState;

/// List all risk factors with filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/risk-factors",
    tag = "Governance - Risk Factors",
    params(ListRiskFactorsQuery),
    responses(
        (status = 200, description = "List of risk factors", body = RiskFactorListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_risk_factors(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListRiskFactorsQuery>,
) -> ApiResult<Json<RiskFactorListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state.risk_factor_service.list(tenant_id, query).await?;

    Ok(Json(response))
}

/// Create a new risk factor.
#[utoipa::path(
    post,
    path = "/governance/risk-factors",
    tag = "Governance - Risk Factors",
    request_body = CreateRiskFactorRequest,
    responses(
        (status = 201, description = "Risk factor created", body = RiskFactorResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Conflict - factor type already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_risk_factor(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateRiskFactorRequest>,
) -> ApiResult<(StatusCode, Json<RiskFactorResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let factor = state.risk_factor_service.create(tenant_id, request).await?;

    Ok((StatusCode::CREATED, Json(factor)))
}

/// Get a risk factor by ID.
#[utoipa::path(
    get,
    path = "/governance/risk-factors/{factor_id}",
    tag = "Governance - Risk Factors",
    params(
        ("factor_id" = Uuid, Path, description = "Risk factor ID")
    ),
    responses(
        (status = 200, description = "Risk factor details", body = RiskFactorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk factor not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_risk_factor(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(factor_id): Path<Uuid>,
) -> ApiResult<Json<RiskFactorResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let factor = state.risk_factor_service.get(tenant_id, factor_id).await?;

    Ok(Json(factor))
}

/// Update a risk factor.
#[utoipa::path(
    put,
    path = "/governance/risk-factors/{factor_id}",
    tag = "Governance - Risk Factors",
    params(
        ("factor_id" = Uuid, Path, description = "Risk factor ID")
    ),
    request_body = UpdateRiskFactorRequest,
    responses(
        (status = 200, description = "Risk factor updated", body = RiskFactorResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk factor not found"),
        (status = 409, description = "Conflict - factor type already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_risk_factor(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(factor_id): Path<Uuid>,
    Json(request): Json<UpdateRiskFactorRequest>,
) -> ApiResult<Json<RiskFactorResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let factor = state
        .risk_factor_service
        .update(tenant_id, factor_id, request)
        .await?;

    Ok(Json(factor))
}

/// Delete a risk factor.
#[utoipa::path(
    delete,
    path = "/governance/risk-factors/{factor_id}",
    tag = "Governance - Risk Factors",
    params(
        ("factor_id" = Uuid, Path, description = "Risk factor ID")
    ),
    responses(
        (status = 204, description = "Risk factor deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk factor not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_risk_factor(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(factor_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .risk_factor_service
        .delete(tenant_id, factor_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable a risk factor.
#[utoipa::path(
    post,
    path = "/governance/risk-factors/{factor_id}/enable",
    tag = "Governance - Risk Factors",
    params(
        ("factor_id" = Uuid, Path, description = "Risk factor ID")
    ),
    responses(
        (status = 200, description = "Risk factor enabled", body = RiskFactorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk factor not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_risk_factor(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(factor_id): Path<Uuid>,
) -> ApiResult<Json<RiskFactorResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let factor = state
        .risk_factor_service
        .enable(tenant_id, factor_id)
        .await?;

    Ok(Json(factor))
}

/// Disable a risk factor.
#[utoipa::path(
    post,
    path = "/governance/risk-factors/{factor_id}/disable",
    tag = "Governance - Risk Factors",
    params(
        ("factor_id" = Uuid, Path, description = "Risk factor ID")
    ),
    responses(
        (status = 200, description = "Risk factor disabled", body = RiskFactorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk factor not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_risk_factor(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(factor_id): Path<Uuid>,
) -> ApiResult<Json<RiskFactorResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let factor = state
        .risk_factor_service
        .disable(tenant_id, factor_id)
        .await?;

    Ok(Json(factor))
}
