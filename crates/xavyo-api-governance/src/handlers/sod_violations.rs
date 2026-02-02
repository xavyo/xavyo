//! SoD violation handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ListSodViolationsQuery, RemediateViolationRequest, ScanRuleResponse, SodViolationListResponse,
    SodViolationResponse,
};
use crate::router::GovernanceState;
use crate::services::SodViolationService;

/// List SoD violations with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/sod-violations",
    tag = "Governance - SoD Violations",
    params(ListSodViolationsQuery),
    responses(
        (status = 200, description = "List of SoD violations", body = SodViolationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_violations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSodViolationsQuery>,
) -> ApiResult<Json<SodViolationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (violations, total) = state
        .sod_violation_service
        .list_violations(
            tenant_id,
            query.rule_id,
            query.user_id,
            query.status,
            query.detected_after,
            query.detected_before,
            limit,
            offset,
        )
        .await?;

    Ok(Json(SodViolationListResponse {
        items: violations
            .iter()
            .map(SodViolationService::to_api_response)
            .collect(),
        total,
        limit,
        offset,
    }))
}

/// Get an SoD violation by ID.
#[utoipa::path(
    get,
    path = "/governance/sod-violations/{id}",
    tag = "Governance - SoD Violations",
    params(
        ("id" = Uuid, Path, description = "SoD Violation ID")
    ),
    responses(
        (status = 200, description = "SoD violation details", body = SodViolationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD violation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_violation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SodViolationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let violation = state
        .sod_violation_service
        .get_violation(tenant_id, id)
        .await?;

    Ok(Json(SodViolationService::to_api_response(&violation)))
}

/// Scan a specific rule for violations.
///
/// Detects all users who currently have both conflicting entitlements
/// and creates violation records for them.
#[utoipa::path(
    post,
    path = "/governance/sod-rules/{id}/scan",
    tag = "Governance - SoD Violations",
    params(
        ("id" = Uuid, Path, description = "SoD Rule ID to scan")
    ),
    responses(
        (status = 200, description = "Scan completed", body = ScanRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn scan_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ScanRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let scan_result = state
        .sod_violation_service
        .scan_rule_violations(tenant_id, id)
        .await?;

    let response = state
        .sod_violation_service
        .scan_to_api_response(tenant_id, id, &scan_result)
        .await?;

    Ok(Json(response))
}

/// Remediate a violation (mark as resolved).
#[utoipa::path(
    post,
    path = "/governance/sod-violations/{id}/remediate",
    tag = "Governance - SoD Violations",
    params(
        ("id" = Uuid, Path, description = "SoD Violation ID")
    ),
    request_body = RemediateViolationRequest,
    responses(
        (status = 200, description = "Violation remediated", body = SodViolationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD violation not found"),
        (status = 409, description = "Violation already remediated"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remediate_violation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<RemediateViolationRequest>,
) -> ApiResult<Json<SodViolationResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let violation = state
        .sod_violation_service
        .remediate_violation(tenant_id, id, user_id, request.notes)
        .await?;

    Ok(Json(SodViolationService::to_api_response(&violation)))
}
