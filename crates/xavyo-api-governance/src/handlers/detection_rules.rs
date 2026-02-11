//! Detection rule handlers for configuring orphan detection rules.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateDetectionRuleRequest, DetectionRuleListResponse, DetectionRuleResponse,
    ListDetectionRulesQuery, UpdateDetectionRuleRequest,
};
use crate::router::GovernanceState;

/// List detection rules with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/detection-rules",
    tag = "Governance - Detection Rules",
    params(ListDetectionRulesQuery),
    responses(
        (status = 200, description = "List of detection rules", body = DetectionRuleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_detection_rules(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDetectionRulesQuery>,
) -> ApiResult<Json<DetectionRuleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state.detection_rule_service.list(tenant_id, &query).await?;

    Ok(Json(result))
}

/// Get a detection rule by ID.
#[utoipa::path(
    get,
    path = "/governance/detection-rules/{id}",
    tag = "Governance - Detection Rules",
    params(
        ("id" = Uuid, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Detection rule details", body = DetectionRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_detection_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<DetectionRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rule = state.detection_rule_service.get(tenant_id, id).await?;

    Ok(Json(rule))
}

/// Create a new detection rule.
#[utoipa::path(
    post,
    path = "/governance/detection-rules",
    tag = "Governance - Detection Rules",
    request_body = CreateDetectionRuleRequest,
    responses(
        (status = 201, description = "Detection rule created", body = DetectionRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Rule with same name exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_detection_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateDetectionRuleRequest>,
) -> ApiResult<(StatusCode, Json<DetectionRuleResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rule = state
        .detection_rule_service
        .create(tenant_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(rule)))
}

/// Update a detection rule.
#[utoipa::path(
    put,
    path = "/governance/detection-rules/{id}",
    tag = "Governance - Detection Rules",
    params(
        ("id" = Uuid, Path, description = "Detection rule ID")
    ),
    request_body = UpdateDetectionRuleRequest,
    responses(
        (status = 200, description = "Detection rule updated", body = DetectionRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Rule not found"),
        (status = 409, description = "Rule with same name exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_detection_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateDetectionRuleRequest>,
) -> ApiResult<Json<DetectionRuleResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rule = state
        .detection_rule_service
        .update(tenant_id, id, request)
        .await?;

    Ok(Json(rule))
}

/// Delete a detection rule.
#[utoipa::path(
    delete,
    path = "/governance/detection-rules/{id}",
    tag = "Governance - Detection Rules",
    params(
        ("id" = Uuid, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 204, description = "Detection rule deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_detection_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state.detection_rule_service.delete(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable a detection rule.
#[utoipa::path(
    post,
    path = "/governance/detection-rules/{id}/enable",
    tag = "Governance - Detection Rules",
    params(
        ("id" = Uuid, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Detection rule enabled", body = DetectionRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_detection_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<DetectionRuleResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rule = state.detection_rule_service.enable(tenant_id, id).await?;

    Ok(Json(rule))
}

/// Disable a detection rule.
#[utoipa::path(
    post,
    path = "/governance/detection-rules/{id}/disable",
    tag = "Governance - Detection Rules",
    params(
        ("id" = Uuid, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Detection rule disabled", body = DetectionRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_detection_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<DetectionRuleResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rule = state.detection_rule_service.disable(tenant_id, id).await?;

    Ok(Json(rule))
}

/// Seed default detection rules for the tenant.
#[utoipa::path(
    post,
    path = "/governance/detection-rules/seed-defaults",
    tag = "Governance - Detection Rules",
    responses(
        (status = 200, description = "Default rules seeded", body = Vec<DetectionRuleResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn seed_default_rules(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<Vec<DetectionRuleResponse>>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rules = state
        .detection_rule_service
        .seed_defaults(tenant_id)
        .await?;

    Ok(Json(rules))
}
