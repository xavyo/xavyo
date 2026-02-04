//! `SoD` rule handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateGovSodRule, UpdateGovSodRule};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateSodRuleRequest, ListSodRulesQuery, SodCheckRequest, SodCheckResponse,
    SodRuleListResponse, SodRuleResponse, UpdateSodRuleRequest,
};
use crate::router::GovernanceState;
use crate::services::SodEnforcementService;

/// List `SoD` rules with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/sod-rules",
    tag = "Governance - SoD Rules",
    params(ListSodRulesQuery),
    responses(
        (status = 200, description = "List of SoD rules", body = SodRuleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_sod_rules(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSodRulesQuery>,
) -> ApiResult<Json<SodRuleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (rules, total) = state
        .sod_rule_service
        .list_rules(
            tenant_id,
            query.status,
            query.severity,
            query.entitlement_id,
            limit,
            offset,
        )
        .await?;

    Ok(Json(SodRuleListResponse {
        items: rules.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    }))
}

/// Get an `SoD` rule by ID.
#[utoipa::path(
    get,
    path = "/governance/sod-rules/{id}",
    tag = "Governance - SoD Rules",
    params(
        ("id" = Uuid, Path, description = "SoD Rule ID")
    ),
    responses(
        (status = 200, description = "SoD rule details", body = SodRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_sod_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SodRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rule = state.sod_rule_service.get_rule(tenant_id, id).await?;

    Ok(Json(rule.into()))
}

/// Create a new `SoD` rule.
#[utoipa::path(
    post,
    path = "/governance/sod-rules",
    tag = "Governance - SoD Rules",
    request_body = CreateSodRuleRequest,
    responses(
        (status = 201, description = "SoD rule created", body = SodRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Rule name or entitlement pair already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_sod_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateSodRuleRequest>,
) -> ApiResult<(StatusCode, Json<SodRuleResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let input = CreateGovSodRule {
        name: request.name,
        description: request.description,
        first_entitlement_id: request.first_entitlement_id,
        second_entitlement_id: request.second_entitlement_id,
        severity: request.severity,
        business_rationale: request.business_rationale,
        created_by: user_id,
    };

    let rule = state.sod_rule_service.create_rule(tenant_id, input).await?;

    Ok((StatusCode::CREATED, Json(rule.into())))
}

/// Update an `SoD` rule.
#[utoipa::path(
    put,
    path = "/governance/sod-rules/{id}",
    tag = "Governance - SoD Rules",
    params(
        ("id" = Uuid, Path, description = "SoD Rule ID")
    ),
    request_body = UpdateSodRuleRequest,
    responses(
        (status = 200, description = "SoD rule updated", body = SodRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD rule not found"),
        (status = 409, description = "Rule name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_sod_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateSodRuleRequest>,
) -> ApiResult<Json<SodRuleResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = UpdateGovSodRule {
        name: request.name,
        description: request.description,
        severity: request.severity,
        business_rationale: request.business_rationale,
    };

    let rule = state
        .sod_rule_service
        .update_rule(tenant_id, id, input)
        .await?;

    Ok(Json(rule.into()))
}

/// Delete an `SoD` rule.
#[utoipa::path(
    delete,
    path = "/governance/sod-rules/{id}",
    tag = "Governance - SoD Rules",
    params(
        ("id" = Uuid, Path, description = "SoD Rule ID")
    ),
    responses(
        (status = 204, description = "SoD rule deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_sod_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state.sod_rule_service.delete_rule(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable an `SoD` rule.
#[utoipa::path(
    post,
    path = "/governance/sod-rules/{id}/enable",
    tag = "Governance - SoD Rules",
    params(
        ("id" = Uuid, Path, description = "SoD Rule ID")
    ),
    responses(
        (status = 200, description = "SoD rule enabled", body = SodRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_sod_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SodRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rule = state.sod_rule_service.enable_rule(tenant_id, id).await?;

    Ok(Json(rule.into()))
}

/// Disable an `SoD` rule.
#[utoipa::path(
    post,
    path = "/governance/sod-rules/{id}/disable",
    tag = "Governance - SoD Rules",
    params(
        ("id" = Uuid, Path, description = "SoD Rule ID")
    ),
    responses(
        (status = 200, description = "SoD rule disabled", body = SodRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_sod_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SodRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let rule = state.sod_rule_service.disable_rule(tenant_id, id).await?;

    Ok(Json(rule.into()))
}

/// Check if an assignment would create `SoD` violations.
///
/// This is a pre-flight check endpoint that allows clients to validate
/// an assignment before attempting it. Useful for UI feedback.
#[utoipa::path(
    post,
    path = "/governance/sod-check",
    tag = "Governance - SoD Rules",
    request_body = SodCheckRequest,
    responses(
        (status = 200, description = "SoD check result", body = SodCheckResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn sod_check(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<SodCheckRequest>,
) -> ApiResult<Json<SodCheckResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .sod_enforcement_service
        .check_assignment(tenant_id, request.user_id, request.entitlement_id, true)
        .await?;

    Ok(Json(SodEnforcementService::to_api_response(&result)))
}
