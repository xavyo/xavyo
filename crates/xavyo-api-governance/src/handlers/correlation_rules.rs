//! HTTP handlers for correlation rule management (F067).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::correlation::{
        CorrelationRuleListResponse, CorrelationRuleResponse, CreateCorrelationRuleRequest,
        ListCorrelationRulesQuery, UpdateCorrelationRuleRequest, ValidateExpressionRequest,
        ValidateExpressionResponse,
    },
    router::GovernanceState,
};

/// List correlation rules for a connector.
#[utoipa::path(
    get,
    path = "/governance/connectors/{connector_id}/correlation/rules",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("is_active" = Option<bool>, Query, description = "Filter by active status"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return"),
        ("offset" = Option<i64>, Query, description = "Results to skip")
    ),
    responses(
        (status = 200, description = "Correlation rules retrieved", body = CorrelationRuleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_correlation_rules(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Query(query): Query<ListCorrelationRulesQuery>,
) -> ApiResult<Json<CorrelationRuleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .correlation_rule_service
        .list(tenant_id, connector_id, &query)
        .await?;

    Ok(Json(result))
}

/// Get a correlation rule by ID.
#[utoipa::path(
    get,
    path = "/governance/connectors/{connector_id}/correlation/rules/{id}",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("id" = Uuid, Path, description = "Correlation rule ID")
    ),
    responses(
        (status = 200, description = "Correlation rule retrieved", body = CorrelationRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Correlation rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_correlation_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<CorrelationRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .correlation_rule_service
        .get(tenant_id, connector_id, id)
        .await?;

    Ok(Json(result))
}

/// Create a new correlation rule.
#[utoipa::path(
    post,
    path = "/governance/connectors/{connector_id}/correlation/rules",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = CreateCorrelationRuleRequest,
    responses(
        (status = 201, description = "Correlation rule created", body = CorrelationRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_correlation_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Json(request): Json<CreateCorrelationRuleRequest>,
) -> ApiResult<(StatusCode, Json<CorrelationRuleResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .correlation_rule_service
        .create(tenant_id, connector_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// Update a correlation rule.
#[utoipa::path(
    patch,
    path = "/governance/connectors/{connector_id}/correlation/rules/{id}",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("id" = Uuid, Path, description = "Correlation rule ID")
    ),
    request_body = UpdateCorrelationRuleRequest,
    responses(
        (status = 200, description = "Correlation rule updated", body = CorrelationRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Correlation rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_correlation_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateCorrelationRuleRequest>,
) -> ApiResult<Json<CorrelationRuleResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .correlation_rule_service
        .update(tenant_id, connector_id, id, request)
        .await?;

    Ok(Json(result))
}

/// Delete a correlation rule.
#[utoipa::path(
    delete,
    path = "/governance/connectors/{connector_id}/correlation/rules/{id}",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("id" = Uuid, Path, description = "Correlation rule ID")
    ),
    responses(
        (status = 204, description = "Correlation rule deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Correlation rule not found"),
        (status = 409, description = "Correlation rule is in use"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_correlation_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .correlation_rule_service
        .delete(tenant_id, connector_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Validate a correlation expression.
#[utoipa::path(
    post,
    path = "/governance/connectors/{connector_id}/correlation/rules/validate-expression",
    tag = "Governance - Correlation Engine",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = ValidateExpressionRequest,
    responses(
        (status = 200, description = "Expression validation result", body = ValidateExpressionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn validate_expression(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(_connector_id): Path<Uuid>,
    Json(request): Json<ValidateExpressionRequest>,
) -> ApiResult<Json<ValidateExpressionResponse>> {
    let _tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .correlation_rule_service
        .validate_expression(request)?;

    Ok(Json(result))
}
