//! HTTP handlers for License Reclamation Rules (F065).
//!
//! Provides endpoints for managing automatic license reclamation rules
//! that reclaim licenses based on user inactivity or lifecycle state changes.

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
    models::license::{
        CreateReclamationRuleRequest, ListReclamationRulesParams, ReclamationRuleListResponse,
        ReclamationRuleResponse, UpdateReclamationRuleRequest,
    },
    router::GovernanceState,
};

/// List reclamation rules with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/license-reclamation-rules",
    tag = "Governance - License Management",
    params(
        ("license_pool_id" = Option<Uuid>, Query, description = "Filter by license pool"),
        ("trigger_type" = Option<String>, Query, description = "Filter by trigger type (inactivity, lifecycle_state)"),
        ("enabled" = Option<bool>, Query, description = "Filter by enabled status"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Results to skip for pagination")
    ),
    responses(
        (status = 200, description = "Reclamation rules retrieved", body = ReclamationRuleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_rules(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListReclamationRulesParams>,
) -> ApiResult<Json<ReclamationRuleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .license_reclamation_service
        .list_rules(tenant_id, params)
        .await?;

    Ok(Json(result))
}

/// Get a reclamation rule by ID.
#[utoipa::path(
    get,
    path = "/governance/license-reclamation-rules/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "Reclamation rule ID")
    ),
    responses(
        (status = 200, description = "Reclamation rule retrieved", body = ReclamationRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Reclamation rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ReclamationRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .license_reclamation_service
        .get_rule_required(tenant_id, id)
        .await?;

    Ok(Json(result))
}

/// Create a new reclamation rule.
///
/// Defines when licenses should be automatically reclaimed from users
/// based on inactivity (no login for N days) or lifecycle state changes
/// (e.g., user terminated).
#[utoipa::path(
    post,
    path = "/governance/license-reclamation-rules",
    tag = "Governance - License Management",
    request_body = CreateReclamationRuleRequest,
    responses(
        (status = 201, description = "Reclamation rule created", body = ReclamationRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "License pool not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateReclamationRuleRequest>,
) -> ApiResult<(StatusCode, Json<ReclamationRuleResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .license_reclamation_service
        .create_rule(tenant_id, user_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// Update a reclamation rule.
///
/// Allows updating the threshold, lifecycle state, notification days,
/// and enabled status of a reclamation rule.
#[utoipa::path(
    put,
    path = "/governance/license-reclamation-rules/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "Reclamation rule ID")
    ),
    request_body = UpdateReclamationRuleRequest,
    responses(
        (status = 200, description = "Reclamation rule updated", body = ReclamationRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Reclamation rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateReclamationRuleRequest>,
) -> ApiResult<Json<ReclamationRuleResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .license_reclamation_service
        .update_rule(tenant_id, id, user_id, request)
        .await?;

    Ok(Json(result))
}

/// Delete a reclamation rule.
#[utoipa::path(
    delete,
    path = "/governance/license-reclamation-rules/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "Reclamation rule ID")
    ),
    responses(
        (status = 204, description = "Reclamation rule deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Reclamation rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .license_reclamation_service
        .delete_rule(tenant_id, id, user_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_handler_module_exists() {
        // Placeholder test to verify the module compiles
    }
}
