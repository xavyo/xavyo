//! HTTP handlers for ticketing configuration management (F064).

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
    models::{
        CreateTicketingConfigurationRequest, ListTicketingConfigurationsQuery,
        TestTicketingConfigurationResponse, TicketingConfigurationListResponse,
        TicketingConfigurationResponse, UpdateTicketingConfigurationRequest,
    },
    router::GovernanceState,
};

/// List ticketing configurations.
#[utoipa::path(
    get,
    path = "/governance/ticketing-configurations",
    tag = "Governance - Semi-manual Resources",
    params(
        ("ticketing_type" = Option<String>, Query, description = "Filter by ticketing type"),
        ("is_active" = Option<bool>, Query, description = "Filter by active status"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return"),
        ("offset" = Option<i64>, Query, description = "Results to skip")
    ),
    responses(
        (status = 200, description = "Ticketing configurations retrieved", body = TicketingConfigurationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_ticketing_configurations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListTicketingConfigurationsQuery>,
) -> ApiResult<Json<TicketingConfigurationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .ticketing_config_service
        .list(tenant_id, &query)
        .await?;

    Ok(Json(result))
}

/// Get a ticketing configuration by ID.
#[utoipa::path(
    get,
    path = "/governance/ticketing-configurations/{id}",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "Ticketing configuration ID")
    ),
    responses(
        (status = 200, description = "Ticketing configuration retrieved", body = TicketingConfigurationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Ticketing configuration not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_ticketing_configuration(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TicketingConfigurationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state.ticketing_config_service.get(tenant_id, id).await?;

    Ok(Json(result))
}

/// Create a new ticketing configuration.
#[utoipa::path(
    post,
    path = "/governance/ticketing-configurations",
    tag = "Governance - Semi-manual Resources",
    request_body = CreateTicketingConfigurationRequest,
    responses(
        (status = 201, description = "Ticketing configuration created", body = TicketingConfigurationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_ticketing_configuration(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateTicketingConfigurationRequest>,
) -> ApiResult<(StatusCode, Json<TicketingConfigurationResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .ticketing_config_service
        .create(tenant_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// Update a ticketing configuration.
#[utoipa::path(
    put,
    path = "/governance/ticketing-configurations/{id}",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "Ticketing configuration ID")
    ),
    request_body = UpdateTicketingConfigurationRequest,
    responses(
        (status = 200, description = "Ticketing configuration updated", body = TicketingConfigurationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Ticketing configuration not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_ticketing_configuration(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateTicketingConfigurationRequest>,
) -> ApiResult<Json<TicketingConfigurationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .ticketing_config_service
        .update(tenant_id, id, request)
        .await?;

    Ok(Json(result))
}

/// Delete a ticketing configuration.
#[utoipa::path(
    delete,
    path = "/governance/ticketing-configurations/{id}",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "Ticketing configuration ID")
    ),
    responses(
        (status = 204, description = "Ticketing configuration deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Ticketing configuration not found"),
        (status = 409, description = "Ticketing configuration is in use"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_ticketing_configuration(
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

    state.ticketing_config_service.delete(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Test a ticketing configuration's connectivity.
#[utoipa::path(
    post,
    path = "/governance/ticketing-configurations/{id}/test",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "Ticketing configuration ID")
    ),
    responses(
        (status = 200, description = "Connectivity test completed", body = TestTicketingConfigurationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Ticketing configuration not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_ticketing_configuration(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TestTicketingConfigurationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .ticketing_config_service
        .test_connectivity(tenant_id, id)
        .await?;

    Ok(Json(TestTicketingConfigurationResponse {
        success: result.success,
        message: result.message,
        response_time_ms: result.response_time_ms,
        error: result.error,
    }))
}
