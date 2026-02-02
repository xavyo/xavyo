//! HTTP handlers for SLA policy management (F064).

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
        CreateSlaPolicyRequest, ListSlaPoliciesQuery, SlaPolicyListResponse, SlaPolicyResponse,
        UpdateSlaPolicyRequest,
    },
    router::GovernanceState,
};

/// List SLA policies.
#[utoipa::path(
    get,
    path = "/governance/sla-policies",
    tag = "Governance - Semi-manual Resources",
    params(
        ("is_active" = Option<bool>, Query, description = "Filter by active status"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return"),
        ("offset" = Option<i64>, Query, description = "Results to skip")
    ),
    responses(
        (status = 200, description = "SLA policies retrieved", body = SlaPolicyListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_sla_policies(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSlaPoliciesQuery>,
) -> ApiResult<Json<SlaPolicyListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state.sla_policy_service.list(tenant_id, &query).await?;

    Ok(Json(result))
}

/// Get an SLA policy by ID.
#[utoipa::path(
    get,
    path = "/governance/sla-policies/{id}",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "SLA policy ID")
    ),
    responses(
        (status = 200, description = "SLA policy retrieved", body = SlaPolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SLA policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_sla_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SlaPolicyResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state.sla_policy_service.get(tenant_id, id).await?;

    Ok(Json(result))
}

/// Create a new SLA policy.
#[utoipa::path(
    post,
    path = "/governance/sla-policies",
    tag = "Governance - Semi-manual Resources",
    request_body = CreateSlaPolicyRequest,
    responses(
        (status = 201, description = "SLA policy created", body = SlaPolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_sla_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateSlaPolicyRequest>,
) -> ApiResult<(StatusCode, Json<SlaPolicyResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state.sla_policy_service.create(tenant_id, request).await?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// Update an SLA policy.
#[utoipa::path(
    put,
    path = "/governance/sla-policies/{id}",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "SLA policy ID")
    ),
    request_body = UpdateSlaPolicyRequest,
    responses(
        (status = 200, description = "SLA policy updated", body = SlaPolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SLA policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_sla_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateSlaPolicyRequest>,
) -> ApiResult<Json<SlaPolicyResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .sla_policy_service
        .update(tenant_id, id, request)
        .await?;

    Ok(Json(result))
}

/// Delete an SLA policy.
#[utoipa::path(
    delete,
    path = "/governance/sla-policies/{id}",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "SLA policy ID")
    ),
    responses(
        (status = 204, description = "SLA policy deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SLA policy not found"),
        (status = 409, description = "SLA policy is in use"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_sla_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state.sla_policy_service.delete(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}
