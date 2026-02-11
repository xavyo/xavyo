//! Birthright policy handlers for governance API.

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
    BirthrightPolicyListResponse, BirthrightPolicyResponse, CreateBirthrightPolicyRequest,
    ImpactAnalysisRequest, ImpactAnalysisResponse, ListBirthrightPoliciesQuery,
    SimulateAllPoliciesResponse, SimulatePolicyRequest, SimulatePolicyResponse,
    UpdateBirthrightPolicyRequest,
};
use crate::router::GovernanceState;

/// List birthright policies with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/birthright-policies",
    tag = "Governance - Lifecycle",
    params(ListBirthrightPoliciesQuery),
    responses(
        (status = 200, description = "List of birthright policies", body = BirthrightPolicyListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_policies(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListBirthrightPoliciesQuery>,
) -> ApiResult<Json<BirthrightPolicyListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (policies, total) = state
        .birthright_policy_service
        .list(tenant_id, query.status, limit, offset)
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(BirthrightPolicyListResponse {
        items: policies.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get a birthright policy by ID.
#[utoipa::path(
    get,
    path = "/governance/birthright-policies/{id}",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy details", body = BirthrightPolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<BirthrightPolicyResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let policy = state.birthright_policy_service.get(tenant_id, id).await?;

    Ok(Json(policy.into()))
}

/// Create a new birthright policy.
#[utoipa::path(
    post,
    path = "/governance/birthright-policies",
    tag = "Governance - Lifecycle",
    request_body = CreateBirthrightPolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = BirthrightPolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Policy name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateBirthrightPolicyRequest>,
) -> ApiResult<(StatusCode, Json<BirthrightPolicyResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let policy = state
        .birthright_policy_service
        .create(
            tenant_id,
            request.name,
            request.description,
            request.priority,
            request.conditions,
            request.entitlement_ids,
            request.evaluation_mode,
            request.grace_period_days,
            user_id,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(policy.into())))
}

/// Update a birthright policy.
#[utoipa::path(
    put,
    path = "/governance/birthright-policies/{id}",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    request_body = UpdateBirthrightPolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = BirthrightPolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 409, description = "Policy name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateBirthrightPolicyRequest>,
) -> ApiResult<Json<BirthrightPolicyResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let policy = state
        .birthright_policy_service
        .update(
            tenant_id,
            id,
            request.name,
            request.description,
            request.priority,
            request.conditions,
            request.entitlement_ids,
            request.evaluation_mode,
            request.grace_period_days,
        )
        .await?;

    Ok(Json(policy.into()))
}

/// Archive (soft-delete) a birthright policy.
#[utoipa::path(
    delete,
    path = "/governance/birthright-policies/{id}",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy archived", body = BirthrightPolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn archive_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<BirthrightPolicyResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let policy = state
        .birthright_policy_service
        .archive(tenant_id, id)
        .await?;

    Ok(Json(policy.into()))
}

/// Enable a birthright policy.
#[utoipa::path(
    post,
    path = "/governance/birthright-policies/{id}/enable",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy enabled", body = BirthrightPolicyResponse),
        (status = 400, description = "Cannot enable policy in current state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<BirthrightPolicyResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let policy = state
        .birthright_policy_service
        .enable(tenant_id, id)
        .await?;

    Ok(Json(policy.into()))
}

/// Disable a birthright policy.
#[utoipa::path(
    post,
    path = "/governance/birthright-policies/{id}/disable",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy disabled", body = BirthrightPolicyResponse),
        (status = 400, description = "Cannot disable policy in current state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<BirthrightPolicyResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let policy = state
        .birthright_policy_service
        .disable(tenant_id, id)
        .await?;

    Ok(Json(policy.into()))
}

/// Simulate a single policy against user attributes.
#[utoipa::path(
    post,
    path = "/governance/birthright-policies/{id}/simulate",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    request_body = SimulatePolicyRequest,
    responses(
        (status = 200, description = "Simulation result", body = SimulatePolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn simulate_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<SimulatePolicyRequest>,
) -> ApiResult<Json<SimulatePolicyResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .birthright_policy_service
        .simulate_policy(tenant_id, id, &request.attributes)
        .await?;

    Ok(Json(result))
}

/// Simulate all active policies against user attributes.
#[utoipa::path(
    post,
    path = "/governance/birthright-policies/simulate",
    tag = "Governance - Lifecycle",
    request_body = SimulatePolicyRequest,
    responses(
        (status = 200, description = "Simulation result", body = SimulateAllPoliciesResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn simulate_all_policies(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<SimulatePolicyRequest>,
) -> ApiResult<Json<SimulateAllPoliciesResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .birthright_policy_service
        .simulate_all_policies(tenant_id, &request.attributes)
        .await?;

    Ok(Json(result))
}

/// Analyze the impact of a policy on users.
#[utoipa::path(
    post,
    path = "/governance/birthright-policies/{id}/impact",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    request_body = ImpactAnalysisRequest,
    responses(
        (status = 200, description = "Impact analysis result", body = ImpactAnalysisResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn analyze_policy_impact(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ImpactAnalysisRequest>,
) -> ApiResult<Json<ImpactAnalysisResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .birthright_policy_service
        .analyze_impact(tenant_id, id, &request)
        .await?;

    Ok(Json(result))
}
