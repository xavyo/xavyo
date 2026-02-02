//! Handlers for authorization policy CRUD (F083).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::{ApiAuthorizationError, ApiResult};
use crate::models::policy::{
    CreatePolicyRequest, ListPoliciesQuery, PolicyListResponse, PolicyResponse, UpdatePolicyRequest,
};
use crate::router::AuthorizationState;

/// List authorization policies with optional filters and pagination.
#[utoipa::path(
    get,
    path = "/admin/authorization/policies",
    tag = "Authorization - Policies",
    params(ListPoliciesQuery),
    responses(
        (status = 200, description = "List of policies", body = PolicyListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_policies(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListPoliciesQuery>,
) -> ApiResult<Json<PolicyListResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let result = state.policy_service.list_policies(tenant_id, query).await?;

    Ok(Json(result))
}

/// Create a new authorization policy.
#[utoipa::path(
    post,
    path = "/admin/authorization/policies",
    tag = "Authorization - Policies",
    request_body = CreatePolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = PolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "Policy name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_policy(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreatePolicyRequest>,
) -> ApiResult<(StatusCode, Json<PolicyResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthorizationError::Unauthorized)?;

    let policy = state
        .policy_service
        .create_policy(tenant_id, request, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(policy)))
}

/// Get an authorization policy by ID.
#[utoipa::path(
    get,
    path = "/admin/authorization/policies/{id}",
    tag = "Authorization - Policies",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy details", body = PolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_policy(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<PolicyResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let policy = state.policy_service.get_policy(tenant_id, id).await?;

    Ok(Json(policy))
}

/// Update an authorization policy.
#[utoipa::path(
    put,
    path = "/admin/authorization/policies/{id}",
    tag = "Authorization - Policies",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    request_body = UpdatePolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = PolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_policy(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdatePolicyRequest>,
) -> ApiResult<Json<PolicyResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let policy = state
        .policy_service
        .update_policy(tenant_id, id, request)
        .await?;

    Ok(Json(policy))
}

/// Deactivate an authorization policy.
///
/// Sets the policy status to "inactive" so it is no longer evaluated by the PDP.
#[utoipa::path(
    delete,
    path = "/admin/authorization/policies/{id}",
    tag = "Authorization - Policies",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy deactivated", body = PolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn deactivate_policy(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<PolicyResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let policy = state
        .policy_service
        .deactivate_policy(tenant_id, id)
        .await?;

    Ok(Json(policy))
}
