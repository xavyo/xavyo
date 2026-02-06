//! Role inducement handlers for F-063: Role Inducements.
//!
//! Provides HTTP handlers for managing role inducements.

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
    CreateInducementRequest, InducedRoleInfoResponse, InducementListResponse, InducementResponse,
    ListInducementsQuery,
};
use crate::router::GovernanceState;

/// List role inducements with filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/inducements",
    tag = "Governance - Role Inducements",
    params(
        ("role_id" = Uuid, Path, description = "Inducing role ID"),
        ListInducementsQuery
    ),
    responses(
        (status = 200, description = "List of inducements", body = InducementListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_role_inducements(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Query(query): Query<ListInducementsQuery>,
) -> ApiResult<Json<InducementListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .role_inducement_service
        .list_by_role(tenant_id, role_id, &query)
        .await?;

    Ok(Json(response))
}

/// Get a role inducement by ID.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/inducements/{inducement_id}",
    tag = "Governance - Role Inducements",
    params(
        ("role_id" = Uuid, Path, description = "Inducing role ID"),
        ("inducement_id" = Uuid, Path, description = "Inducement ID")
    ),
    responses(
        (status = 200, description = "Inducement details", body = InducementResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or inducement not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_role_inducement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, inducement_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<InducementResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let inducement = state
        .role_inducement_service
        .get_inducement(tenant_id, role_id, inducement_id)
        .await?;

    Ok(Json(inducement))
}

/// Create a new role inducement.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/inducements",
    tag = "Governance - Role Inducements",
    params(
        ("role_id" = Uuid, Path, description = "Inducing role ID")
    ),
    request_body = CreateInducementRequest,
    responses(
        (status = 201, description = "Inducement created", body = InducementResponse),
        (status = 400, description = "Validation error or cycle detected"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 409, description = "Inducement already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_role_inducement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<CreateInducementRequest>,
) -> ApiResult<(StatusCode, Json<InducementResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Validate request
    request
        .validate()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;

    let inducement = state
        .role_inducement_service
        .create_inducement(tenant_id, role_id, request, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(inducement)))
}

/// Delete a role inducement.
#[utoipa::path(
    delete,
    path = "/governance/roles/{role_id}/inducements/{inducement_id}",
    tag = "Governance - Role Inducements",
    params(
        ("role_id" = Uuid, Path, description = "Inducing role ID"),
        ("inducement_id" = Uuid, Path, description = "Inducement ID")
    ),
    responses(
        (status = 204, description = "Inducement deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or inducement not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_role_inducement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, inducement_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .role_inducement_service
        .delete_inducement(tenant_id, role_id, inducement_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable a role inducement.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/inducements/{inducement_id}/enable",
    tag = "Governance - Role Inducements",
    params(
        ("role_id" = Uuid, Path, description = "Inducing role ID"),
        ("inducement_id" = Uuid, Path, description = "Inducement ID")
    ),
    responses(
        (status = 200, description = "Inducement enabled", body = InducementResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or inducement not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_role_inducement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, inducement_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<InducementResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let inducement = state
        .role_inducement_service
        .enable_inducement(tenant_id, role_id, inducement_id)
        .await?;

    Ok(Json(inducement))
}

/// Disable a role inducement.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/inducements/{inducement_id}/disable",
    tag = "Governance - Role Inducements",
    params(
        ("role_id" = Uuid, Path, description = "Inducing role ID"),
        ("inducement_id" = Uuid, Path, description = "Inducement ID")
    ),
    responses(
        (status = 200, description = "Inducement disabled", body = InducementResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or inducement not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_role_inducement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, inducement_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<InducementResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let inducement = state
        .role_inducement_service
        .disable_inducement(tenant_id, role_id, inducement_id)
        .await?;

    Ok(Json(inducement))
}

/// Get all induced roles for a role (recursive traversal).
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/induced-roles",
    tag = "Governance - Role Inducements",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "List of induced roles", body = Vec<InducedRoleInfoResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_induced_roles(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<Vec<InducedRoleInfoResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let induced_roles = state
        .role_inducement_service
        .get_induced_roles(tenant_id, role_id)
        .await?;

    Ok(Json(induced_roles))
}
