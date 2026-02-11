//! Peer group handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreatePeerGroupRequest, ListPeerGroupsQuery, PeerGroupListResponse, PeerGroupResponse,
    RefreshPeerGroupsResponse, RefreshStatsResponse, UserPeerComparisonResponse,
};
use crate::router::GovernanceState;

/// List all peer groups with filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/peer-groups",
    tag = "Governance - Peer Groups",
    params(ListPeerGroupsQuery),
    responses(
        (status = 200, description = "List of peer groups", body = PeerGroupListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_peer_groups(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListPeerGroupsQuery>,
) -> ApiResult<Json<PeerGroupListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state.peer_group_service.list(tenant_id, query).await?;

    Ok(Json(response))
}

/// Create a new peer group.
#[utoipa::path(
    post,
    path = "/governance/peer-groups",
    tag = "Governance - Peer Groups",
    request_body = CreatePeerGroupRequest,
    responses(
        (status = 201, description = "Peer group created", body = PeerGroupResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_peer_group(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreatePeerGroupRequest>,
) -> ApiResult<(StatusCode, Json<PeerGroupResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let group = state.peer_group_service.create(tenant_id, request).await?;

    Ok((StatusCode::CREATED, Json(group)))
}

/// Get a peer group by ID.
#[utoipa::path(
    get,
    path = "/governance/peer-groups/{group_id}",
    tag = "Governance - Peer Groups",
    params(
        ("group_id" = Uuid, Path, description = "Peer group ID")
    ),
    responses(
        (status = 200, description = "Peer group details", body = PeerGroupResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Peer group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_peer_group(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(group_id): Path<Uuid>,
) -> ApiResult<Json<PeerGroupResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let group = state.peer_group_service.get(tenant_id, group_id).await?;

    Ok(Json(group))
}

/// Delete a peer group.
#[utoipa::path(
    delete,
    path = "/governance/peer-groups/{group_id}",
    tag = "Governance - Peer Groups",
    params(
        ("group_id" = Uuid, Path, description = "Peer group ID")
    ),
    responses(
        (status = 204, description = "Peer group deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Peer group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_peer_group(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(group_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state.peer_group_service.delete(tenant_id, group_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Refresh statistics for a specific peer group.
#[utoipa::path(
    post,
    path = "/governance/peer-groups/{group_id}/refresh",
    tag = "Governance - Peer Groups",
    params(
        ("group_id" = Uuid, Path, description = "Peer group ID")
    ),
    responses(
        (status = 200, description = "Group statistics refreshed", body = RefreshStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Peer group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn refresh_peer_group_stats(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(group_id): Path<Uuid>,
) -> ApiResult<Json<RefreshStatsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .peer_group_service
        .refresh_group_stats(tenant_id, group_id)
        .await?;

    Ok(Json(response))
}

/// Refresh all peer groups (recalculate statistics).
#[utoipa::path(
    post,
    path = "/governance/peer-groups/refresh-all",
    tag = "Governance - Peer Groups",
    responses(
        (status = 200, description = "All groups refreshed", body = RefreshPeerGroupsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn refresh_all_peer_groups(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<RefreshPeerGroupsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .peer_group_service
        .refresh_all_groups(tenant_id)
        .await?;

    Ok(Json(response))
}

/// Get peer comparison for a user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/peer-comparison",
    tag = "Governance - Peer Groups",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User peer comparison", body = UserPeerComparisonResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_peer_comparison(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<UserPeerComparisonResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .peer_group_service
        .get_user_comparison(tenant_id, user_id)
        .await?;

    Ok(Json(response))
}
