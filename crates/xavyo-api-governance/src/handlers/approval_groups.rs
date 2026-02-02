//! Approval group handlers for governance API (F054).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateApprovalGroup, UpdateApprovalGroup};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ApprovalGroupListResponse, ApprovalGroupResponse, ApprovalGroupSummary,
    CreateApprovalGroupRequest, ListApprovalGroupsQuery, ModifyMembersRequest,
    UpdateApprovalGroupRequest,
};
use crate::router::GovernanceState;

/// List approval groups.
#[utoipa::path(
    get,
    path = "/governance/approval-groups",
    tag = "Governance - Workflow Escalation",
    params(ListApprovalGroupsQuery),
    responses(
        (status = 200, description = "List of approval groups", body = ApprovalGroupListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_groups(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListApprovalGroupsQuery>,
) -> ApiResult<Json<ApprovalGroupListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (groups, total) = state
        .approval_group_service
        .list_groups(tenant_id, query.is_active, limit, offset)
        .await?;

    let items: Vec<ApprovalGroupSummary> =
        groups.into_iter().map(ApprovalGroupSummary::from).collect();

    Ok(Json(ApprovalGroupListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get an approval group by ID.
#[utoipa::path(
    get,
    path = "/governance/approval-groups/{id}",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Approval Group ID")
    ),
    responses(
        (status = 200, description = "Approval group details", body = ApprovalGroupResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_group(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApprovalGroupResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let group = state
        .approval_group_service
        .get_group(tenant_id, id)
        .await?;

    Ok(Json(ApprovalGroupResponse::from(group)))
}

/// Create a new approval group.
#[utoipa::path(
    post,
    path = "/governance/approval-groups",
    tag = "Governance - Workflow Escalation",
    request_body = CreateApprovalGroupRequest,
    responses(
        (status = 201, description = "Group created", body = ApprovalGroupResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Group name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_group(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateApprovalGroupRequest>,
) -> ApiResult<(StatusCode, Json<ApprovalGroupResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateApprovalGroup {
        name: request.name,
        description: request.description,
        member_ids: request.member_ids,
    };

    let group = state
        .approval_group_service
        .create_group(tenant_id, input)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(ApprovalGroupResponse::from(group)),
    ))
}

/// Update an approval group.
#[utoipa::path(
    put,
    path = "/governance/approval-groups/{id}",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Approval Group ID")
    ),
    request_body = UpdateApprovalGroupRequest,
    responses(
        (status = 200, description = "Group updated", body = ApprovalGroupResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Group not found"),
        (status = 409, description = "Group name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_group(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateApprovalGroupRequest>,
) -> ApiResult<Json<ApprovalGroupResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = UpdateApprovalGroup {
        name: request.name,
        description: request.description,
        is_active: request.is_active,
    };

    let group = state
        .approval_group_service
        .update_group(tenant_id, id, input)
        .await?;

    Ok(Json(ApprovalGroupResponse::from(group)))
}

/// Delete an approval group.
#[utoipa::path(
    delete,
    path = "/governance/approval-groups/{id}",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Approval Group ID")
    ),
    responses(
        (status = 204, description = "Group deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Group not found"),
        (status = 412, description = "Group is in use by escalation rules"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_group(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .approval_group_service
        .delete_group(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Add members to an approval group.
#[utoipa::path(
    post,
    path = "/governance/approval-groups/{id}/members",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Approval Group ID")
    ),
    request_body = ModifyMembersRequest,
    responses(
        (status = 200, description = "Members added", body = ApprovalGroupResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_members(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ModifyMembersRequest>,
) -> ApiResult<Json<ApprovalGroupResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let group = state
        .approval_group_service
        .add_members(tenant_id, id, request.member_ids)
        .await?;

    Ok(Json(ApprovalGroupResponse::from(group)))
}

/// Remove members from an approval group.
#[utoipa::path(
    delete,
    path = "/governance/approval-groups/{id}/members",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Approval Group ID")
    ),
    request_body = ModifyMembersRequest,
    responses(
        (status = 200, description = "Members removed", body = ApprovalGroupResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_members(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ModifyMembersRequest>,
) -> ApiResult<Json<ApprovalGroupResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let group = state
        .approval_group_service
        .remove_members(tenant_id, id, request.member_ids)
        .await?;

    Ok(Json(ApprovalGroupResponse::from(group)))
}

/// Enable an approval group.
#[utoipa::path(
    post,
    path = "/governance/approval-groups/{id}/enable",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Approval Group ID")
    ),
    responses(
        (status = 200, description = "Group enabled", body = ApprovalGroupResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_group(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApprovalGroupResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let group = state
        .approval_group_service
        .enable_group(tenant_id, id)
        .await?;

    Ok(Json(ApprovalGroupResponse::from(group)))
}

/// Disable an approval group.
#[utoipa::path(
    post,
    path = "/governance/approval-groups/{id}/disable",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Approval Group ID")
    ),
    responses(
        (status = 200, description = "Group disabled", body = ApprovalGroupResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_group(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApprovalGroupResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let group = state
        .approval_group_service
        .disable_group(tenant_id, id)
        .await?;

    Ok(Json(ApprovalGroupResponse::from(group)))
}

/// Get groups for a specific user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/approval-groups",
    tag = "Governance - Workflow Escalation",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User's approval groups", body = Vec<ApprovalGroupSummary>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_groups(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<Vec<ApprovalGroupSummary>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let groups = state
        .approval_group_service
        .get_groups_for_user(tenant_id, user_id)
        .await?;

    let summaries: Vec<ApprovalGroupSummary> =
        groups.into_iter().map(ApprovalGroupSummary::from).collect();

    Ok(Json(summaries))
}
