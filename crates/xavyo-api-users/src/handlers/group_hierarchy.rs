//! Group hierarchy endpoint handlers (F071).
//!
//! Provides endpoints for:
//! - Moving groups in the hierarchy (US2)
//! - Navigating the hierarchy: children, ancestors, subtree, roots (US3)
//! - Subtree membership queries (US4)

use crate::error::ApiUsersError;
use crate::models::{
    AncestorEntry, AncestorPathResponse, GroupDetail, GroupListResponse, HierarchyPaginationParams,
    ListGroupsQuery, MoveGroupRequest, Pagination, PaginationWithTotal, SubtreeEntry,
    SubtreeMember, SubtreeMembershipResponse, SubtreeResponse,
};
use crate::services::GroupHierarchyService;
use axum::{
    extract::{Path, Query},
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::Group;

/// Helper: extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiUsersError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiUsersError::Unauthorized)
}

/// Helper: convert a Group to `GroupDetail` (with ancestor path).
async fn group_to_detail(
    service: &GroupHierarchyService,
    tenant_id: Uuid,
    group: &Group,
) -> Result<GroupDetail, ApiUsersError> {
    let path = service
        .get_ancestor_path_names(tenant_id, group.id)
        .await
        .unwrap_or_default();

    Ok(GroupDetail {
        id: group.id,
        tenant_id: group.tenant_id,
        display_name: group.display_name.clone(),
        external_id: group.external_id.clone(),
        description: group.description.clone(),
        parent_id: group.parent_id,
        group_type: group.group_type.clone(),
        path,
        created_at: group.created_at,
        updated_at: group.updated_at,
    })
}

// --- US1: Group Type Classification ---

/// List groups with optional type filter.
///
/// GET /`api/v1/groups?group_type=department&limit=50&offset=0`
#[utoipa::path(
    get,
    path = "/groups",
    params(ListGroupsQuery),
    responses(
        (status = 200, description = "Paginated group list", body = GroupListResponse),
        (status = 401, description = "Not authenticated"),
    ),
    security(("bearerAuth" = [])),
    tag = "Group Hierarchy"
)]
pub async fn list_groups(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Query(query): Query<ListGroupsQuery>,
) -> Result<Json<GroupListResponse>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let limit = query.limit();
    let offset = query.offset();

    // Validate group_type if provided
    if let Some(ref gt) = query.group_type {
        GroupHierarchyService::validate_group_type(gt)?;
    }

    let (groups, has_more) = service
        .list_by_tenant_filtered(tenant_id, query.group_type.as_deref(), limit, offset)
        .await?;

    let mut details = Vec::with_capacity(groups.len());
    for group in &groups {
        details.push(group_to_detail(&service, tenant_id, group).await?);
    }

    Ok(Json(GroupListResponse {
        groups: details,
        pagination: Pagination {
            limit,
            offset,
            has_more,
        },
    }))
}

// --- US2: Build Group Hierarchy ---

/// Move group to a new parent (or make root).
///
/// PUT /`api/v1/groups/:group_id/parent`
#[utoipa::path(
    put,
    path = "/groups/{group_id}/parent",
    params(
        ("group_id" = String, Path, description = "Group ID"),
    ),
    request_body = MoveGroupRequest,
    responses(
        (status = 200, description = "Group moved successfully", body = GroupDetail),
        (status = 400, description = "Validation error (depth exceeded, cycle detected)"),
        (status = 404, description = "Group or parent not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "Group Hierarchy"
)]
pub async fn move_group(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Path(group_id): Path<Uuid>,
    Json(request): Json<MoveGroupRequest>,
) -> Result<Json<GroupDetail>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        group_id = %group_id,
        new_parent_id = ?request.parent_id,
        "Moving group in hierarchy"
    );

    let group = service
        .move_group(tenant_id, group_id, request.parent_id)
        .await?;

    let detail = group_to_detail(&service, tenant_id, &group).await?;
    Ok(Json(detail))
}

// --- US3: Navigate the Hierarchy ---

/// List direct children of a group.
///
/// GET /`api/v1/groups/:group_id/children`
#[utoipa::path(
    get,
    path = "/groups/{group_id}/children",
    params(
        ("group_id" = String, Path, description = "Group ID"),
        HierarchyPaginationParams,
    ),
    responses(
        (status = 200, description = "Direct children of the group", body = GroupListResponse),
        (status = 404, description = "Group not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "Group Hierarchy"
)]
pub async fn get_children(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Path(group_id): Path<Uuid>,
    Query(pagination): Query<HierarchyPaginationParams>,
) -> Result<Json<GroupListResponse>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let limit = pagination.limit();
    let offset = pagination.offset();

    let (children, has_more) = service
        .get_children(tenant_id, group_id, limit, offset)
        .await?;

    let mut details = Vec::with_capacity(children.len());
    for child in &children {
        details.push(group_to_detail(&service, tenant_id, child).await?);
    }

    Ok(Json(GroupListResponse {
        groups: details,
        pagination: Pagination {
            limit,
            offset,
            has_more,
        },
    }))
}

/// Get ancestor path from root to group.
///
/// GET /`api/v1/groups/:group_id/ancestors`
#[utoipa::path(
    get,
    path = "/groups/{group_id}/ancestors",
    params(
        ("group_id" = String, Path, description = "Group ID"),
    ),
    responses(
        (status = 200, description = "Ancestor path from root to group", body = AncestorPathResponse),
        (status = 404, description = "Group not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "Group Hierarchy"
)]
pub async fn get_ancestors(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<AncestorPathResponse>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let ancestor_rows = service.get_ancestors(tenant_id, group_id).await?;

    let ancestors = ancestor_rows
        .into_iter()
        .map(|a| AncestorEntry {
            id: a.id,
            display_name: a.display_name,
            group_type: a.group_type,
            depth: a.depth,
        })
        .collect();

    Ok(Json(AncestorPathResponse {
        group_id,
        ancestors,
    }))
}

/// Get full subtree (all descendants).
///
/// GET /`api/v1/groups/:group_id/subtree`
#[utoipa::path(
    get,
    path = "/groups/{group_id}/subtree",
    params(
        ("group_id" = String, Path, description = "Group ID"),
        HierarchyPaginationParams,
    ),
    responses(
        (status = 200, description = "All descendant groups with relative depth", body = SubtreeResponse),
        (status = 404, description = "Group not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "Group Hierarchy"
)]
pub async fn get_subtree(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Path(group_id): Path<Uuid>,
    Query(pagination): Query<HierarchyPaginationParams>,
) -> Result<Json<SubtreeResponse>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let limit = pagination.limit();
    let offset = pagination.offset();

    let (subtree_rows, has_more) = service
        .get_subtree(tenant_id, group_id, limit, offset)
        .await?;

    let descendants = subtree_rows
        .into_iter()
        .map(|s| SubtreeEntry {
            id: s.id,
            display_name: s.display_name,
            group_type: s.group_type,
            parent_id: s.parent_id,
            relative_depth: s.relative_depth,
        })
        .collect();

    Ok(Json(SubtreeResponse {
        root_group_id: group_id,
        descendants,
        pagination: Pagination {
            limit,
            offset,
            has_more,
        },
    }))
}

/// List root groups (no parent).
///
/// GET /api/v1/groups/roots
#[utoipa::path(
    get,
    path = "/groups/roots",
    params(HierarchyPaginationParams),
    responses(
        (status = 200, description = "Root groups for the tenant", body = GroupListResponse),
    ),
    security(("bearerAuth" = [])),
    tag = "Group Hierarchy"
)]
pub async fn list_root_groups(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Query(pagination): Query<HierarchyPaginationParams>,
) -> Result<Json<GroupListResponse>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let limit = pagination.limit();
    let offset = pagination.offset();

    let (roots, has_more) = service.get_roots(tenant_id, limit, offset).await?;

    let mut details = Vec::with_capacity(roots.len());
    for group in &roots {
        details.push(group_to_detail(&service, tenant_id, group).await?);
    }

    Ok(Json(GroupListResponse {
        groups: details,
        pagination: Pagination {
            limit,
            offset,
            has_more,
        },
    }))
}

// --- US4: Subtree Membership ---

/// Get all users in group and all descendant groups.
///
/// GET /api/v1/groups/:group_id/subtree-members
#[utoipa::path(
    get,
    path = "/groups/{group_id}/subtree-members",
    params(
        ("group_id" = String, Path, description = "Group ID"),
        HierarchyPaginationParams,
    ),
    responses(
        (status = 200, description = "Paginated list of users in the subtree", body = SubtreeMembershipResponse),
        (status = 404, description = "Group not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "Group Hierarchy"
)]
pub async fn get_subtree_members(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Path(group_id): Path<Uuid>,
    Query(pagination): Query<HierarchyPaginationParams>,
) -> Result<Json<SubtreeMembershipResponse>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let limit = pagination.limit();
    let offset = pagination.offset();

    let (member_rows, total_count) = service
        .get_subtree_members(tenant_id, group_id, limit, offset)
        .await?;

    let members = member_rows
        .into_iter()
        .map(|m| SubtreeMember {
            user_id: m.user_id,
            email: m.email,
            display_name: m.display_name,
        })
        .collect();

    Ok(Json(SubtreeMembershipResponse {
        group_id,
        members,
        pagination: PaginationWithTotal::new(total_count, offset, limit),
    }))
}

#[cfg(test)]
mod tests {
    // Handler tests require integration test setup with database
    // See quickstart.md for manual API testing scenarios
}
