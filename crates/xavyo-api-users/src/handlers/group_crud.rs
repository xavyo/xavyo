//! Group CRUD endpoint handlers.
//!
//! Provides endpoints for:
//! - Getting a single group by ID
//! - Creating a new group
//! - Updating a group
//! - Deleting a group
//! - Managing group members (list, add, remove)

use crate::error::ApiUsersError;
use crate::models::{
    AddGroupMembersRequest, CreateGroupRequest, GroupDetail, GroupMemberResponse,
    GroupMembersResponse, UpdateGroupRequest,
};
use crate::services::GroupHierarchyService;
use axum::{extract::Path, Extension, Json};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{Group, GroupMembership, UpdateGroup};

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

/// Get a single group by ID.
///
/// GET /api/v1/admin/groups/:group_id
pub async fn get_group_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupDetail>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let group = Group::find_by_id(&pool, tenant_id, group_id)
        .await?
        .ok_or(ApiUsersError::GroupNotFound)?;

    let detail = group_to_detail(&service, tenant_id, &group).await?;
    Ok(Json(detail))
}

/// Create a new group.
///
/// POST /api/v1/admin/groups
pub async fn create_group_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Json(request): Json<CreateGroupRequest>,
) -> Result<(axum::http::StatusCode, Json<GroupDetail>), ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Validate display_name is not empty
    if request.display_name.trim().is_empty() {
        return Err(ApiUsersError::Validation(
            "display_name is required".to_string(),
        ));
    }

    // Validate group_type if provided
    if let Some(ref gt) = request.group_type {
        GroupHierarchyService::validate_group_type(gt)?;
    }

    // Validate parent exists if provided
    if let Some(parent_id) = request.parent_id {
        let parent = Group::find_by_id(&pool, tenant_id, parent_id).await?;
        if parent.is_none() {
            return Err(ApiUsersError::ParentNotFound);
        }
    }

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        display_name = %request.display_name,
        "Creating group"
    );

    let group = Group::create(
        &pool,
        tenant_id,
        &request.display_name,
        None, // external_id not exposed in create request
        request.description.as_deref(),
        request.parent_id,
        request.group_type.as_deref(),
    )
    .await?;

    let detail = group_to_detail(&service, tenant_id, &group).await?;
    Ok((axum::http::StatusCode::CREATED, Json(detail)))
}

/// Update an existing group.
///
/// PUT /api/v1/admin/groups/:group_id
pub async fn update_group_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Extension(service): Extension<Arc<GroupHierarchyService>>,
    Path(group_id): Path<Uuid>,
    Json(request): Json<UpdateGroupRequest>,
) -> Result<Json<GroupDetail>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Validate display_name if provided
    if let Some(ref name) = request.display_name {
        if name.trim().is_empty() {
            return Err(ApiUsersError::Validation(
                "display_name cannot be empty".to_string(),
            ));
        }
    }

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        group_id = %group_id,
        "Updating group"
    );

    let update = UpdateGroup {
        display_name: request.display_name,
        external_id: None,
        description: request.description,
        parent_id: None,
        group_type: None,
    };

    let group = Group::update(&pool, tenant_id, group_id, update)
        .await?
        .ok_or(ApiUsersError::GroupNotFound)?;

    let detail = group_to_detail(&service, tenant_id, &group).await?;
    Ok(Json(detail))
}

/// Delete a group.
///
/// DELETE /api/v1/admin/groups/:group_id
pub async fn delete_group_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Path(group_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        group_id = %group_id,
        "Deleting group"
    );

    let deleted = Group::delete(&pool, tenant_id, group_id).await?;
    if !deleted {
        return Err(ApiUsersError::GroupNotFound);
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Get members of a group.
///
/// GET /api/v1/admin/groups/:group_id/members
pub async fn get_group_members_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupMembersResponse>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Verify group exists
    let _group = Group::find_by_id(&pool, tenant_id, group_id)
        .await?
        .ok_or(ApiUsersError::GroupNotFound)?;

    let member_infos = GroupMembership::get_group_members(&pool, tenant_id, group_id).await?;

    let members = member_infos
        .into_iter()
        .map(|m| GroupMemberResponse {
            user_id: m.user_id,
            display_name: m.display_name,
            email: m.email,
        })
        .collect();

    Ok(Json(GroupMembersResponse { members }))
}

/// Add members to a group.
///
/// POST /api/v1/admin/groups/:group_id/members
pub async fn add_group_members_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Path(group_id): Path<Uuid>,
    Json(request): Json<AddGroupMembersRequest>,
) -> Result<Json<GroupMembersResponse>, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Verify group exists
    let _group = Group::find_by_id(&pool, tenant_id, group_id)
        .await?
        .ok_or(ApiUsersError::GroupNotFound)?;

    if request.member_ids.is_empty() {
        return Err(ApiUsersError::Validation(
            "member_ids must not be empty".to_string(),
        ));
    }

    // H-3: Cap member_ids to prevent DoS via unbounded loop
    if request.member_ids.len() > 500 {
        return Err(ApiUsersError::Validation(
            "Cannot add more than 500 members in a single request".to_string(),
        ));
    }

    // C-1: Verify ALL member_ids belong to the caller's tenant before inserting.
    // A single batch query is used to avoid N+1 round-trips.
    let valid_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = ANY($1) AND tenant_id = $2")
            .bind(&request.member_ids)
            .bind(tenant_id)
            .fetch_one(&pool)
            .await?;

    if valid_count != request.member_ids.len() as i64 {
        return Err(ApiUsersError::Validation(
            "One or more member_ids do not belong to this tenant".to_string(),
        ));
    }

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        group_id = %group_id,
        count = request.member_ids.len(),
        "Adding members to group"
    );

    // Add each member (ON CONFLICT DO NOTHING handles duplicates)
    for user_id in &request.member_ids {
        // add_member uses ON CONFLICT DO NOTHING RETURNING *
        // If the member already exists, fetch_one will fail, so we use a
        // try and ignore the "no rows returned" error for duplicates.
        match GroupMembership::add_member(&pool, tenant_id, group_id, *user_id).await {
            Ok(_) => {}
            Err(sqlx::Error::RowNotFound) => {
                // Member already exists (ON CONFLICT DO NOTHING), skip silently
            }
            Err(e) => return Err(ApiUsersError::Database(e)),
        }
    }

    // Return updated members list
    let member_infos = GroupMembership::get_group_members(&pool, tenant_id, group_id).await?;

    let members = member_infos
        .into_iter()
        .map(|m| GroupMemberResponse {
            user_id: m.user_id,
            display_name: m.display_name,
            email: m.email,
        })
        .collect();

    Ok(Json(GroupMembersResponse { members }))
}

/// Remove a member from a group.
///
/// DELETE /api/v1/admin/groups/:group_id/members/:user_id
pub async fn remove_group_member_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(pool): Extension<PgPool>,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, ApiUsersError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Verify group exists
    let _group = Group::find_by_id(&pool, tenant_id, group_id)
        .await?
        .ok_or(ApiUsersError::GroupNotFound)?;

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        group_id = %group_id,
        user_id = %user_id,
        "Removing member from group"
    );

    let removed = GroupMembership::remove_member(&pool, tenant_id, group_id, user_id).await?;
    if !removed {
        return Err(ApiUsersError::GroupMemberNotFound);
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    // Handler tests require integration test setup with database
    // See quickstart.md for manual API testing scenarios
}
