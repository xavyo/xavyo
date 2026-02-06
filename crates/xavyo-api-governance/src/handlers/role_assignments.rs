//! Role assignment handlers for F-063: Role Inducements.
//!
//! Provides HTTP handlers for assigning and revoking roles from users,
//! which triggers the construction pattern for automatic provisioning.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::router::GovernanceState;
use crate::services::{RoleAssignmentResult, RoleRevocationResult};

/// Request to assign a role to a user.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AssignRoleRequest {
    /// Optional justification for the assignment.
    pub justification: Option<String>,

    /// Optional expiration timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Response for role assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AssignRoleResponse {
    /// The role that was assigned.
    pub role_id: Uuid,
    /// The user the role was assigned to.
    pub user_id: Uuid,
    /// Number of entitlement assignments created.
    pub entitlement_assignments_created: usize,
    /// Number of provisioning operations queued.
    pub provisioning_operations_queued: usize,
}

impl From<RoleAssignmentResult> for AssignRoleResponse {
    fn from(result: RoleAssignmentResult) -> Self {
        Self {
            role_id: result.role_id,
            user_id: result.user_id,
            entitlement_assignments_created: result.entitlement_assignment_ids.len(),
            provisioning_operations_queued: result.provisioning_operation_ids.len(),
        }
    }
}

/// Response for role revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeRoleResponse {
    /// The role that was revoked.
    pub role_id: Uuid,
    /// The user the role was revoked from.
    pub user_id: Uuid,
    /// Number of entitlement assignments revoked.
    pub entitlement_assignments_revoked: usize,
    /// Number of deprovisioning operations queued.
    pub deprovisioning_operations_queued: usize,
}

impl From<RoleRevocationResult> for RevokeRoleResponse {
    fn from(result: RoleRevocationResult) -> Self {
        Self {
            role_id: result.role_id,
            user_id: result.user_id,
            entitlement_assignments_revoked: result.entitlement_assignments_revoked.len(),
            deprovisioning_operations_queued: result.deprovisioning_operation_ids.len(),
        }
    }
}

/// Response for checking if user has role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserHasRoleResponse {
    /// The user ID checked.
    pub user_id: Uuid,
    /// The role ID checked.
    pub role_id: Uuid,
    /// Whether the user has the role.
    pub has_role: bool,
}

/// Response for listing user's roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserRolesResponse {
    /// The user ID.
    pub user_id: Uuid,
    /// Role IDs the user has.
    pub role_ids: Vec<Uuid>,
}

/// Assign a role to a user.
///
/// This triggers the construction pattern:
/// 1. All entitlements mapped to the role are assigned to the user
/// 2. Provisioning operations are queued for all role constructions
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/assignments/{user_id}",
    tag = "Governance - Role Assignments",
    params(
        ("role_id" = Uuid, Path, description = "Role ID to assign"),
        ("user_id" = Uuid, Path, description = "User ID to assign the role to")
    ),
    request_body = AssignRoleRequest,
    responses(
        (status = 201, description = "Role assigned successfully", body = AssignRoleResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 422, description = "Cannot assign abstract role"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn assign_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, user_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<AssignRoleRequest>,
) -> ApiResult<(StatusCode, Json<AssignRoleResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let assigned_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Validate request
    request
        .validate()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;

    let result = state
        .role_assignment_service
        .assign_role(
            tenant_id,
            user_id,
            role_id,
            assigned_by,
            request.justification,
            request.expires_at,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(result.into())))
}

/// Revoke a role from a user.
///
/// This triggers the deprovisioning pattern:
/// 1. Entitlements unique to this role are revoked
/// 2. Deprovisioning operations are queued based on construction policies
#[utoipa::path(
    delete,
    path = "/governance/roles/{role_id}/assignments/{user_id}",
    tag = "Governance - Role Assignments",
    params(
        ("role_id" = Uuid, Path, description = "Role ID to revoke"),
        ("user_id" = Uuid, Path, description = "User ID to revoke the role from")
    ),
    responses(
        (status = 200, description = "Role revoked successfully", body = RevokeRoleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<RevokeRoleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let revoked_by = Uuid::parse_str(&claims.sub).ok();

    let result = state
        .role_assignment_service
        .revoke_role(tenant_id, user_id, role_id, revoked_by)
        .await?;

    Ok(Json(result.into()))
}

/// Check if a user has a specific role.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/assignments/{user_id}",
    tag = "Governance - Role Assignments",
    params(
        ("role_id" = Uuid, Path, description = "Role ID to check"),
        ("user_id" = Uuid, Path, description = "User ID to check")
    ),
    responses(
        (status = 200, description = "Role check result", body = UserHasRoleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn check_user_has_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<UserHasRoleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let has_role = state
        .role_assignment_service
        .user_has_role(tenant_id, user_id, role_id)
        .await?;

    Ok(Json(UserHasRoleResponse {
        user_id,
        role_id,
        has_role,
    }))
}

/// List all roles for a user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/roles",
    tag = "Governance - Role Assignments",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User's roles", body = UserRolesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_user_roles(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<UserRolesResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let role_ids = state
        .role_assignment_service
        .get_user_role_ids(tenant_id, user_id)
        .await?;

    Ok(Json(UserRolesResponse { user_id, role_ids }))
}
