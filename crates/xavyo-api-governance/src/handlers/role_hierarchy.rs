//! Business role hierarchy handlers for governance API (F088).
//!
//! Provides endpoints for managing role hierarchies with parent-child relationships,
//! entitlement inheritance, and impact analysis.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateGovRole, GovRoleFilter, UpdateGovRole};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::router::GovernanceState;

// ============================================================================
// Request/Response Models
// ============================================================================

/// Query parameters for listing roles.
#[derive(Debug, Clone, Deserialize, utoipa::IntoParams)]
pub struct ListRolesQuery {
    /// Filter by parent role ID (use "null" for root roles).
    pub parent_role_id: Option<String>,
    /// Filter by abstract flag.
    pub is_abstract: Option<bool>,
    /// Search by name prefix.
    pub name: Option<String>,
    /// Maximum number of results (default: 50, max: 100).
    pub limit: Option<i64>,
    /// Offset for pagination.
    pub offset: Option<i64>,
}

/// Request to create a new governance role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateRoleRequest {
    /// Role name (unique per tenant).
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Parent role ID (null for root role).
    pub parent_role_id: Option<Uuid>,
    /// Whether this role is abstract (cannot be assigned directly).
    #[serde(default)]
    pub is_abstract: bool,
}

/// Request to update a governance role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateRoleRequest {
    /// Updated name.
    pub name: Option<String>,
    /// Updated description.
    pub description: Option<String>,
    /// Updated parent role ID.
    pub parent_role_id: Option<Option<Uuid>>,
    /// Updated abstract flag.
    pub is_abstract: Option<bool>,
    /// Expected version for optimistic concurrency.
    pub version: i32,
}

/// Request to move a role to a new parent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MoveRoleRequest {
    /// New parent role ID (null to make root).
    pub new_parent_id: Option<Uuid>,
    /// Expected version for optimistic concurrency.
    pub version: i32,
}

/// Query parameters for tree endpoint.
#[derive(Debug, Clone, Deserialize, utoipa::IntoParams)]
pub struct GetTreeQuery {
    /// Optional root role ID to start from.
    pub root_role_id: Option<Uuid>,
}

/// Role response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub parent_role_id: Option<Uuid>,
    pub is_abstract: bool,
    pub hierarchy_depth: i32,
    pub version: i32,
    pub created_by: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<xavyo_db::models::GovRole> for RoleResponse {
    fn from(role: xavyo_db::models::GovRole) -> Self {
        Self {
            id: role.id,
            name: role.name,
            description: role.description,
            parent_role_id: role.parent_role_id,
            is_abstract: role.is_abstract,
            hierarchy_depth: role.hierarchy_depth,
            version: role.version,
            created_by: role.created_by,
            created_at: role.created_at,
            updated_at: role.updated_at,
        }
    }
}

/// Role list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleListResponse {
    pub items: Vec<RoleResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Role move response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleMoveResponse {
    pub role: RoleResponse,
    pub affected_roles_count: i64,
    pub recomputed: bool,
}

/// Role tree node response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleTreeNodeResponse {
    pub id: Uuid,
    pub name: String,
    pub depth: i32,
    pub is_abstract: bool,
    pub direct_entitlement_count: i64,
    pub effective_entitlement_count: i64,
    pub assigned_user_count: i64,
    pub children: Vec<RoleTreeNodeResponse>,
}

impl From<xavyo_db::models::GovRoleTreeNode> for RoleTreeNodeResponse {
    fn from(node: xavyo_db::models::GovRoleTreeNode) -> Self {
        Self {
            id: node.id,
            name: node.name,
            depth: node.depth,
            is_abstract: node.is_abstract,
            direct_entitlement_count: node.direct_entitlement_count,
            effective_entitlement_count: node.effective_entitlement_count,
            assigned_user_count: node.assigned_user_count,
            children: node.children.into_iter().map(Self::from).collect(),
        }
    }
}

/// Role tree response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleTreeResponse {
    pub roots: Vec<RoleTreeNodeResponse>,
}

/// Impact analysis response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ImpactAnalysisResponse {
    pub role_id: Uuid,
    pub role_name: String,
    pub descendant_count: i64,
    pub total_affected_users: i64,
    pub descendants: Vec<DescendantResponse>,
}

/// Descendant role response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DescendantResponse {
    pub id: Uuid,
    pub name: String,
    pub depth: i32,
    pub assigned_user_count: i64,
}

impl From<xavyo_db::models::GovRoleDescendant> for DescendantResponse {
    fn from(d: xavyo_db::models::GovRoleDescendant) -> Self {
        Self {
            id: d.id,
            name: d.name,
            depth: d.depth,
            assigned_user_count: d.assigned_user_count,
        }
    }
}

impl From<xavyo_db::models::GovRoleImpactAnalysis> for ImpactAnalysisResponse {
    fn from(impact: xavyo_db::models::GovRoleImpactAnalysis) -> Self {
        Self {
            role_id: impact.role_id,
            role_name: impact.role_name,
            descendant_count: impact.descendant_count,
            total_affected_users: impact.total_affected_users,
            descendants: impact
                .descendants
                .into_iter()
                .map(DescendantResponse::from)
                .collect(),
        }
    }
}

// ============================================================================
// Role CRUD Handlers
// ============================================================================

/// List governance roles.
#[utoipa::path(
    get,
    path = "/governance/roles",
    tag = "Governance - Role Hierarchy",
    params(ListRolesQuery),
    responses(
        (status = 200, description = "List of roles", body = RoleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_roles(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListRolesQuery>,
) -> ApiResult<Json<RoleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    // Parse parent_role_id filter
    let parent_filter = match query.parent_role_id.as_deref() {
        Some("null") | Some("none") => Some(None), // Root roles only
        Some(id) => Some(Some(Uuid::parse_str(id).map_err(|_| {
            ApiGovernanceError::Validation("Invalid parent_role_id format".to_string())
        })?)),
        None => None,
    };

    let filter = GovRoleFilter {
        parent_role_id: parent_filter,
        is_abstract: query.is_abstract,
        name_prefix: query.name,
    };

    let (roles, total) = state
        .role_hierarchy_service
        .list_roles(tenant_id, filter, limit, offset)
        .await?;

    let items: Vec<RoleResponse> = roles.into_iter().map(RoleResponse::from).collect();

    Ok(Json(RoleListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Create a new governance role.
#[utoipa::path(
    post,
    path = "/governance/roles",
    tag = "Governance - Role Hierarchy",
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created", body = RoleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Conflict - name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateRoleRequest>,
) -> ApiResult<Json<RoleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let created_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Validate name
    if request.name.trim().is_empty() {
        return Err(ApiGovernanceError::Validation(
            "Role name cannot be empty".to_string(),
        ));
    }
    if request.name.len() > 255 {
        return Err(ApiGovernanceError::Validation(
            "Role name cannot exceed 255 characters".to_string(),
        ));
    }

    let input = CreateGovRole {
        name: request.name,
        description: request.description,
        parent_role_id: request.parent_role_id,
        is_abstract: request.is_abstract,
    };

    let role = state
        .role_hierarchy_service
        .create_role(tenant_id, created_by, input)
        .await?;

    Ok(Json(RoleResponse::from(role)))
}

/// Get a governance role by ID.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Role details", body = RoleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<RoleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let role = state
        .role_hierarchy_service
        .get_role(tenant_id, role_id)
        .await?;

    Ok(Json(RoleResponse::from(role)))
}

/// Update a governance role.
#[utoipa::path(
    put,
    path = "/governance/roles/{role_id}",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated", body = RoleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 409, description = "Conflict - version mismatch or circular reference"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<UpdateRoleRequest>,
) -> ApiResult<Json<RoleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let updated_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Validate name if provided
    if let Some(ref name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiGovernanceError::Validation(
                "Role name cannot be empty".to_string(),
            ));
        }
        if name.len() > 255 {
            return Err(ApiGovernanceError::Validation(
                "Role name cannot exceed 255 characters".to_string(),
            ));
        }
    }

    let input = UpdateGovRole {
        name: request.name,
        description: request.description,
        parent_role_id: request.parent_role_id,
        is_abstract: request.is_abstract,
        version: request.version,
    };

    let role = state
        .role_hierarchy_service
        .update_role(tenant_id, role_id, updated_by, input)
        .await?;

    Ok(Json(RoleResponse::from(role)))
}

/// Delete a governance role.
#[utoipa::path(
    delete,
    path = "/governance/roles/{role_id}",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 204, description = "Role deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let deleted_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .role_hierarchy_service
        .delete_role(tenant_id, role_id, deleted_by)
        .await?;

    Ok(())
}

// ============================================================================
// Hierarchy Navigation Handlers
// ============================================================================

/// Get role hierarchy as tree structure.
#[utoipa::path(
    get,
    path = "/governance/roles/tree",
    tag = "Governance - Role Hierarchy",
    params(GetTreeQuery),
    responses(
        (status = 200, description = "Role hierarchy tree", body = RoleTreeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Root role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_tree(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<GetTreeQuery>,
) -> ApiResult<Json<RoleTreeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let tree = state
        .role_hierarchy_service
        .get_tree(tenant_id, query.root_role_id)
        .await?;

    let roots: Vec<RoleTreeNodeResponse> =
        tree.into_iter().map(RoleTreeNodeResponse::from).collect();

    Ok(Json(RoleTreeResponse { roots }))
}

/// Get ancestors of a role.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/ancestors",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "List of ancestor roles", body = Vec<RoleResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_ancestors(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<Vec<RoleResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let ancestors = state
        .role_hierarchy_service
        .get_ancestors(tenant_id, role_id)
        .await?;

    let items: Vec<RoleResponse> = ancestors.into_iter().map(RoleResponse::from).collect();

    Ok(Json(items))
}

/// Get descendants of a role.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/descendants",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "List of descendant roles", body = Vec<RoleResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_descendants(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<Vec<RoleResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let descendants = state
        .role_hierarchy_service
        .get_descendants(tenant_id, role_id)
        .await?;

    let items: Vec<RoleResponse> = descendants.into_iter().map(RoleResponse::from).collect();

    Ok(Json(items))
}

/// Get children of a role.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/children",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "List of child roles", body = Vec<RoleResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_children(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<Vec<RoleResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let children = state
        .role_hierarchy_service
        .get_children(tenant_id, role_id)
        .await?;

    let items: Vec<RoleResponse> = children.into_iter().map(RoleResponse::from).collect();

    Ok(Json(items))
}

// ============================================================================
// Move and Impact Handlers
// ============================================================================

/// Move a role to a new parent.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/move",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    request_body = MoveRoleRequest,
    responses(
        (status = 200, description = "Role moved", body = RoleMoveResponse),
        (status = 400, description = "Invalid request - circular reference or depth exceeded"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or parent not found"),
        (status = 409, description = "Conflict - version mismatch"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn move_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<MoveRoleRequest>,
) -> ApiResult<Json<RoleMoveResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let moved_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .role_hierarchy_service
        .move_role(
            tenant_id,
            role_id,
            request.new_parent_id,
            request.version,
            moved_by,
        )
        .await?;

    Ok(Json(RoleMoveResponse {
        role: RoleResponse::from(result.role),
        affected_roles_count: result.affected_roles_count,
        recomputed: result.recomputed,
    }))
}

/// Get impact analysis for a role.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/impact",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Impact analysis", body = ImpactAnalysisResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_impact(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<ImpactAnalysisResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let impact = state
        .role_hierarchy_service
        .get_impact(tenant_id, role_id)
        .await?;

    Ok(Json(ImpactAnalysisResponse::from(impact)))
}
