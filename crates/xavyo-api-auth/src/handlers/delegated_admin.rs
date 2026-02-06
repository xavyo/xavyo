//! HTTP handlers for delegated administration endpoints (F029).
//!
//! Admin endpoints for managing granular permissions:
//! - GET /admin/delegation/permissions - List all permissions
//! - GET /admin/delegation/role-templates - List role templates
//! - POST /admin/delegation/role-templates - Create role template
//! - GET /admin/delegation/role-templates/:id - Get role template
//! - PUT /admin/delegation/role-templates/:id - Update role template
//! - DELETE /admin/delegation/role-templates/:id - Delete role template
//! - GET /admin/delegation/assignments - List assignments
//! - POST /admin/delegation/assignments - Create assignment
//! - GET /admin/delegation/assignments/:id - Get assignment
//! - DELETE /admin/delegation/assignments/:id - Revoke assignment
//! - GET /admin/delegation/audit-log - Get audit log

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::ApiAuthError;
use crate::models::{
    AssignmentDetailResponse, AssignmentListResponse, AssignmentResponse, AuditLogQuery,
    AuditLogResponse, CategorySummaryResponse, CreateAssignmentRequest, CreateRoleTemplateRequest,
    ListAssignmentsQuery, ListTemplatesQuery, PermissionListResponse, PermissionResponse,
    RoleTemplateDetailResponse, RoleTemplateListResponse, UpdateRoleTemplateRequest,
};
use crate::services::DelegatedAdminService;
use xavyo_db::{AssignmentFilter, AuditLogFilter};

// ============================================================================
// Permission Handlers (US3)
// ============================================================================

/// List all system-defined permissions with categories.
///
/// Requires authentication. Only accessible by authenticated admin users.
#[utoipa::path(
    get,
    path = "/admin/delegation/permissions",
    responses(
        (status = 200, description = "List of permissions", body = PermissionListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn list_permissions(
    Extension(_claims): Extension<JwtClaims>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
) -> Result<Json<PermissionListResponse>, ApiAuthError> {
    // Authentication is verified by the presence of valid JwtClaims.
    // The /admin/* routes are protected by auth middleware, so reaching here
    // means the user is authenticated. Permission listing is read-only metadata
    // about available permissions, safe for any authenticated admin user.
    let permissions = delegation_service.list_permissions().await?;
    let categories = delegation_service.get_category_summaries().await?;

    Ok(Json(PermissionListResponse {
        permissions,
        categories: categories
            .into_iter()
            .map(|c| CategorySummaryResponse {
                name: c.name,
                permission_count: c.permission_count,
            })
            .collect(),
    }))
}

/// Get permissions for a specific category.
///
/// Requires authentication. Only accessible by authenticated admin users.
#[utoipa::path(
    get,
    path = "/admin/delegation/permissions/{category}",
    params(
        ("category" = String, Path, description = "Permission category"),
    ),
    responses(
        (status = 200, description = "Permissions for category", body = Vec<PermissionResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn get_permissions_by_category(
    Extension(_claims): Extension<JwtClaims>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Path(category): Path<String>,
) -> Result<Json<Vec<PermissionResponse>>, ApiAuthError> {
    // Authentication is verified by the presence of valid JwtClaims.
    // Permission listing by category is read-only metadata, safe for any
    // authenticated admin user.
    let permissions = delegation_service
        .get_permissions_by_category(&category)
        .await?;
    Ok(Json(permissions))
}

// ============================================================================
// Role Template Handlers (US2)
// ============================================================================

/// List all role templates.
#[utoipa::path(
    get,
    path = "/admin/delegation/role-templates",
    params(ListTemplatesQuery),
    responses(
        (status = 200, description = "List of role templates", body = RoleTemplateListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn list_role_templates(
    Extension(tenant_id): Extension<TenantId>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Query(query): Query<ListTemplatesQuery>,
) -> Result<Json<RoleTemplateListResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let (templates, total) = delegation_service
        .list_role_templates(tenant_uuid, query.include_system)
        .await?;

    Ok(Json(RoleTemplateListResponse { templates, total }))
}

/// Create a new role template.
#[utoipa::path(
    post,
    path = "/admin/delegation/role-templates",
    request_body = CreateRoleTemplateRequest,
    responses(
        (status = 201, description = "Role template created", body = RoleTemplateDetailResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn create_role_template(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Json(request): Json<CreateRoleTemplateRequest>,
) -> Result<(StatusCode, Json<RoleTemplateDetailResponse>), ApiAuthError> {
    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)?;

    let template = delegation_service
        .create_role_template(
            tenant_uuid,
            user_id,
            request.name,
            request.description,
            request.permissions,
            None, // ip_address - could extract from request headers
            None, // user_agent - could extract from request headers
        )
        .await?;

    // Fetch the full detail response with permissions
    let detail = delegation_service
        .get_role_template(tenant_uuid, template.id)
        .await?;

    Ok((StatusCode::CREATED, Json(detail)))
}

/// Get a specific role template with its permissions.
#[utoipa::path(
    get,
    path = "/admin/delegation/role-templates/{id}",
    params(
        ("id" = Uuid, Path, description = "Template ID"),
    ),
    responses(
        (status = 200, description = "Role template details", body = RoleTemplateDetailResponse),
        (status = 404, description = "Template not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn get_role_template(
    Extension(tenant_id): Extension<TenantId>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Path(template_id): Path<Uuid>,
) -> Result<Json<RoleTemplateDetailResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let template = delegation_service
        .get_role_template(tenant_uuid, template_id)
        .await?;

    Ok(Json(template))
}

/// Update an existing role template.
#[utoipa::path(
    put,
    path = "/admin/delegation/role-templates/{id}",
    params(
        ("id" = Uuid, Path, description = "Template ID"),
    ),
    request_body = UpdateRoleTemplateRequest,
    responses(
        (status = 200, description = "Role template updated", body = RoleTemplateDetailResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Template not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn update_role_template(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Path(template_id): Path<Uuid>,
    Json(request): Json<UpdateRoleTemplateRequest>,
) -> Result<Json<RoleTemplateDetailResponse>, ApiAuthError> {
    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)?;

    let _template = delegation_service
        .update_role_template(
            tenant_uuid,
            user_id,
            template_id,
            request.name,
            request.description,
            request.permissions,
            None, // ip_address
            None, // user_agent
        )
        .await?;

    // Return the full detail response with permissions
    let detail = delegation_service
        .get_role_template(tenant_uuid, template_id)
        .await?;

    Ok(Json(detail))
}

/// Delete a role template (system templates cannot be deleted).
#[utoipa::path(
    delete,
    path = "/admin/delegation/role-templates/{id}",
    params(
        ("id" = Uuid, Path, description = "Template ID"),
    ),
    responses(
        (status = 204, description = "Role template deleted"),
        (status = 404, description = "Template not found"),
        (status = 409, description = "Cannot delete system template"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn delete_role_template(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Path(template_id): Path<Uuid>,
) -> Result<StatusCode, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)?;

    delegation_service
        .delete_role_template(
            tenant_uuid,
            user_id,
            template_id,
            None, // ip_address
            None, // user_agent
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Assignment Handlers (US1, US5)
// ============================================================================

/// List role assignments with optional filtering.
#[utoipa::path(
    get,
    path = "/admin/delegation/assignments",
    params(ListAssignmentsQuery),
    responses(
        (status = 200, description = "List of assignments", body = AssignmentListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn list_assignments(
    Extension(tenant_id): Extension<TenantId>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Query(query): Query<ListAssignmentsQuery>,
) -> Result<Json<AssignmentListResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let query = query.validated();

    let filter = AssignmentFilter {
        user_id: query.user_id,
        template_id: query.template_id,
        include_expired: query.include_expired,
        include_revoked: query.include_revoked,
    };

    let (assignments, total) = delegation_service
        .list_assignments(tenant_uuid, filter, query.cursor, query.limit)
        .await?;

    // Compute next_cursor if there are more results
    let next_cursor = if assignments.len() as i32 >= query.limit {
        assignments.last().map(|a| a.assigned_at)
    } else {
        None
    };

    Ok(Json(AssignmentListResponse {
        assignments,
        total,
        next_cursor,
    }))
}

/// Create a new role assignment for a user.
#[utoipa::path(
    post,
    path = "/admin/delegation/assignments",
    request_body = CreateAssignmentRequest,
    responses(
        (status = 201, description = "Assignment created", body = AssignmentResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn create_assignment(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Json(request): Json<CreateAssignmentRequest>,
) -> Result<(StatusCode, Json<AssignmentResponse>), ApiAuthError> {
    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_uuid = *tenant_id.as_uuid();
    let assigned_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)?;

    let assignment = delegation_service
        .create_assignment(
            tenant_uuid,
            assigned_by,
            request.user_id,
            request.template_id,
            request.scope_type,
            request.scope_value,
            request.expires_at,
            None, // ip_address
            None, // user_agent
        )
        .await?;

    Ok((StatusCode::CREATED, Json(assignment)))
}

/// Get a specific assignment with template details.
#[utoipa::path(
    get,
    path = "/admin/delegation/assignments/{id}",
    params(
        ("id" = Uuid, Path, description = "Assignment ID"),
    ),
    responses(
        (status = 200, description = "Assignment details", body = AssignmentDetailResponse),
        (status = 404, description = "Assignment not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn get_assignment(
    Extension(tenant_id): Extension<TenantId>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Path(assignment_id): Path<Uuid>,
) -> Result<Json<AssignmentDetailResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let assignment = delegation_service
        .get_assignment(tenant_uuid, assignment_id)
        .await?;

    // Get template details
    let template = delegation_service
        .get_role_template(tenant_uuid, assignment.template_id)
        .await
        .ok(); // Template might not exist or be inaccessible

    Ok(Json(AssignmentDetailResponse {
        assignment,
        template,
    }))
}

/// Revoke an assignment (soft delete).
#[utoipa::path(
    delete,
    path = "/admin/delegation/assignments/{id}",
    params(
        ("id" = Uuid, Path, description = "Assignment ID"),
    ),
    responses(
        (status = 204, description = "Assignment revoked"),
        (status = 404, description = "Assignment not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn revoke_assignment(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Path(assignment_id): Path<Uuid>,
) -> Result<StatusCode, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let revoked_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)?;

    delegation_service
        .revoke_assignment(
            tenant_uuid,
            assignment_id,
            revoked_by,
            None, // ip_address
            None, // user_agent
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// User Effective Permissions Handler
// ============================================================================

/// Get the effective permissions for a specific user.
#[utoipa::path(
    get,
    path = "/admin/delegation/users/{user_id}/permissions",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User's effective permissions", body = EffectivePermissions),
        (status = 404, description = "User not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn get_user_permissions(
    Extension(tenant_id): Extension<TenantId>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<crate::models::EffectivePermissions>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let effective = delegation_service
        .get_user_effective_permissions(tenant_uuid, user_id)
        .await?;

    Ok(Json(effective))
}

// ============================================================================
// Audit Log Handlers (US4)
// ============================================================================

/// Get audit log entries with optional filtering.
#[utoipa::path(
    get,
    path = "/admin/delegation/audit-log",
    params(AuditLogQuery),
    responses(
        (status = 200, description = "Audit log entries", body = AuditLogResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn get_audit_log(
    Extension(tenant_id): Extension<TenantId>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let query = query.validated();

    let filter = AuditLogFilter {
        admin_user_id: query.admin_user_id,
        action: query.action,
        resource_type: query.resource_type,
        start_date: query.start_date,
        end_date: query.end_date,
    };

    let (entries, total) = delegation_service
        .get_audit_log(tenant_uuid, filter, query.cursor, query.limit)
        .await?;

    // Compute next_cursor if there are more results
    let next_cursor = if entries.len() as i32 >= query.limit {
        entries.last().map(|e| e.created_at)
    } else {
        None
    };

    Ok(Json(AuditLogResponse {
        entries,
        total,
        next_cursor,
    }))
}

// ============================================================================
// Permission Check Handler (for debugging/testing)
// ============================================================================

/// Check permission request body.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct CheckPermissionRequest {
    pub user_id: Uuid,
    pub permission: String,
}

/// Check permission response body.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CheckPermissionResponse {
    pub has_permission: bool,
    pub is_super_admin: bool,
}

/// Check if a user has a specific permission.
#[utoipa::path(
    post,
    path = "/admin/delegation/check-permission",
    request_body = CheckPermissionRequest,
    responses(
        (status = 200, description = "Permission check result", body = CheckPermissionResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Delegated Admin"
)]
pub async fn check_permission(
    Extension(tenant_id): Extension<TenantId>,
    Extension(delegation_service): Extension<Arc<DelegatedAdminService>>,
    Json(request): Json<CheckPermissionRequest>,
) -> Result<Json<CheckPermissionResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let has_permission = delegation_service
        .has_permission(tenant_uuid, request.user_id, &request.permission)
        .await?;

    Ok(Json(CheckPermissionResponse {
        has_permission,
        is_super_admin: false, // Can't check without claims
    }))
}
