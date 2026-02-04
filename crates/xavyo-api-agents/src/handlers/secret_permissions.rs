//! HTTP handlers for agent secret permission management (F120).
//!
//! Provides endpoints for:
//! - Granting permissions to agents for secret types
//! - Revoking permissions
//! - Listing permissions

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::agent_secret_permission::{
    AgentSecretPermission, AgentSecretPermissionFilter, GrantSecretPermission,
    UpdateSecretPermission,
};

use crate::error::ApiAgentsError;
use crate::router::AgentsState;
#[cfg(feature = "openapi")]
#[allow(unused_imports)]
use crate::services::secret_permission_service::PermissionGrantResponse;

/// Query parameters for listing permissions.
#[derive(Debug, Deserialize)]
pub struct ListPermissionsQuery {
    /// Filter by secret type.
    pub secret_type: Option<String>,
    /// Only include valid (non-expired) permissions.
    #[serde(default)]
    pub valid_only: bool,
    /// Maximum results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    100
}

/// Response for listing permissions.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PermissionListResponse {
    /// List of permissions.
    pub permissions: Vec<AgentSecretPermission>,
    /// Total count (for pagination).
    pub count: usize,
}

/// Request to revoke a permission.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokePermissionRequest {
    /// The secret type to revoke permission for.
    pub secret_type: String,
}

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Extract `user_id` from JWT claims.
fn extract_user_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims.sub.parse().map_err(|_| ApiAgentsError::MissingUser)
}

/// Grant a permission to an agent for a secret type.
///
/// POST /agents/{agent_id}/secret-permissions
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{agent_id}/secret-permissions",
    request_body = GrantSecretPermission,
    responses(
        (status = 201, description = "Permission granted", body = PermissionGrantResponse),
        (status = 200, description = "Permission updated", body = PermissionGrantResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Agent or secret type not found"),
    ),
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    tag = "Secret Permissions"
))]
pub async fn grant_permission(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<GrantSecretPermission>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let granted_by = extract_user_id(&claims)?;

    let result = state
        .secret_permission_service
        .grant_permission(tenant_id, agent_id, granted_by, request)
        .await?;

    let status = if result.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((status, Json(result)))
}

/// List permissions for an agent.
///
/// GET /agents/{agent_id}/secret-permissions
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{agent_id}/secret-permissions",
    responses(
        (status = 200, description = "List of permissions", body = PermissionListResponse),
        (status = 404, description = "Agent not found"),
    ),
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID"),
        ("secret_type" = Option<String>, Query, description = "Filter by secret type"),
        ("valid_only" = Option<bool>, Query, description = "Only include valid permissions"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Pagination offset"),
    ),
    tag = "Secret Permissions"
))]
pub async fn list_agent_permissions(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<ListPermissionsQuery>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let filter = AgentSecretPermissionFilter {
        agent_id: Some(agent_id),
        secret_type: query.secret_type,
        granted_by: None,
        valid_only: query.valid_only,
    };

    let permissions = state
        .secret_permission_service
        .list_permissions(tenant_id, filter, query.limit, query.offset)
        .await?;

    let response = PermissionListResponse {
        count: permissions.len(),
        permissions,
    };

    Ok(Json(response))
}

/// Get a specific permission by ID.
///
/// GET /agents/{agent_id}/secret-permissions/{permission_id}
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{agent_id}/secret-permissions/{permission_id}",
    responses(
        (status = 200, description = "Permission details", body = AgentSecretPermission),
        (status = 404, description = "Permission not found"),
    ),
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID"),
        ("permission_id" = Uuid, Path, description = "Permission ID"),
    ),
    tag = "Secret Permissions"
))]
pub async fn get_permission(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path((_agent_id, permission_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let permission = state
        .secret_permission_service
        .get_permission(tenant_id, permission_id)
        .await?;

    Ok(Json(permission))
}

/// Update a permission.
///
/// PATCH /agents/{agent_id}/secret-permissions/{permission_id}
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/agents/{agent_id}/secret-permissions/{permission_id}",
    request_body = UpdateSecretPermission,
    responses(
        (status = 200, description = "Permission updated", body = AgentSecretPermission),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Permission not found"),
    ),
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID"),
        ("permission_id" = Uuid, Path, description = "Permission ID"),
    ),
    tag = "Secret Permissions"
))]
pub async fn update_permission(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path((_agent_id, permission_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateSecretPermission>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let permission = state
        .secret_permission_service
        .update_permission(tenant_id, permission_id, request)
        .await?;

    Ok(Json(permission))
}

/// Revoke a permission for an agent to access a secret type.
///
/// DELETE /agents/{agent_id}/secret-permissions
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/agents/{agent_id}/secret-permissions",
    request_body = RevokePermissionRequest,
    responses(
        (status = 204, description = "Permission revoked"),
        (status = 404, description = "Agent or permission not found"),
    ),
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    tag = "Secret Permissions"
))]
pub async fn revoke_permission(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<RevokePermissionRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .secret_permission_service
        .revoke_permission(tenant_id, agent_id, &request.secret_type)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Revoke all permissions for an agent.
///
/// DELETE /agents/{agent_id}/secret-permissions/all
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/agents/{agent_id}/secret-permissions/all",
    responses(
        (status = 200, description = "All permissions revoked", body = RevokeAllResponse),
        (status = 404, description = "Agent not found"),
    ),
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    tag = "Secret Permissions"
))]
pub async fn revoke_all_permissions(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let count = state
        .secret_permission_service
        .revoke_all_for_agent(tenant_id, agent_id)
        .await?;

    Ok(Json(RevokeAllResponse {
        revoked_count: count,
    }))
}

/// Response for revoking all permissions.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeAllResponse {
    /// Number of permissions revoked.
    pub revoked_count: u64,
}

/// Check if an agent has a specific permission.
///
/// GET /agents/{agent_id}/secret-permissions/check/{secret_type}
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{agent_id}/secret-permissions/check/{secret_type}",
    responses(
        (status = 200, description = "Permission valid", body = AgentSecretPermission),
        (status = 403, description = "Permission denied or expired"),
        (status = 404, description = "Agent not found"),
    ),
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID"),
        ("secret_type" = String, Path, description = "Secret type to check"),
    ),
    tag = "Secret Permissions"
))]
pub async fn check_permission(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, secret_type)): Path<(Uuid, String)>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let permission = state
        .secret_permission_service
        .check_permission(tenant_id, agent_id, &secret_type)
        .await?;

    Ok(Json(permission))
}
