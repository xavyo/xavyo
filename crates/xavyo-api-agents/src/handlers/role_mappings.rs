//! IAM Role Mapping handlers for Workload Identity Federation (F121).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    CreateIamRoleMapping, IamRoleMapping, IamRoleMappingFilter, UpdateIamRoleMapping,
};

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Extract `user_id` from JWT claims (uses sub field).
fn extract_user_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiAgentsError::MissingUser)
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request to create a role mapping.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateRoleMappingRequest {
    /// Identity provider configuration ID.
    pub provider_config_id: Uuid,
    /// Agent type (NULL for default mapping).
    pub agent_type: Option<String>,
    /// Role identifier (AWS ARN, GCP SA email, Azure client ID).
    pub role_identifier: String,
    /// Allowed scopes/permissions.
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    /// Maximum TTL in seconds (15 min to 12 hours).
    #[serde(default = "default_ttl")]
    pub max_ttl_seconds: i32,
    /// Additional constraints (JSON).
    #[serde(default = "default_constraints")]
    pub constraints: serde_json::Value,
}

fn default_ttl() -> i32 {
    3600 // 1 hour
}

fn default_constraints() -> serde_json::Value {
    serde_json::json!({})
}

/// Request to update a role mapping.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateRoleMappingRequest {
    /// Role identifier (AWS ARN, GCP SA email, Azure client ID).
    pub role_identifier: Option<String>,
    /// Allowed scopes/permissions.
    pub allowed_scopes: Option<Vec<String>>,
    /// Maximum TTL in seconds.
    pub max_ttl_seconds: Option<i32>,
    /// Additional constraints (JSON).
    pub constraints: Option<serde_json::Value>,
}

/// Query parameters for listing role mappings.
#[derive(Debug, Default, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListRoleMappingsQuery {
    /// Filter by provider configuration ID.
    pub provider_config_id: Option<Uuid>,
    /// Filter by agent type.
    pub agent_type: Option<String>,
}

/// Response for a role mapping.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleMappingResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider_config_id: Uuid,
    pub agent_type: Option<String>,
    pub role_identifier: String,
    pub allowed_scopes: Vec<String>,
    pub max_ttl_seconds: i32,
    pub constraints: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<IamRoleMapping> for RoleMappingResponse {
    fn from(mapping: IamRoleMapping) -> Self {
        Self {
            id: mapping.id,
            tenant_id: mapping.tenant_id,
            provider_config_id: mapping.provider_config_id,
            agent_type: mapping.agent_type,
            role_identifier: mapping.role_identifier,
            allowed_scopes: mapping.allowed_scopes,
            max_ttl_seconds: mapping.max_ttl_seconds,
            constraints: mapping.constraints,
            created_at: mapping.created_at,
            updated_at: mapping.updated_at,
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /role-mappings - Create a new IAM role mapping.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/role-mappings",
    tag = "Role Mappings",
    operation_id = "createRoleMapping",
    request_body = CreateRoleMappingRequest,
    responses(
        (status = 201, description = "Role mapping created", body = RoleMappingResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Identity provider not found"),
        (status = 409, description = "Duplicate mapping for agent_type")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_role_mapping(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateRoleMappingRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;

    // Verify provider exists
    let provider = state
        .identity_provider_service
        .get_provider(tenant_id, request.provider_config_id)
        .await?;

    let create_request = CreateIamRoleMapping {
        provider_config_id: request.provider_config_id,
        agent_type: request.agent_type,
        role_identifier: request.role_identifier,
        allowed_scopes: request.allowed_scopes,
        max_ttl_seconds: request.max_ttl_seconds,
        constraints: request.constraints,
    };

    // Validate the request
    state
        .role_mapping_service
        .validate_mapping_request(&create_request)?;

    let mapping = state
        .role_mapping_service
        .create_mapping(
            tenant_id,
            user_id,
            &provider.provider_type.clone(),
            &create_request,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(RoleMappingResponse::from(mapping)),
    ))
}

/// GET /role-mappings - List IAM role mappings.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/role-mappings",
    tag = "Role Mappings",
    operation_id = "listRoleMappings",
    params(ListRoleMappingsQuery),
    responses(
        (status = 200, description = "List of role mappings", body = Vec<RoleMappingResponse>),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_role_mappings(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListRoleMappingsQuery>,
) -> Result<Json<Vec<RoleMappingResponse>>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let filter = IamRoleMappingFilter {
        provider_config_id: query.provider_config_id,
        agent_type: query.agent_type,
    };

    let mappings = state
        .role_mapping_service
        .list_mappings(tenant_id, &filter)
        .await?;

    let response: Vec<RoleMappingResponse> = mappings.into_iter().map(Into::into).collect();

    Ok(Json(response))
}

/// GET /role-mappings/{id} - Get IAM role mapping by ID.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/role-mappings/{id}",
    tag = "Role Mappings",
    operation_id = "getRoleMapping",
    params(
        ("id" = Uuid, Path, description = "Role mapping ID")
    ),
    responses(
        (status = 200, description = "Role mapping", body = RoleMappingResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Role mapping not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_role_mapping(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<RoleMappingResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let mapping = state
        .role_mapping_service
        .get_mapping(tenant_id, id)
        .await?;

    Ok(Json(RoleMappingResponse::from(mapping)))
}

/// PATCH /role-mappings/{id} - Update IAM role mapping.
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/role-mappings/{id}",
    tag = "Role Mappings",
    operation_id = "updateRoleMapping",
    params(
        ("id" = Uuid, Path, description = "Role mapping ID")
    ),
    request_body = UpdateRoleMappingRequest,
    responses(
        (status = 200, description = "Role mapping updated", body = RoleMappingResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Role mapping not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn update_role_mapping(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateRoleMappingRequest>,
) -> Result<Json<RoleMappingResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;

    // Get existing mapping to know the provider
    let existing = state
        .role_mapping_service
        .get_mapping(tenant_id, id)
        .await?;

    // Get provider to get provider_type for audit log
    let provider = state
        .identity_provider_service
        .get_provider(tenant_id, existing.provider_config_id)
        .await?;

    let update_request = UpdateIamRoleMapping {
        role_identifier: request.role_identifier,
        allowed_scopes: request.allowed_scopes,
        max_ttl_seconds: request.max_ttl_seconds,
        constraints: request.constraints,
    };

    let mapping = state
        .role_mapping_service
        .update_mapping(
            tenant_id,
            user_id,
            id,
            &provider.provider_type.clone(),
            &update_request,
        )
        .await?;

    Ok(Json(RoleMappingResponse::from(mapping)))
}

/// DELETE /role-mappings/{id} - Delete IAM role mapping.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/role-mappings/{id}",
    tag = "Role Mappings",
    operation_id = "deleteRoleMapping",
    params(
        ("id" = Uuid, Path, description = "Role mapping ID")
    ),
    responses(
        (status = 204, description = "Role mapping deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Role mapping not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn delete_role_mapping(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;

    // Get existing mapping to know the provider
    let existing = state
        .role_mapping_service
        .get_mapping(tenant_id, id)
        .await?;

    // Get provider to get provider_type for audit log
    let provider = state
        .identity_provider_service
        .get_provider(tenant_id, existing.provider_config_id)
        .await?;

    state
        .role_mapping_service
        .delete_mapping(tenant_id, user_id, id, &provider.provider_type.clone())
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
