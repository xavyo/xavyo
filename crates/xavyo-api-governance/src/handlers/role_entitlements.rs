//! Role entitlement handlers for governance API (F088).
//!
//! Provides endpoints for managing role-entitlement mappings and
//! viewing effective entitlements (direct + inherited).

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::router::GovernanceState;

// ============================================================================
// Request/Response Models
// ============================================================================

/// Request to add an entitlement to a role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AddRoleEntitlementRequest {
    /// The entitlement ID to add.
    pub entitlement_id: Uuid,
}

/// Role entitlement response (direct mapping).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleEntitlementResponse {
    pub id: Uuid,
    pub role_id: Option<Uuid>,
    pub role_name: String,
    pub entitlement_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Uuid,
}

impl From<xavyo_db::models::GovRoleEntitlement> for RoleEntitlementResponse {
    fn from(e: xavyo_db::models::GovRoleEntitlement) -> Self {
        Self {
            id: e.id,
            role_id: e.role_id,
            role_name: e.role_name,
            entitlement_id: e.entitlement_id,
            created_at: e.created_at,
            created_by: e.created_by,
        }
    }
}

/// Effective entitlement response (includes inheritance info).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EffectiveEntitlementResponse {
    pub entitlement_id: Uuid,
    pub entitlement_name: String,
    pub application_name: Option<String>,
    pub source_role_id: Uuid,
    pub source_role_name: String,
    pub is_inherited: bool,
}

impl From<xavyo_db::models::EffectiveEntitlementDetails> for EffectiveEntitlementResponse {
    fn from(e: xavyo_db::models::EffectiveEntitlementDetails) -> Self {
        Self {
            entitlement_id: e.entitlement_id,
            entitlement_name: e.entitlement_name,
            application_name: e.application_name,
            source_role_id: e.source_role_id,
            source_role_name: e.source_role_name,
            is_inherited: e.is_inherited,
        }
    }
}

/// Effective entitlements list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EffectiveEntitlementsResponse {
    pub items: Vec<EffectiveEntitlementResponse>,
    pub direct_count: i64,
    pub inherited_count: i64,
    pub total: i64,
}

// ============================================================================
// Role Entitlement Handlers
// ============================================================================

/// List direct entitlements for a role.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/entitlements",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "List of direct entitlements", body = Vec<RoleEntitlementResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_role_entitlements(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<Vec<RoleEntitlementResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let entitlements = state
        .role_hierarchy_service
        .list_role_entitlements(tenant_id, role_id)
        .await?;

    let items: Vec<RoleEntitlementResponse> = entitlements
        .into_iter()
        .map(RoleEntitlementResponse::from)
        .collect();

    Ok(Json(items))
}

/// Add an entitlement to a role.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/entitlements",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    request_body = AddRoleEntitlementRequest,
    responses(
        (status = 201, description = "Entitlement added", body = RoleEntitlementResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or entitlement not found"),
        (status = 409, description = "Conflict - entitlement already mapped"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_role_entitlement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<AddRoleEntitlementRequest>,
) -> ApiResult<Json<RoleEntitlementResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let created_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let mapping = state
        .role_hierarchy_service
        .add_role_entitlement(tenant_id, role_id, request.entitlement_id, created_by)
        .await?;

    Ok(Json(RoleEntitlementResponse::from(mapping)))
}

/// Remove an entitlement from a role.
#[utoipa::path(
    delete,
    path = "/governance/roles/{role_id}/entitlements/{entitlement_id}",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("entitlement_id" = Uuid, Path, description = "Entitlement ID")
    ),
    responses(
        (status = 204, description = "Entitlement removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or mapping not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_role_entitlement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, entitlement_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .role_hierarchy_service
        .remove_role_entitlement(tenant_id, role_id, entitlement_id)
        .await?;

    Ok(())
}

/// Get effective entitlements for a role (direct + inherited).
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/effective-entitlements",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Effective entitlements", body = EffectiveEntitlementsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_effective_entitlements(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<EffectiveEntitlementsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let entitlements = state
        .role_hierarchy_service
        .get_effective_entitlements(tenant_id, role_id)
        .await?;

    let direct_count = entitlements.iter().filter(|e| !e.is_inherited).count() as i64;
    let inherited_count = entitlements.iter().filter(|e| e.is_inherited).count() as i64;
    let total = entitlements.len() as i64;

    let items: Vec<EffectiveEntitlementResponse> = entitlements
        .into_iter()
        .map(EffectiveEntitlementResponse::from)
        .collect();

    Ok(Json(EffectiveEntitlementsResponse {
        items,
        direct_count,
        inherited_count,
        total,
    }))
}

/// Trigger recomputation of effective entitlements for a role.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/effective-entitlements/recompute",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Recomputation completed", body = RecomputeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn recompute_effective_entitlements(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<RecomputeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let affected_count = state
        .role_hierarchy_service
        .recompute_effective_entitlements(tenant_id, role_id)
        .await?;

    Ok(Json(RecomputeResponse { affected_count }))
}

/// Recompute response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RecomputeResponse {
    /// Number of roles affected by the recomputation.
    pub affected_count: i64,
}
