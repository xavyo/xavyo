//! Role inheritance block handlers for governance API (F088).
//!
//! Provides endpoints for managing inheritance blocks, which allow a role
//! to explicitly exclude specific entitlements from being inherited from ancestors.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::{GovApplication, GovEntitlement};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::router::GovernanceState;

// ============================================================================
// Request/Response Models
// ============================================================================

/// Request to add an inheritance block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AddInheritanceBlockRequest {
    /// The entitlement ID to block from inheritance.
    pub entitlement_id: Uuid,
}

/// Inheritance block response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InheritanceBlockResponse {
    pub id: Uuid,
    pub role_id: Uuid,
    pub entitlement_id: Uuid,
    pub created_by: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<xavyo_db::models::GovRoleInheritanceBlock> for InheritanceBlockResponse {
    fn from(block: xavyo_db::models::GovRoleInheritanceBlock) -> Self {
        Self {
            id: block.id,
            role_id: block.role_id,
            entitlement_id: block.entitlement_id,
            created_by: block.created_by,
            created_at: block.created_at,
        }
    }
}

/// Inheritance block with details response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InheritanceBlockDetailsResponse {
    pub id: Uuid,
    pub entitlement_id: Uuid,
    pub entitlement_name: String,
    pub application_name: Option<String>,
    pub created_by: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<xavyo_db::models::InheritanceBlockDetails> for InheritanceBlockDetailsResponse {
    fn from(block: xavyo_db::models::InheritanceBlockDetails) -> Self {
        Self {
            id: block.id,
            entitlement_id: block.entitlement_id,
            entitlement_name: block.entitlement_name,
            application_name: block.application_name,
            created_by: block.created_by,
            created_at: block.created_at,
        }
    }
}

// ============================================================================
// Inheritance Block Handlers
// ============================================================================

/// List inheritance blocks for a role.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/inheritance-blocks",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "List of inheritance blocks", body = Vec<InheritanceBlockDetailsResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_inheritance_blocks(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<Vec<InheritanceBlockDetailsResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let blocks = state
        .role_hierarchy_service
        .list_inheritance_blocks(tenant_id, role_id)
        .await?;

    let items: Vec<InheritanceBlockDetailsResponse> = blocks
        .into_iter()
        .map(InheritanceBlockDetailsResponse::from)
        .collect();

    Ok(Json(items))
}

/// Add an inheritance block to a role.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/inheritance-blocks",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    request_body = AddInheritanceBlockRequest,
    responses(
        (status = 201, description = "Inheritance block added", body = InheritanceBlockDetailsResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or entitlement not found"),
        (status = 409, description = "Conflict - block already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_inheritance_block(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<AddInheritanceBlockRequest>,
) -> ApiResult<Json<InheritanceBlockDetailsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let created_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let block = state
        .role_hierarchy_service
        .add_inheritance_block(tenant_id, role_id, request.entitlement_id, created_by)
        .await?;

    Ok(Json(
        inheritance_block_details(state.pool(), tenant_id, block).await?,
    ))
}

async fn inheritance_block_details(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    block: xavyo_db::models::GovRoleInheritanceBlock,
) -> ApiResult<InheritanceBlockDetailsResponse> {
    let entitlement = GovEntitlement::find_by_id(pool, tenant_id, block.entitlement_id)
        .await?
        .ok_or_else(|| {
            ApiGovernanceError::NotFound(format!("Entitlement {} not found", block.entitlement_id))
        })?;
    let application_name = GovApplication::find_by_id(pool, tenant_id, entitlement.application_id)
        .await?
        .map(|app| app.name);
    Ok(InheritanceBlockDetailsResponse {
        id: block.id,
        entitlement_id: block.entitlement_id,
        entitlement_name: entitlement.name,
        application_name,
        created_by: block.created_by,
        created_at: block.created_at,
    })
}

/// Remove an inheritance block from a role.
#[utoipa::path(
    delete,
    path = "/governance/roles/{role_id}/inheritance-blocks/{block_id}",
    tag = "Governance - Role Hierarchy",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("block_id" = Uuid, Path, description = "Inheritance block ID")
    ),
    responses(
        (status = 204, description = "Inheritance block removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or block not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_inheritance_block(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, block_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let deleted_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .role_hierarchy_service
        .remove_inheritance_block(tenant_id, role_id, block_id, deleted_by)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn add_inheritance_block_returns_entitlement_details() {
        let src = include_str!("role_inheritance_blocks.rs");
        let production = src.split("mod tests").next().expect("production source");
        let add = production
            .split("pub async fn add_inheritance_block")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("add_inheritance_block");
        assert!(
            add.contains("inheritance_block_details(")
                && add.contains("InheritanceBlockDetailsResponse")
                && !add.contains("InheritanceBlockResponse::from(block)"),
            "POST inheritance-blocks must return entitlement_name and application_name"
        );
    }
}
