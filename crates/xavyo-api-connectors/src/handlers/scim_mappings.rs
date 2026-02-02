//! HTTP handlers for SCIM target attribute mapping management (F087).
//!
//! Provides endpoints to list, replace, and reset attribute mappings
//! for SCIM outbound provisioning targets.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateScimTargetAttributeMapping, ScimTarget, ScimTargetAttributeMapping};

use crate::error::{ConnectorApiError, Result};
use crate::handlers::scim_targets::ScimTargetState;

/// Query parameters for listing attribute mappings.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListMappingsQuery {
    pub resource_type: Option<String>,
}

/// Request body for replacing attribute mappings.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReplaceMappingsRequest {
    pub mappings: Vec<MappingEntry>,
}

/// A single mapping entry in a replace request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MappingEntry {
    pub source_field: String,
    pub target_scim_path: String,
    #[serde(default = "default_mapping_type")]
    pub mapping_type: String,
    pub constant_value: Option<String>,
    pub transform: Option<String>,
    pub resource_type: String,
}

fn default_mapping_type() -> String {
    "direct".to_string()
}

/// Response for mapping list.
#[derive(Debug, Serialize, ToSchema)]
pub struct MappingListResponse {
    pub target_id: Uuid,
    pub mappings: Vec<ScimTargetAttributeMapping>,
    pub total_count: usize,
}

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ConnectorApiError::Unauthorized {
            message: "Missing tenant_id in claims".to_string(),
        })
}

/// GET /admin/scim-targets/:id/mappings — List attribute mappings for a target.
#[utoipa::path(
    get,
    path = "/admin/scim-targets/{target_id}/mappings",
    tag = "SCIM Target Mappings",
    params(
        ("target_id" = Uuid, Path, description = "SCIM target ID"),
        ListMappingsQuery
    ),
    responses(
        (status = 200, description = "List of attribute mappings", body = MappingListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_mappings(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
    Query(query): Query<ListMappingsQuery>,
) -> Result<Json<MappingListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();

    // Verify the target exists and belongs to this tenant.
    ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    let mappings = ScimTargetAttributeMapping::list_by_target(
        pool,
        tenant_id,
        target_id,
        query.resource_type.as_deref(),
    )
    .await?;

    let total_count = mappings.len();

    Ok(Json(MappingListResponse {
        target_id,
        mappings,
        total_count,
    }))
}

/// PUT /admin/scim-targets/:id/mappings — Replace all attribute mappings for a target.
#[utoipa::path(
    put,
    path = "/admin/scim-targets/{target_id}/mappings",
    tag = "SCIM Target Mappings",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    request_body = ReplaceMappingsRequest,
    responses(
        (status = 200, description = "Mappings replaced", body = MappingListResponse),
        (status = 400, description = "Invalid mapping configuration"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn replace_mappings(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
    Json(body): Json<ReplaceMappingsRequest>,
) -> Result<Json<MappingListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();

    // Verify the target exists and belongs to this tenant.
    ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    // Validate entries.
    for entry in &body.mappings {
        if entry.source_field.is_empty() {
            return Err(ConnectorApiError::Validation(
                "source_field cannot be empty".to_string(),
            ));
        }
        if entry.target_scim_path.is_empty() {
            return Err(ConnectorApiError::Validation(
                "target_scim_path cannot be empty".to_string(),
            ));
        }
        if !["direct", "constant", "expression"].contains(&entry.mapping_type.as_str()) {
            return Err(ConnectorApiError::Validation(format!(
                "Invalid mapping_type '{}'; must be direct, constant, or expression",
                entry.mapping_type,
            )));
        }
        if !["user", "group"].contains(&entry.resource_type.as_str()) {
            return Err(ConnectorApiError::Validation(format!(
                "Invalid resource_type '{}'; must be user or group",
                entry.resource_type,
            )));
        }
    }

    let create_mappings: Vec<CreateScimTargetAttributeMapping> = body
        .mappings
        .into_iter()
        .map(|e| CreateScimTargetAttributeMapping {
            tenant_id,
            target_id,
            source_field: e.source_field,
            target_scim_path: e.target_scim_path,
            mapping_type: e.mapping_type,
            constant_value: e.constant_value,
            transform: e.transform,
            resource_type: e.resource_type,
        })
        .collect();

    let mappings = ScimTargetAttributeMapping::replace_all_for_target(
        pool,
        tenant_id,
        target_id,
        &create_mappings,
    )
    .await?;

    let total_count = mappings.len();

    Ok(Json(MappingListResponse {
        target_id,
        mappings,
        total_count,
    }))
}

/// POST /admin/scim-targets/:id/mappings/defaults — Reset mappings to defaults.
#[utoipa::path(
    post,
    path = "/admin/scim-targets/{target_id}/mappings/defaults",
    tag = "SCIM Target Mappings",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    responses(
        (status = 200, description = "Mappings reset to defaults", body = MappingListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn reset_mapping_defaults(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
) -> Result<(StatusCode, Json<MappingListResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();

    // Verify the target exists and belongs to this tenant.
    ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    // Delete existing and insert defaults atomically.
    let mappings =
        ScimTargetAttributeMapping::reset_to_defaults(pool, tenant_id, target_id).await?;

    let total_count = mappings.len();

    Ok((
        StatusCode::OK,
        Json(MappingListResponse {
            target_id,
            mappings,
            total_count,
        }),
    ))
}
