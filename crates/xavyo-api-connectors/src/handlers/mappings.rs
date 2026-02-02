//! Mapping API handlers.
//!
//! Handles attribute mapping CRUD and preview operations.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ConnectorApiError, Result};
use crate::router::ConnectorState;
use crate::services::{
    CreateMappingRequest, MappingResponse, PreviewMappingRequest, PreviewMappingResponse,
    UpdateMappingRequest,
};

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ConnectorApiError::Validation(
            "Missing tenant_id in claims".to_string(),
        ))
}

/// Query parameters for listing mappings.
#[derive(Debug, Clone, Deserialize)]
pub struct ListMappingsQuery {
    /// Filter by object class.
    pub object_class: Option<String>,
}

/// Create a new attribute mapping.
///
/// POST /connectors/{connector_id}/mappings
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/mappings",
    request_body = CreateMappingRequest,
    responses(
        (status = 201, description = "Mapping created", body = MappingResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Connector not found"),
    ),
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
    ),
    tag = "mappings"
)]
pub async fn create_mapping(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Json(request): Json<CreateMappingRequest>,
) -> Result<(StatusCode, Json<MappingResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Get tenant_id from connector (validates connector exists)
    let connector = state
        .connector_service
        .get_connector(tenant_id, connector_id)
        .await?;

    let mapping = state
        .mapping_service
        .create_mapping(tenant_id, connector.id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(mapping)))
}

/// List mappings for a connector.
///
/// GET /connectors/{connector_id}/mappings
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/mappings",
    responses(
        (status = 200, description = "Mappings list", body = Vec<MappingResponse>),
        (status = 404, description = "Connector not found"),
    ),
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("object_class" = Option<String>, Query, description = "Filter by object class"),
    ),
    tag = "mappings"
)]
pub async fn list_mappings(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Query(query): Query<ListMappingsQuery>,
) -> Result<Json<Vec<MappingResponse>>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let mappings = state
        .mapping_service
        .list_mappings(tenant_id, connector_id, query.object_class.as_deref())
        .await?;

    Ok(Json(mappings))
}

/// Get a specific mapping.
///
/// GET /connectors/{connector_id}/mappings/{mapping_id}
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/mappings/{mapping_id}",
    responses(
        (status = 200, description = "Mapping details", body = MappingResponse),
        (status = 404, description = "Mapping not found"),
    ),
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("mapping_id" = Uuid, Path, description = "Mapping ID"),
    ),
    tag = "mappings"
)]
pub async fn get_mapping(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path((_connector_id, mapping_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MappingResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let mapping = state
        .mapping_service
        .get_mapping(tenant_id, mapping_id)
        .await?;

    Ok(Json(mapping))
}

/// Update a mapping.
///
/// PUT /connectors/{connector_id}/mappings/{mapping_id}
#[utoipa::path(
    put,
    path = "/connectors/{connector_id}/mappings/{mapping_id}",
    request_body = UpdateMappingRequest,
    responses(
        (status = 200, description = "Mapping updated", body = MappingResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Mapping not found"),
    ),
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("mapping_id" = Uuid, Path, description = "Mapping ID"),
    ),
    tag = "mappings"
)]
pub async fn update_mapping(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path((_connector_id, mapping_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateMappingRequest>,
) -> Result<Json<MappingResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let mapping = state
        .mapping_service
        .update_mapping(tenant_id, mapping_id, request)
        .await?;

    Ok(Json(mapping))
}

/// Delete a mapping.
///
/// DELETE /connectors/{connector_id}/mappings/{mapping_id}
#[utoipa::path(
    delete,
    path = "/connectors/{connector_id}/mappings/{mapping_id}",
    responses(
        (status = 204, description = "Mapping deleted"),
        (status = 404, description = "Mapping not found"),
    ),
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("mapping_id" = Uuid, Path, description = "Mapping ID"),
    ),
    tag = "mappings"
)]
pub async fn delete_mapping(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path((_connector_id, mapping_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .mapping_service
        .delete_mapping(tenant_id, mapping_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Preview a mapping transformation.
///
/// POST /connectors/{connector_id}/mappings/{mapping_id}/preview
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/mappings/{mapping_id}/preview",
    request_body = PreviewMappingRequest,
    responses(
        (status = 200, description = "Preview result", body = PreviewMappingResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Mapping not found"),
    ),
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("mapping_id" = Uuid, Path, description = "Mapping ID"),
    ),
    tag = "mappings"
)]
pub async fn preview_mapping(
    State(state): State<ConnectorState>,
    Extension(claims): Extension<JwtClaims>,
    Path((_connector_id, mapping_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<PreviewMappingRequest>,
) -> Result<Json<PreviewMappingResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let preview = state
        .mapping_service
        .preview_mapping(tenant_id, mapping_id, request)
        .await?;

    Ok(Json(preview))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_mappings_query_deserialization() {
        let query: ListMappingsQuery = serde_json::from_str(r#"{"object_class": "user"}"#).unwrap();
        assert_eq!(query.object_class, Some("user".to_string()));

        let empty_query: ListMappingsQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(empty_query.object_class.is_none());
    }
}
