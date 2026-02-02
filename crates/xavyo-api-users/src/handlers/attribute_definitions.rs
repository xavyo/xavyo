//! Attribute definition CRUD handlers (F070/F081).
//!
//! Endpoints for managing tenant custom attribute schema definitions.

use crate::error::ApiUsersError;
use crate::models::attribute_definitions::{
    AttributeDefinitionListResponse, AttributeDefinitionResponse, CreateAttributeDefinitionRequest,
    DeleteAttributeDefinitionQuery, ListAttributeDefinitionsQuery, SeedWellKnownResponse,
    UpdateAttributeDefinitionRequest,
};
use crate::services::attribute_definition_service::AttributeDefinitionService;
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Extension, Json,
};
use std::sync::Arc;
use xavyo_auth::JwtClaims;

/// Create a new attribute definition.
#[utoipa::path(
    post,
    path = "/admin/attribute-definitions",
    request_body = CreateAttributeDefinitionRequest,
    responses(
        (status = 201, description = "Attribute definition created", body = AttributeDefinitionResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 409, description = "Name already exists in tenant"),
        (status = 422, description = "Limit exceeded"),
    ),
    security(("bearerAuth" = [])),
    tag = "Attribute Definitions"
)]
pub async fn create_attribute_definition(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<AttributeDefinitionService>>,
    Json(request): Json<CreateAttributeDefinitionRequest>,
) -> Result<(StatusCode, Json<AttributeDefinitionResponse>), ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        name = %request.name,
        data_type = %request.data_type,
        "Creating attribute definition"
    );

    let actor_id = uuid::Uuid::parse_str(&claims.sub).ok();
    let response = service.create(tenant_id, actor_id, request).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// List attribute definitions for the tenant.
#[utoipa::path(
    get,
    path = "/admin/attribute-definitions",
    params(ListAttributeDefinitionsQuery),
    responses(
        (status = 200, description = "Attribute definitions listed", body = AttributeDefinitionListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Attribute Definitions"
)]
pub async fn list_attribute_definitions(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<AttributeDefinitionService>>,
    Query(query): Query<ListAttributeDefinitionsQuery>,
) -> Result<Json<AttributeDefinitionListResponse>, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    let response = service
        .list(tenant_id, query.is_active, query.data_type.as_deref())
        .await?;
    Ok(Json(response))
}

/// Get an attribute definition by ID.
#[utoipa::path(
    get,
    path = "/admin/attribute-definitions/{id}",
    params(
        ("id" = String, Path, description = "Attribute definition ID")
    ),
    responses(
        (status = 200, description = "Attribute definition found", body = AttributeDefinitionResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Attribute definition not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "Attribute Definitions"
)]
pub async fn get_attribute_definition(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<AttributeDefinitionService>>,
    Path(id): Path<String>,
) -> Result<Json<AttributeDefinitionResponse>, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    let id = uuid::Uuid::parse_str(&id).map_err(|_| {
        ApiUsersError::Validation("Invalid UUID format for attribute definition ID".to_string())
    })?;

    let response = service.get(tenant_id, id).await?;
    Ok(Json(response))
}

/// Update an attribute definition.
#[utoipa::path(
    put,
    path = "/admin/attribute-definitions/{id}",
    params(
        ("id" = String, Path, description = "Attribute definition ID")
    ),
    request_body = UpdateAttributeDefinitionRequest,
    responses(
        (status = 200, description = "Attribute definition updated", body = AttributeDefinitionResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Attribute definition not found"),
        (status = 422, description = "Data type change rejected"),
    ),
    security(("bearerAuth" = [])),
    tag = "Attribute Definitions"
)]
pub async fn update_attribute_definition(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<AttributeDefinitionService>>,
    Path(id): Path<String>,
    Json(request): Json<UpdateAttributeDefinitionRequest>,
) -> Result<Json<AttributeDefinitionResponse>, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    let id = uuid::Uuid::parse_str(&id).map_err(|_| {
        ApiUsersError::Validation("Invalid UUID format for attribute definition ID".to_string())
    })?;

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        definition_id = %id,
        "Updating attribute definition"
    );

    let actor_id = uuid::Uuid::parse_str(&claims.sub).ok();
    let response = service.update(tenant_id, id, actor_id, request).await?;
    Ok(Json(response))
}

/// Delete an attribute definition.
#[utoipa::path(
    delete,
    path = "/admin/attribute-definitions/{id}",
    params(
        ("id" = String, Path, description = "Attribute definition ID"),
        DeleteAttributeDefinitionQuery,
    ),
    responses(
        (status = 204, description = "Attribute definition deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Attribute definition not found"),
        (status = 409, description = "Attribute definition in use (use force=true)"),
    ),
    security(("bearerAuth" = [])),
    tag = "Attribute Definitions"
)]
pub async fn delete_attribute_definition(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<AttributeDefinitionService>>,
    Path(id): Path<String>,
    Query(query): Query<DeleteAttributeDefinitionQuery>,
) -> Result<StatusCode, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    let id = uuid::Uuid::parse_str(&id).map_err(|_| {
        ApiUsersError::Validation("Invalid UUID format for attribute definition ID".to_string())
    })?;

    let force = query.force.unwrap_or(false);

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        definition_id = %id,
        force = force,
        "Deleting attribute definition"
    );

    let actor_id = uuid::Uuid::parse_str(&claims.sub).ok();
    service.delete(tenant_id, id, force, actor_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Seed well-known enterprise attributes for the tenant (F081).
#[utoipa::path(
    post,
    path = "/admin/attribute-definitions/seed-wellknown",
    responses(
        (status = 200, description = "Well-known attributes seeded", body = SeedWellKnownResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Attribute Definitions"
)]
pub async fn seed_wellknown(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<AttributeDefinitionService>>,
) -> Result<Json<SeedWellKnownResponse>, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        "Seeding well-known attribute definitions"
    );

    let response = service.seed_wellknown(tenant_id).await?;

    tracing::info!(
        tenant_id = %tenant_id,
        seeded = response.total_seeded,
        skipped = response.total_skipped,
        "Well-known seeding complete"
    );

    Ok(Json(response))
}
