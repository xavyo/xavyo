//! Handlers for entitlement-action mapping CRUD (F083).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::{ApiAuthorizationError, ApiResult};
use crate::models::mapping::{
    CreateMappingRequest, ListMappingsQuery, MappingListResponse, MappingResponse,
};
use crate::router::AuthorizationState;

/// List entitlement-action mappings with optional filters and pagination.
#[utoipa::path(
    get,
    path = "/admin/authorization/mappings",
    tag = "Authorization - Mappings",
    params(ListMappingsQuery),
    responses(
        (status = 200, description = "List of mappings", body = MappingListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_mappings(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListMappingsQuery>,
) -> ApiResult<Json<MappingListResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let result = state
        .mapping_service
        .list_mappings(tenant_id, query)
        .await?;

    Ok(Json(result))
}

/// Create a new entitlement-action mapping.
#[utoipa::path(
    post,
    path = "/admin/authorization/mappings",
    tag = "Authorization - Mappings",
    request_body = CreateMappingRequest,
    responses(
        (status = 201, description = "Mapping created", body = MappingResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "Mapping already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_mapping(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateMappingRequest>,
) -> ApiResult<(StatusCode, Json<MappingResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthorizationError::Unauthorized)?;

    let mapping = state
        .mapping_service
        .create_mapping(tenant_id, request, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(mapping)))
}

/// Get an entitlement-action mapping by ID.
#[utoipa::path(
    get,
    path = "/admin/authorization/mappings/{id}",
    tag = "Authorization - Mappings",
    params(
        ("id" = Uuid, Path, description = "Mapping ID")
    ),
    responses(
        (status = 200, description = "Mapping details", body = MappingResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Mapping not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mapping(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<MappingResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let mapping = state.mapping_service.get_mapping(tenant_id, id).await?;

    Ok(Json(mapping))
}

/// Delete an entitlement-action mapping.
#[utoipa::path(
    delete,
    path = "/admin/authorization/mappings/{id}",
    tag = "Authorization - Mappings",
    params(
        ("id" = Uuid, Path, description = "Mapping ID")
    ),
    responses(
        (status = 204, description = "Mapping deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Mapping not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_mapping(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    state.mapping_service.delete_mapping(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}
