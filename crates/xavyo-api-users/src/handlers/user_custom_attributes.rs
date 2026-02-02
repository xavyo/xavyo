//! User custom attribute handlers (F070).
//!
//! Endpoints for getting, setting, and patching custom attributes on individual users.

use crate::error::ApiUsersError;
use crate::models::attribute_definitions::{
    BulkUpdateRequest, BulkUpdateResponse, PatchCustomAttributesRequest,
    SetCustomAttributesRequest, UserCustomAttributesResponse,
};
use crate::services::user_attribute_service::UserAttributeService;
use axum::{extract::Path, Extension, Json};
use std::sync::Arc;
use xavyo_auth::JwtClaims;

/// Get a user's custom attributes.
#[utoipa::path(
    get,
    path = "/admin/users/{user_id}/custom-attributes",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Custom attributes retrieved", body = UserCustomAttributesResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "User not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "User Custom Attributes"
)]
pub async fn get_user_custom_attributes(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<UserAttributeService>>,
    Path(user_id): Path<String>,
) -> Result<Json<UserCustomAttributesResponse>, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    let user_id = uuid::Uuid::parse_str(&user_id)
        .map_err(|_| ApiUsersError::Validation("Invalid UUID format for user ID".to_string()))?;

    let response = service.get_custom_attributes(tenant_id, user_id).await?;
    Ok(Json(response))
}

/// Set (full replace) a user's custom attributes.
#[utoipa::path(
    put,
    path = "/admin/users/{user_id}/custom-attributes",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    request_body = SetCustomAttributesRequest,
    responses(
        (status = 200, description = "Custom attributes updated", body = UserCustomAttributesResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "User not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "User Custom Attributes"
)]
pub async fn set_user_custom_attributes(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<UserAttributeService>>,
    Path(user_id): Path<String>,
    Json(request): Json<SetCustomAttributesRequest>,
) -> Result<Json<UserCustomAttributesResponse>, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    let user_id = uuid::Uuid::parse_str(&user_id)
        .map_err(|_| ApiUsersError::Validation("Invalid UUID format for user ID".to_string()))?;

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        user_id = %user_id,
        "Setting user custom attributes (full replace)"
    );

    let actor_id = uuid::Uuid::parse_str(&claims.sub).ok();
    let response = service
        .set_custom_attributes(tenant_id, user_id, actor_id, request)
        .await?;
    Ok(Json(response))
}

/// Patch (merge) a user's custom attributes.
#[utoipa::path(
    patch,
    path = "/admin/users/{user_id}/custom-attributes",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    request_body = PatchCustomAttributesRequest,
    responses(
        (status = 200, description = "Custom attributes patched", body = UserCustomAttributesResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "User not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "User Custom Attributes"
)]
pub async fn patch_user_custom_attributes(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<UserAttributeService>>,
    Path(user_id): Path<String>,
    Json(request): Json<PatchCustomAttributesRequest>,
) -> Result<Json<UserCustomAttributesResponse>, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    let user_id = uuid::Uuid::parse_str(&user_id)
        .map_err(|_| ApiUsersError::Validation("Invalid UUID format for user ID".to_string()))?;

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        user_id = %user_id,
        "Patching user custom attributes (merge)"
    );

    let actor_id = uuid::Uuid::parse_str(&claims.sub).ok();
    let response = service
        .patch_custom_attributes(tenant_id, user_id, actor_id, request)
        .await?;
    Ok(Json(response))
}

/// Bulk update a custom attribute across multiple users.
#[utoipa::path(
    post,
    path = "/admin/custom-attributes/bulk-update",
    request_body = BulkUpdateRequest,
    responses(
        (status = 200, description = "Bulk update results", body = BulkUpdateResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Attribute definition not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "Bulk Operations"
)]
pub async fn bulk_update_custom_attribute(
    Extension(claims): Extension<JwtClaims>,
    Extension(service): Extension<Arc<UserAttributeService>>,
    Json(request): Json<BulkUpdateRequest>,
) -> Result<Json<BulkUpdateResponse>, ApiUsersError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiUsersError::Unauthorized)?
        .as_uuid();

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        attribute_name = %request.attribute_name,
        "Bulk updating custom attribute"
    );

    let actor_id = uuid::Uuid::parse_str(&claims.sub).ok();
    let response = service.bulk_update(tenant_id, actor_id, request).await?;
    Ok(Json(response))
}
