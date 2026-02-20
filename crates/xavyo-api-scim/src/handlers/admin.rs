//! SCIM admin handlers for token and mapping management.
//!
//! These handlers require JWT authentication with admin role.

use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use xavyo_db::models::{CreateScimToken, ScimAttributeMapping, UpdateMappingsRequest};

use crate::error::ScimError;
use crate::services::TokenService;

/// List all SCIM tokens for the tenant.
///
/// GET /admin/scim/tokens
#[utoipa::path(
    get,
    path = "/admin/scim/tokens",
    responses(
        (status = 200, description = "List of SCIM tokens"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    tag = "SCIM Admin"
)]
pub async fn list_tokens(
    Extension(claims): Extension<JwtClaims>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(token_service): Extension<Arc<TokenService>>,
) -> Result<Response, ScimError> {
    if !claims.has_role("admin") {
        return Err(ScimError::Forbidden);
    }

    let tid = *tenant_id.as_uuid();
    let tokens = token_service.list_tokens(tid).await?;
    Ok((StatusCode::OK, Json(tokens)).into_response())
}

/// Create a new SCIM token.
///
/// POST /admin/scim/tokens
#[utoipa::path(
    post,
    path = "/admin/scim/tokens",
    request_body = CreateScimToken,
    responses(
        (status = 201, description = "Token created"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    tag = "SCIM Admin"
)]
pub async fn create_token(
    Extension(claims): Extension<JwtClaims>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(token_service): Extension<Arc<TokenService>>,
    Json(request): Json<CreateScimToken>,
) -> Result<Response, ScimError> {
    if !claims.has_role("admin") {
        return Err(ScimError::Forbidden);
    }

    let tid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ScimError::Unauthorized)?;
    let token = token_service
        .generate_token(tid, &request.name, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(token)).into_response())
}

/// Revoke a SCIM token.
///
/// DELETE /admin/scim/tokens/{id}
#[utoipa::path(
    delete,
    path = "/admin/scim/tokens/{id}",
    params(
        ("id" = Uuid, Path, description = "Token ID"),
    ),
    responses(
        (status = 204, description = "Token revoked"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Token not found"),
    ),
    tag = "SCIM Admin"
)]
pub async fn revoke_token(
    Extension(claims): Extension<JwtClaims>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(token_service): Extension<Arc<TokenService>>,
    Path(id): Path<Uuid>,
) -> Result<Response, ScimError> {
    if !claims.has_role("admin") {
        return Err(ScimError::Forbidden);
    }

    let tid = *tenant_id.as_uuid();
    token_service.revoke_token(tid, id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Get attribute mappings for the tenant.
///
/// GET /admin/scim/mappings
#[utoipa::path(
    get,
    path = "/admin/scim/mappings",
    responses(
        (status = 200, description = "List of attribute mappings"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    tag = "SCIM Admin"
)]
pub async fn get_mappings(
    Extension(claims): Extension<JwtClaims>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(pool): Extension<sqlx::PgPool>,
) -> Result<Response, ScimError> {
    if !claims.has_role("admin") {
        return Err(ScimError::Forbidden);
    }

    let tid = *tenant_id.as_uuid();
    let mappings = ScimAttributeMapping::list_by_tenant(&pool, tid).await?;
    Ok((StatusCode::OK, Json(mappings)).into_response())
}

/// Update attribute mappings for the tenant.
///
/// PUT /admin/scim/mappings
#[utoipa::path(
    put,
    path = "/admin/scim/mappings",
    request_body = UpdateMappingsRequest,
    responses(
        (status = 200, description = "Mappings updated"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    tag = "SCIM Admin"
)]
pub async fn update_mappings(
    Extension(claims): Extension<JwtClaims>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(request): Json<UpdateMappingsRequest>,
) -> Result<Response, ScimError> {
    if !claims.has_role("admin") {
        return Err(ScimError::Forbidden);
    }

    // Validate mapping count.
    const MAX_MAPPINGS: usize = 50;
    const MAX_FIELD_LEN: usize = 255;
    const ALLOWED_TRANSFORMS: &[&str] = &["lowercase", "uppercase", "trim"];

    if request.mappings.len() > MAX_MAPPINGS {
        return Err(ScimError::Validation(format!(
            "Too many mappings: {} (maximum {MAX_MAPPINGS})",
            request.mappings.len()
        )));
    }

    // Validate each mapping's fields.
    for (i, mapping) in request.mappings.iter().enumerate() {
        if mapping.scim_path.is_empty() || mapping.scim_path.len() > MAX_FIELD_LEN {
            return Err(ScimError::Validation(format!(
                "Mapping at index {i}: scim_path must be 1-{MAX_FIELD_LEN} characters"
            )));
        }
        if mapping.xavyo_field.is_empty() || mapping.xavyo_field.len() > MAX_FIELD_LEN {
            return Err(ScimError::Validation(format!(
                "Mapping at index {i}: xavyo_field must be 1-{MAX_FIELD_LEN} characters"
            )));
        }
        if let Some(ref transform) = mapping.transform {
            if !ALLOWED_TRANSFORMS.contains(&transform.to_lowercase().as_str()) {
                return Err(ScimError::Validation(format!(
                    "Mapping at index {i}: invalid transform '{}'. Allowed: {}",
                    transform,
                    ALLOWED_TRANSFORMS.join(", ")
                )));
            }
        }
    }

    let tid = *tenant_id.as_uuid();
    let mut updated_mappings = Vec::new();

    for mapping in request.mappings {
        let result = ScimAttributeMapping::upsert(
            &pool,
            tid,
            &mapping.scim_path,
            &mapping.xavyo_field,
            mapping.transform.as_deref(),
            mapping.required,
        )
        .await?;

        updated_mappings.push(result);
    }

    Ok((StatusCode::OK, Json(updated_mappings)).into_response())
}
