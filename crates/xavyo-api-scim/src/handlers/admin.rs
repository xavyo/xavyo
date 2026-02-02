//! SCIM admin handlers for token and mapping management.

use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::models::{CreateScimToken, ScimAttributeMapping, UpdateMappingsRequest};

use crate::error::ScimError;
use crate::services::TokenService;

/// Authenticated admin context.
/// This should be provided by the main app's admin auth middleware.
#[derive(Debug, Clone)]
pub struct AdminAuthContext {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
}

/// List all SCIM tokens for the tenant.
///
/// GET /admin/scim/tokens
pub async fn list_tokens(
    Extension(auth): Extension<AdminAuthContext>,
    Extension(token_service): Extension<Arc<TokenService>>,
) -> Result<Response, ScimError> {
    let tokens = token_service.list_tokens(auth.tenant_id).await?;
    Ok((StatusCode::OK, Json(tokens)).into_response())
}

/// Create a new SCIM token.
///
/// POST /admin/scim/tokens
pub async fn create_token(
    Extension(auth): Extension<AdminAuthContext>,
    Extension(token_service): Extension<Arc<TokenService>>,
    Json(request): Json<CreateScimToken>,
) -> Result<Response, ScimError> {
    let token = token_service
        .generate_token(auth.tenant_id, &request.name, auth.user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(token)).into_response())
}

/// Revoke a SCIM token.
///
/// DELETE /admin/scim/tokens/{id}
pub async fn revoke_token(
    Extension(auth): Extension<AdminAuthContext>,
    Extension(token_service): Extension<Arc<TokenService>>,
    Path(id): Path<Uuid>,
) -> Result<Response, ScimError> {
    token_service.revoke_token(auth.tenant_id, id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Get attribute mappings for the tenant.
///
/// GET /admin/scim/mappings
pub async fn get_mappings(
    Extension(auth): Extension<AdminAuthContext>,
    Extension(pool): Extension<sqlx::PgPool>,
) -> Result<Response, ScimError> {
    let mappings = ScimAttributeMapping::list_by_tenant(&pool, auth.tenant_id).await?;
    Ok((StatusCode::OK, Json(mappings)).into_response())
}

/// Update attribute mappings for the tenant.
///
/// PUT /admin/scim/mappings
pub async fn update_mappings(
    Extension(auth): Extension<AdminAuthContext>,
    Extension(pool): Extension<sqlx::PgPool>,
    Json(request): Json<UpdateMappingsRequest>,
) -> Result<Response, ScimError> {
    let mut updated_mappings = Vec::new();

    for mapping in request.mappings {
        let result = ScimAttributeMapping::upsert(
            &pool,
            auth.tenant_id,
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
