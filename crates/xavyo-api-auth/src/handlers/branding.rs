//! HTTP handlers for tenant branding endpoints (F030).
//!
//! Admin endpoints for managing visual branding:
//! - GET /admin/branding - Get current branding configuration
//! - PUT /admin/branding - Update branding configuration

use axum::{Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::ApiAuthError;
use crate::models::{BrandingResponse, UpdateBrandingRequest};
use crate::services::BrandingService;

// ============================================================================
// Branding Handlers (US1)
// ============================================================================

/// Get the current branding configuration for the tenant.
#[utoipa::path(
    get,
    path = "/admin/branding",
    responses(
        (status = 200, description = "Branding configuration", body = BrandingResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Branding"
)]
pub async fn get_branding(
    Extension(tenant_id): Extension<TenantId>,
    Extension(branding_service): Extension<Arc<BrandingService>>,
) -> Result<Json<BrandingResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let branding = branding_service.get_branding(tenant_uuid).await?;
    Ok(Json(branding))
}

/// Update the branding configuration for the tenant.
#[utoipa::path(
    put,
    path = "/admin/branding",
    request_body = UpdateBrandingRequest,
    responses(
        (status = 200, description = "Branding updated", body = BrandingResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Branding"
)]
pub async fn update_branding(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(branding_service): Extension<Arc<BrandingService>>,
    Json(request): Json<UpdateBrandingRequest>,
) -> Result<Json<BrandingResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)?;

    let branding = branding_service
        .update_branding(tenant_uuid, user_id, request)
        .await?;

    Ok(Json(branding))
}
