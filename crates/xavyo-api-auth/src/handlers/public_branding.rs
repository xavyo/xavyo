//! HTTP handlers for public branding endpoint (F030).
//!
//! Public endpoint for login pages (no authentication required):
//! - GET /`public/branding/:tenant_slug` - Get branding for login page

use axum::{extract::Path, Extension, Json};
use std::sync::Arc;

use crate::error::ApiAuthError;
use crate::models::PublicBrandingResponse;
use crate::services::BrandingService;

// ============================================================================
// Public Branding Handler
// ============================================================================

/// Get public branding configuration for a tenant by slug.
/// This endpoint is public (no authentication required) and used by login pages.
/// Results are cached for 5 minutes.
#[utoipa::path(
    get,
    path = "/public/branding/{tenant_slug}",
    params(
        ("tenant_slug" = String, Path, description = "Tenant slug"),
    ),
    responses(
        (status = 200, description = "Public branding configuration", body = PublicBrandingResponse),
        (status = 404, description = "Tenant not found"),
    ),
    tag = "Public"
)]
pub async fn get_public_branding(
    Extension(branding_service): Extension<Arc<BrandingService>>,
    Path(tenant_slug): Path<String>,
) -> Result<Json<PublicBrandingResponse>, ApiAuthError> {
    let branding = branding_service.get_public_branding(&tenant_slug).await?;
    Ok(Json(branding))
}
