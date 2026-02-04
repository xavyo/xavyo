//! HTTP handlers for branding asset endpoints (F030).
//!
//! Admin endpoints for managing branding assets:
//! - POST /admin/branding/assets/upload - Upload an asset
//! - GET /admin/branding/assets - List assets
//! - GET /admin/branding/assets/:id - Get asset details
//! - DELETE /admin/branding/assets/:id - Delete an asset

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Extension, Json,
};
use axum_extra::extract::Multipart;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::AssetType;

use crate::error::ApiAuthError;
use crate::models::AssetResponse;
use crate::services::AssetService;

/// Maximum total size for multipart upload (4MB to account for base64 overhead).
const MAX_MULTIPART_SIZE: usize = 4 * 1024 * 1024;

/// Maximum allowed filename length (bytes).
const MAX_FILENAME_LENGTH: usize = 255;

/// SECURITY: Sanitize uploaded filename to prevent path traversal and other attacks.
///
/// This function:
/// - Removes directory components (path traversal prevention)
/// - Filters to only allow safe characters (alphanumeric, dash, underscore, period)
/// - Limits the filename length
/// - Preserves the file extension
fn sanitize_filename(raw_filename: &str) -> String {
    // Extract just the filename part (remove any path components)
    let filename = raw_filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw_filename);

    // Filter to safe characters only: alphanumeric, dash, underscore, period
    let sanitized: String = filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();

    // Ensure we don't start with a period (hidden file) or have multiple consecutive periods
    let sanitized = sanitized.trim_start_matches('.');
    let sanitized: String = sanitized.chars().fold(String::new(), |mut acc, c| {
        if c == '.' && acc.ends_with('.') {
            // Skip consecutive periods
        } else {
            acc.push(c);
        }
        acc
    });

    // Limit length (preserve extension if possible)
    let result = if sanitized.len() > MAX_FILENAME_LENGTH {
        if let Some(ext_pos) = sanitized.rfind('.') {
            let ext = &sanitized[ext_pos..];
            if ext.len() < MAX_FILENAME_LENGTH {
                let name_len = MAX_FILENAME_LENGTH - ext.len();
                format!("{}{}", &sanitized[..name_len], ext)
            } else {
                sanitized[..MAX_FILENAME_LENGTH].to_string()
            }
        } else {
            sanitized[..MAX_FILENAME_LENGTH].to_string()
        }
    } else {
        sanitized
    };

    // If result is empty, use a default
    if result.is_empty() {
        "upload".to_string()
    } else {
        result
    }
}

/// Query parameters for listing assets.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListAssetsQuery {
    /// Filter by asset type (optional).
    pub asset_type: Option<String>,
}

// ============================================================================
// Asset Handlers (US2)
// ============================================================================

/// Upload a branding asset (logo, favicon, background).
#[utoipa::path(
    post,
    path = "/admin/branding/assets/upload",
    responses(
        (status = 201, description = "Asset uploaded", body = AssetResponse),
        (status = 400, description = "Invalid request"),
        (status = 413, description = "File too large"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Branding Assets"
)]
pub async fn upload_asset(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(asset_service): Extension<Arc<AssetService>>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<AssetResponse>), ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)?;

    // Parse multipart form
    let mut asset_type_str: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut data: Option<Vec<u8>> = None;
    let mut total_size: usize = 0;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiAuthError::Validation(format!("Failed to parse multipart: {e}")))?
    {
        let name = field.name().unwrap_or_default().to_string();

        match name.as_str() {
            "asset_type" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiAuthError::Validation(format!("Invalid asset_type: {e}")))?;
                total_size += text.len();
                asset_type_str = Some(text);
            }
            "file" => {
                filename = field.file_name().map(std::string::ToString::to_string);
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| ApiAuthError::Validation(format!("Failed to read file: {e}")))?;
                total_size += bytes.len();

                // Check total size limit
                if total_size > MAX_MULTIPART_SIZE {
                    return Err(ApiAuthError::FileTooLarge(format!(
                        "Total upload size exceeds {MAX_MULTIPART_SIZE} bytes"
                    )));
                }

                data = Some(bytes.to_vec());
            }
            _ => {
                // Ignore unknown fields
            }
        }

        // Early check on total size
        if total_size > MAX_MULTIPART_SIZE {
            return Err(ApiAuthError::FileTooLarge(format!(
                "Total upload size exceeds {MAX_MULTIPART_SIZE} bytes"
            )));
        }
    }

    // Validate required fields
    let asset_type_str = asset_type_str
        .ok_or_else(|| ApiAuthError::Validation("asset_type is required".to_string()))?;
    let asset_type: AssetType = asset_type_str
        .parse()
        .map_err(|e: String| ApiAuthError::Validation(e))?;
    let raw_filename =
        filename.ok_or_else(|| ApiAuthError::Validation("filename is required".to_string()))?;
    // SECURITY: Sanitize filename to prevent path traversal and injection attacks
    let filename = sanitize_filename(&raw_filename);
    let data = data.ok_or_else(|| ApiAuthError::Validation("file is required".to_string()))?;

    if data.is_empty() {
        return Err(ApiAuthError::Validation("file is empty".to_string()));
    }

    let asset = asset_service
        .upload_asset(tenant_uuid, user_id, asset_type, &filename, &data)
        .await?;

    Ok((StatusCode::CREATED, Json(asset)))
}

/// List all branding assets for the tenant.
#[utoipa::path(
    get,
    path = "/admin/branding/assets",
    params(ListAssetsQuery),
    responses(
        (status = 200, description = "List of assets", body = Vec<AssetResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Branding Assets"
)]
pub async fn list_assets(
    Extension(tenant_id): Extension<TenantId>,
    Extension(asset_service): Extension<Arc<AssetService>>,
    Query(query): Query<ListAssetsQuery>,
) -> Result<Json<Vec<AssetResponse>>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();

    let asset_type = if let Some(ref type_str) = query.asset_type {
        Some(
            type_str
                .parse::<AssetType>()
                .map_err(|e: String| ApiAuthError::Validation(e))?,
        )
    } else {
        None
    };

    let assets = asset_service.list_assets(tenant_uuid, asset_type).await?;
    Ok(Json(assets))
}

/// Get a specific branding asset.
#[utoipa::path(
    get,
    path = "/admin/branding/assets/{id}",
    params(
        ("id" = Uuid, Path, description = "Asset ID"),
    ),
    responses(
        (status = 200, description = "Asset details", body = AssetResponse),
        (status = 404, description = "Asset not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Branding Assets"
)]
pub async fn get_asset(
    Extension(tenant_id): Extension<TenantId>,
    Extension(asset_service): Extension<Arc<AssetService>>,
    Path(asset_id): Path<Uuid>,
) -> Result<Json<AssetResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let asset = asset_service.get_asset(tenant_uuid, asset_id).await?;
    Ok(Json(asset))
}

/// Delete a branding asset.
#[utoipa::path(
    delete,
    path = "/admin/branding/assets/{id}",
    params(
        ("id" = Uuid, Path, description = "Asset ID"),
    ),
    responses(
        (status = 204, description = "Asset deleted"),
        (status = 404, description = "Asset not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Branding Assets"
)]
pub async fn delete_asset(
    Extension(tenant_id): Extension<TenantId>,
    Extension(asset_service): Extension<Arc<AssetService>>,
    Path(asset_id): Path<Uuid>,
) -> Result<StatusCode, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    asset_service.delete_asset(tenant_uuid, asset_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
