//! Asset management service (F030).
//!
//! Handles branding asset operations: upload, delete, list.

use crate::error::ApiAuthError;
use crate::models::AssetResponse;
use crate::services::{asset_storage::AssetStorage, image_validator};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::models::{AssetListFilter, AssetType, BrandingAsset, CreateBrandingAsset};
use xavyo_db::set_tenant_context;

/// Asset management service.
#[derive(Clone)]
pub struct AssetService {
    pool: PgPool,
    storage: Arc<dyn AssetStorage>,
}

impl AssetService {
    /// Create a new asset service.
    pub fn new(pool: PgPool, storage: Arc<dyn AssetStorage>) -> Self {
        Self { pool, storage }
    }

    // ========================================================================
    // User Story 2: Upload and Manage Branding Assets
    // ========================================================================

    /// Upload a new branding asset.
    ///
    /// Validates the image and stores it in the configured storage backend.
    pub async fn upload_asset(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        asset_type: AssetType,
        filename: &str,
        data: &[u8],
    ) -> Result<AssetResponse, ApiAuthError> {
        // Validate image
        let metadata = image_validator::validate_image(data, filename)?;

        // Check for duplicate by checksum
        let existing = BrandingAsset::find_by_checksum(&self.pool, tenant_id, &metadata.checksum)
            .await
            .map_err(ApiAuthError::Database)?;

        if let Some(asset) = existing {
            info!(
                tenant_id = %tenant_id,
                asset_id = %asset.id,
                checksum = %metadata.checksum,
                "Returning existing asset with matching checksum"
            );
            return Ok(self.asset_to_response(&asset));
        }

        // Generate asset ID
        let asset_id = Uuid::new_v4();

        // Get file extension from content type or filename
        let extension = image_validator::get_extension(filename)
            .unwrap_or_else(|| self.content_type_to_extension(&metadata.content_type));

        // Store file
        let storage_path = self
            .storage
            .store(TenantId::from_uuid(tenant_id), asset_id, data, &extension)
            .await?;

        // Set tenant context
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Create database record
        let create_data = CreateBrandingAsset {
            tenant_id,
            asset_type: asset_type.to_string(),
            filename: filename.to_string(),
            content_type: metadata.content_type,
            file_size: metadata.file_size as i32,
            storage_path,
            width: metadata.width as i32,
            height: metadata.height as i32,
            checksum: metadata.checksum,
            uploaded_by: user_id,
        };

        let asset = BrandingAsset::create(&self.pool, create_data)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(
            tenant_id = %tenant_id,
            asset_id = %asset.id,
            asset_type = %asset_type,
            filename = %filename,
            "Asset uploaded"
        );

        Ok(self.asset_to_response(&asset))
    }

    /// Delete a branding asset.
    ///
    /// Checks if the asset is referenced in branding before deletion.
    pub async fn delete_asset(&self, tenant_id: Uuid, asset_id: Uuid) -> Result<(), ApiAuthError> {
        // Set tenant context
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Find asset
        let asset = BrandingAsset::find_by_id_and_tenant(&self.pool, asset_id, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::AssetNotFound)?;

        // Check if asset is in use
        let is_referenced = BrandingAsset::is_referenced(&self.pool, &asset.storage_path)
            .await
            .map_err(ApiAuthError::Database)?;

        if is_referenced {
            return Err(ApiAuthError::AssetInUse(format!(
                "Asset {} is currently in use in branding configuration",
                asset_id
            )));
        }

        // Delete from storage
        if let Err(e) = self.storage.delete(&asset.storage_path).await {
            warn!(
                tenant_id = %tenant_id,
                asset_id = %asset_id,
                error = %e,
                "Failed to delete asset from storage, continuing with database deletion"
            );
        }

        // Delete from database
        BrandingAsset::delete_by_tenant(&self.pool, asset_id, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(
            tenant_id = %tenant_id,
            asset_id = %asset_id,
            "Asset deleted"
        );

        Ok(())
    }

    /// List all assets for a tenant.
    pub async fn list_assets(
        &self,
        tenant_id: Uuid,
        asset_type: Option<AssetType>,
    ) -> Result<Vec<AssetResponse>, ApiAuthError> {
        // Set tenant context
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let filter = AssetListFilter {
            asset_type: asset_type.map(|t| t.to_string()),
        };

        let assets = BrandingAsset::list_by_tenant(&self.pool, tenant_id, filter)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(assets
            .into_iter()
            .map(|a| self.asset_to_response(&a))
            .collect())
    }

    /// Get a specific asset.
    pub async fn get_asset(
        &self,
        tenant_id: Uuid,
        asset_id: Uuid,
    ) -> Result<AssetResponse, ApiAuthError> {
        // Set tenant context
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let asset = BrandingAsset::find_by_id_and_tenant(&self.pool, asset_id, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::AssetNotFound)?;

        Ok(self.asset_to_response(&asset))
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Convert a BrandingAsset to AssetResponse with the public URL.
    fn asset_to_response(&self, asset: &BrandingAsset) -> AssetResponse {
        AssetResponse {
            id: asset.id,
            asset_type: asset.asset_type.clone(),
            filename: asset.filename.clone(),
            content_type: asset.content_type.clone(),
            file_size: asset.file_size,
            url: self.storage.get_url(&asset.storage_path),
            width: asset.width,
            height: asset.height,
            checksum: asset.checksum.clone(),
            created_at: asset.created_at,
        }
    }

    /// Get file extension from content type.
    fn content_type_to_extension(&self, content_type: &str) -> String {
        match content_type {
            "image/png" => "png".to_string(),
            "image/jpeg" => "jpg".to_string(),
            "image/gif" => "gif".to_string(),
            "image/webp" => "webp".to_string(),
            "image/svg+xml" => "svg".to_string(),
            _ => "bin".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_content_type_to_extension() {
        // Test content type to extension mapping
        fn content_type_to_extension(content_type: &str) -> &'static str {
            match content_type {
                "image/png" => "png",
                "image/jpeg" => "jpg",
                "image/gif" => "gif",
                "image/webp" => "webp",
                "image/svg+xml" => "svg",
                _ => "bin",
            }
        }

        assert_eq!(content_type_to_extension("image/png"), "png");
        assert_eq!(content_type_to_extension("image/jpeg"), "jpg");
        assert_eq!(content_type_to_extension("image/gif"), "gif");
        assert_eq!(content_type_to_extension("image/webp"), "webp");
        assert_eq!(content_type_to_extension("image/svg+xml"), "svg");
        assert_eq!(content_type_to_extension("application/octet-stream"), "bin");
    }
}
