//! Asset storage abstraction for branding images.
//!
//! Provides a trait for asset storage with local filesystem implementation.
//! S3 implementation can be added later.

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

use crate::error::ApiAuthError;
use xavyo_core::TenantId;

/// Asset storage trait for abstracting storage backends.
#[async_trait]
pub trait AssetStorage: Send + Sync {
    /// Store an asset and return the storage path.
    async fn store(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        data: &[u8],
        extension: &str,
    ) -> Result<String, ApiAuthError>;

    /// Delete an asset by its storage path.
    async fn delete(&self, storage_path: &str) -> Result<(), ApiAuthError>;

    /// Get the public URL for an asset.
    fn get_url(&self, storage_path: &str) -> String;

    /// Check if an asset exists.
    async fn exists(&self, storage_path: &str) -> bool;
}

/// Local filesystem asset storage.
pub struct LocalAssetStorage {
    /// Base directory for asset storage.
    base_path: PathBuf,
    /// Base URL prefix for assets.
    url_prefix: String,
}

impl LocalAssetStorage {
    /// Create a new local asset storage.
    ///
    /// # Arguments
    /// * `base_path` - Directory where assets will be stored
    /// * `url_prefix` - URL prefix for serving assets (e.g., "/assets" or "<https://cdn.example.com>")
    pub fn new(base_path: impl AsRef<Path>, url_prefix: impl Into<String>) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            url_prefix: url_prefix.into(),
        }
    }

    /// Get the full file path for an asset.
    fn get_file_path(&self, tenant_id: TenantId, asset_id: Uuid, extension: &str) -> PathBuf {
        self.base_path
            .join(tenant_id.to_string())
            .join(format!("{asset_id}.{extension}"))
    }

    /// Ensure the tenant directory exists.
    async fn ensure_tenant_dir(&self, tenant_id: TenantId) -> Result<(), ApiAuthError> {
        let dir = self.base_path.join(tenant_id.to_string());
        fs::create_dir_all(&dir).await.map_err(|e| {
            ApiAuthError::Internal(format!("Failed to create asset directory: {e}"))
        })?;
        Ok(())
    }

    /// SECURITY: Validate storage path to prevent path traversal attacks.
    ///
    /// Valid paths must:
    /// - Be in format `{tenant_uuid}/{asset_uuid}.{extension}`
    /// - Contain exactly one `/`
    /// - Have valid UUIDs for tenant and asset
    /// - Not contain `..`, `./`, or other traversal sequences
    /// - Result in a path that stays within `base_path` when canonicalized
    fn validate_storage_path(&self, storage_path: &str) -> Result<PathBuf, ApiAuthError> {
        // Check for path traversal patterns
        if storage_path.contains("..")
            || storage_path.contains("./")
            || storage_path.starts_with('/')
            || storage_path.contains("//")
        {
            return Err(ApiAuthError::Validation(
                "Invalid storage path: potential path traversal".to_string(),
            ));
        }

        // Validate format: {uuid}/{uuid}.{ext}
        let parts: Vec<&str> = storage_path.split('/').collect();
        if parts.len() != 2 {
            return Err(ApiAuthError::Validation(
                "Invalid storage path format".to_string(),
            ));
        }

        // Validate tenant UUID
        if Uuid::parse_str(parts[0]).is_err() {
            return Err(ApiAuthError::Validation(
                "Invalid tenant ID in storage path".to_string(),
            ));
        }

        // Validate asset filename (uuid.extension)
        let filename_parts: Vec<&str> = parts[1].splitn(2, '.').collect();
        if filename_parts.len() != 2 {
            return Err(ApiAuthError::Validation(
                "Invalid filename format in storage path".to_string(),
            ));
        }
        if Uuid::parse_str(filename_parts[0]).is_err() {
            return Err(ApiAuthError::Validation(
                "Invalid asset ID in storage path".to_string(),
            ));
        }

        // Build the full path
        let file_path = self.base_path.join(storage_path);

        // Final safety check: ensure the resolved path is within base_path
        // Use lexical comparison since files may not exist yet
        let normalized = file_path
            .components()
            .fold(PathBuf::new(), |mut acc, component| {
                use std::path::Component;
                match component {
                    Component::ParentDir => {
                        acc.pop();
                    }
                    Component::Normal(c) => {
                        acc.push(c);
                    }
                    Component::RootDir => {
                        acc.push("/");
                    }
                    _ => {}
                }
                acc
            });

        let base_normalized =
            self.base_path
                .components()
                .fold(PathBuf::new(), |mut acc, component| {
                    use std::path::Component;
                    match component {
                        Component::ParentDir => {
                            acc.pop();
                        }
                        Component::Normal(c) => {
                            acc.push(c);
                        }
                        Component::RootDir => {
                            acc.push("/");
                        }
                        _ => {}
                    }
                    acc
                });

        if !normalized.starts_with(&base_normalized) {
            return Err(ApiAuthError::Validation(
                "Storage path escapes base directory".to_string(),
            ));
        }

        Ok(file_path)
    }
}

#[async_trait]
impl AssetStorage for LocalAssetStorage {
    async fn store(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        data: &[u8],
        extension: &str,
    ) -> Result<String, ApiAuthError> {
        // Ensure tenant directory exists
        self.ensure_tenant_dir(tenant_id).await?;

        // Build file path
        let file_path = self.get_file_path(tenant_id, asset_id, extension);

        // Write file
        fs::write(&file_path, data)
            .await
            .map_err(|e| ApiAuthError::Internal(format!("Failed to write asset file: {e}")))?;

        // Return relative storage path
        let storage_path = format!("{tenant_id}/{asset_id}.{extension}");
        Ok(storage_path)
    }

    async fn delete(&self, storage_path: &str) -> Result<(), ApiAuthError> {
        // SECURITY: Validate path to prevent path traversal attacks
        let file_path = self.validate_storage_path(storage_path)?;

        if file_path.exists() {
            fs::remove_file(&file_path)
                .await
                .map_err(|e| ApiAuthError::Internal(format!("Failed to delete asset file: {e}")))?;
        }

        Ok(())
    }

    fn get_url(&self, storage_path: &str) -> String {
        format!("{}/{}", self.url_prefix, storage_path)
    }

    async fn exists(&self, storage_path: &str) -> bool {
        // SECURITY: Validate path to prevent path traversal attacks
        match self.validate_storage_path(storage_path) {
            Ok(file_path) => file_path.exists(),
            Err(_) => false, // Invalid paths don't exist
        }
    }
}

/// In-memory asset storage for testing.
#[cfg(test)]
pub struct InMemoryAssetStorage {
    assets: std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
    url_prefix: String,
}

#[cfg(test)]
impl InMemoryAssetStorage {
    pub fn new(url_prefix: impl Into<String>) -> Self {
        Self {
            assets: std::sync::RwLock::new(std::collections::HashMap::new()),
            url_prefix: url_prefix.into(),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl AssetStorage for InMemoryAssetStorage {
    async fn store(
        &self,
        tenant_id: TenantId,
        asset_id: Uuid,
        data: &[u8],
        extension: &str,
    ) -> Result<String, ApiAuthError> {
        let storage_path = format!("{}/{}.{}", tenant_id, asset_id, extension);
        self.assets
            .write()
            .unwrap()
            .insert(storage_path.clone(), data.to_vec());
        Ok(storage_path)
    }

    async fn delete(&self, storage_path: &str) -> Result<(), ApiAuthError> {
        self.assets.write().unwrap().remove(storage_path);
        Ok(())
    }

    fn get_url(&self, storage_path: &str) -> String {
        format!("{}/{}", self.url_prefix, storage_path)
    }

    async fn exists(&self, storage_path: &str) -> bool {
        self.assets.read().unwrap().contains_key(storage_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_storage() {
        let storage = InMemoryAssetStorage::new("/assets");
        let tenant_id = TenantId::new();
        let asset_id = Uuid::new_v4();
        let data = b"test image data";

        // Store
        let path = storage
            .store(tenant_id, asset_id, data, "png")
            .await
            .unwrap();

        // Check exists
        assert!(storage.exists(&path).await);

        // Check URL
        assert!(storage.get_url(&path).starts_with("/assets/"));

        // Delete
        storage.delete(&path).await.unwrap();
        assert!(!storage.exists(&path).await);
    }
}
