//! Branding asset model.
//!
//! Metadata for uploaded image files (actual files stored on filesystem/S3).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor, Type};
use uuid::Uuid;

/// Asset type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AssetType {
    Logo,
    Favicon,
    Background,
    #[serde(rename = "email_logo")]
    #[sqlx(rename = "email_logo")]
    EmailLogo,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Logo => write!(f, "logo"),
            Self::Favicon => write!(f, "favicon"),
            Self::Background => write!(f, "background"),
            Self::EmailLogo => write!(f, "email_logo"),
        }
    }
}

impl std::str::FromStr for AssetType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "logo" => Ok(Self::Logo),
            "favicon" => Ok(Self::Favicon),
            "background" => Ok(Self::Background),
            "email_logo" => Ok(Self::EmailLogo),
            _ => Err(format!("Invalid asset type: {s}")),
        }
    }
}

/// Branding asset metadata.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BrandingAsset {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this asset belongs to.
    pub tenant_id: Uuid,

    /// Type of asset.
    pub asset_type: String, // Using String due to sqlx limitations with custom enums

    /// Original filename.
    pub filename: String,

    /// MIME content type.
    pub content_type: String,

    /// File size in bytes.
    pub file_size: i32,

    /// Path to stored file.
    pub storage_path: String,

    /// Image width in pixels.
    pub width: i32,

    /// Image height in pixels.
    pub height: i32,

    /// SHA-256 hash of file content.
    pub checksum: String,

    /// User who uploaded the asset.
    pub uploaded_by: Uuid,

    /// When the asset was uploaded.
    pub created_at: DateTime<Utc>,
}

/// Data for creating a new branding asset.
#[derive(Debug, Clone)]
pub struct CreateBrandingAsset {
    pub tenant_id: Uuid,
    pub asset_type: String,
    pub filename: String,
    pub content_type: String,
    pub file_size: i32,
    pub storage_path: String,
    pub width: i32,
    pub height: i32,
    pub checksum: String,
    pub uploaded_by: Uuid,
}

/// Asset list filter options.
#[derive(Debug, Clone, Default)]
pub struct AssetListFilter {
    pub asset_type: Option<String>,
}

impl BrandingAsset {
    /// Create a new branding asset.
    pub async fn create<'e, E>(executor: E, data: CreateBrandingAsset) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            INSERT INTO branding_assets (
                tenant_id, asset_type, filename, content_type,
                file_size, storage_path, width, height,
                checksum, uploaded_by, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
            RETURNING *
            ",
        )
        .bind(data.tenant_id)
        .bind(&data.asset_type)
        .bind(&data.filename)
        .bind(&data.content_type)
        .bind(data.file_size)
        .bind(&data.storage_path)
        .bind(data.width)
        .bind(data.height)
        .bind(&data.checksum)
        .bind(data.uploaded_by)
        .fetch_one(executor)
        .await
    }

    /// Find asset by ID.
    ///
    /// **SECURITY WARNING**: This method does NOT filter by `tenant_id`.
    /// Use `find_by_id_and_tenant()` for tenant-isolated queries.
    /// This method should only be used for internal operations where
    /// tenant context is already validated or for system-level queries.
    #[deprecated(
        since = "0.1.0",
        note = "Use find_by_id_and_tenant() for tenant-isolated queries"
    )]
    pub async fn find_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM branding_assets WHERE id = $1")
            .bind(id)
            .fetch_optional(executor)
            .await
    }

    /// Find asset by ID and tenant.
    pub async fn find_by_id_and_tenant<'e, E>(
        executor: E,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as("SELECT * FROM branding_assets WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(executor)
            .await
    }

    /// List assets for a tenant.
    pub async fn list_by_tenant<'e, E>(
        executor: E,
        tenant_id: Uuid,
        filter: AssetListFilter,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        if let Some(asset_type) = filter.asset_type {
            sqlx::query_as(
                r"
                SELECT * FROM branding_assets
                WHERE tenant_id = $1 AND asset_type = $2
                ORDER BY created_at DESC
                ",
            )
            .bind(tenant_id)
            .bind(&asset_type)
            .fetch_all(executor)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM branding_assets
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                ",
            )
            .bind(tenant_id)
            .fetch_all(executor)
            .await
        }
    }

    /// Find asset by checksum (to detect duplicates).
    pub async fn find_by_checksum<'e, E>(
        executor: E,
        tenant_id: Uuid,
        checksum: &str,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r"
            SELECT * FROM branding_assets
            WHERE tenant_id = $1 AND checksum = $2
            ",
        )
        .bind(tenant_id)
        .bind(checksum)
        .fetch_optional(executor)
        .await
    }

    /// Check if asset is referenced in tenant branding.
    pub async fn is_referenced<'e, E>(executor: E, storage_path: &str) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let pattern = format!("%{storage_path}%");
        let result: (bool,) = sqlx::query_as(
            r"
            SELECT EXISTS(
                SELECT 1 FROM tenant_branding
                WHERE logo_url LIKE $1
                   OR logo_dark_url LIKE $1
                   OR favicon_url LIKE $1
                   OR email_logo_url LIKE $1
                   OR login_page_background_url LIKE $1
            )
            ",
        )
        .bind(&pattern)
        .fetch_one(executor)
        .await?;

        Ok(result.0)
    }

    /// Delete asset by ID.
    pub async fn delete<'e, E>(executor: E, id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM branding_assets WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete asset by ID and tenant.
    pub async fn delete_by_tenant<'e, E>(
        executor: E,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query("DELETE FROM branding_assets WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_type_display() {
        assert_eq!(AssetType::Logo.to_string(), "logo");
        assert_eq!(AssetType::Favicon.to_string(), "favicon");
        assert_eq!(AssetType::Background.to_string(), "background");
        assert_eq!(AssetType::EmailLogo.to_string(), "email_logo");
    }

    #[test]
    fn test_asset_type_from_str() {
        assert_eq!("logo".parse::<AssetType>().unwrap(), AssetType::Logo);
        assert_eq!("FAVICON".parse::<AssetType>().unwrap(), AssetType::Favicon);
        assert_eq!(
            "email_logo".parse::<AssetType>().unwrap(),
            AssetType::EmailLogo
        );
        assert!("invalid".parse::<AssetType>().is_err());
    }

    #[test]
    fn test_asset_list_filter_default() {
        let filter = AssetListFilter::default();
        assert!(filter.asset_type.is_none());
    }
}
