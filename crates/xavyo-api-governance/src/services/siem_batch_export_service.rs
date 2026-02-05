//! SIEM Batch Export service (F078).
//!
//! Manages batch export job lifecycle: create, list, get, download.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{CreateSiemBatchExport, SiemBatchExport};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for SIEM batch export operations.
pub struct SiemBatchExportService {
    pool: PgPool,
}

impl SiemBatchExportService {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new batch export job (queued as 'pending').
    pub async fn create_export(
        &self,
        tenant_id: Uuid,
        requested_by: Uuid,
        input: CreateSiemBatchExport,
    ) -> Result<SiemBatchExport> {
        let export = SiemBatchExport::create(&self.pool, tenant_id, requested_by, input).await?;
        Ok(export)
    }

    /// Get a batch export by ID.
    pub async fn get_export(&self, tenant_id: Uuid, id: Uuid) -> Result<SiemBatchExport> {
        SiemBatchExport::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::SiemBatchExportNotFound(id))
    }

    /// List batch exports for a tenant with pagination.
    pub async fn list_exports(
        &self,
        tenant_id: Uuid,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SiemBatchExport>, i64)> {
        let exports =
            SiemBatchExport::list_by_tenant(&self.pool, tenant_id, status, limit, offset).await?;
        let total = SiemBatchExport::count_by_tenant(&self.pool, tenant_id, status).await?;
        Ok((exports, total))
    }

    /// Get the file path for a completed export (for download).
    /// Returns the file path if the export is completed and has a file.
    pub async fn get_download_path(&self, tenant_id: Uuid, id: Uuid) -> Result<String> {
        let export = self.get_export(tenant_id, id).await?;

        if export.status != "completed" {
            return Err(GovernanceError::SiemBatchExportNotReady(
                id,
                format!("status is '{}'", export.status),
            ));
        }

        export.file_path.ok_or_else(|| {
            GovernanceError::SiemBatchExportNotReady(id, "no file path available".to_string())
        })
    }
}
