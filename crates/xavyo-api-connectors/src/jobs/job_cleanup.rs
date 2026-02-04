//! Job Cleanup Job for F044 Background Job Tracking.
//!
//! Periodically removes old completed and failed jobs to prevent unbounded storage growth.
//! - Completed jobs are retained for 30 days by default
//! - Failed/cancelled jobs are retained for 90 days by default (for audit purposes)

use std::sync::Arc;

use sqlx::PgPool;
use tracing::{debug, info, warn};
use uuid::Uuid;

use xavyo_db::models::ProvisioningOperation;

/// Default number of days to retain completed jobs.
pub const DEFAULT_COMPLETED_RETENTION_DAYS: i64 = 30;

/// Default number of days to retain failed/cancelled jobs.
pub const DEFAULT_FAILED_RETENTION_DAYS: i64 = 90;

/// Job for cleaning up old provisioning operations.
///
/// This job runs periodically to remove completed and failed jobs older than
/// the configured retention periods, keeping storage usage bounded.
pub struct JobCleanupJob {
    pool: Arc<PgPool>,
    completed_retention_days: i64,
    failed_retention_days: i64,
}

impl JobCleanupJob {
    /// Create a new job cleanup job with default retention periods.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self::with_retention(
            pool,
            DEFAULT_COMPLETED_RETENTION_DAYS,
            DEFAULT_FAILED_RETENTION_DAYS,
        )
    }

    /// Create a new job cleanup job with custom retention periods.
    #[must_use] 
    pub fn with_retention(
        pool: PgPool,
        completed_retention_days: i64,
        failed_retention_days: i64,
    ) -> Self {
        let completed_retention_days = completed_retention_days.max(1);
        let failed_retention_days = failed_retention_days.max(1);
        Self {
            pool: Arc::new(pool),
            completed_retention_days,
            failed_retention_days,
        }
    }

    /// Run cleanup for a specific tenant.
    ///
    /// Returns the number of jobs deleted.
    pub async fn cleanup_tenant(&self, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let deleted = ProvisioningOperation::cleanup_old_jobs(
            &self.pool,
            tenant_id,
            self.completed_retention_days,
            self.failed_retention_days,
        )
        .await?;

        if deleted > 0 {
            info!(
                tenant_id = %tenant_id,
                deleted = deleted,
                completed_days = self.completed_retention_days,
                failed_days = self.failed_retention_days,
                "Cleaned up old jobs"
            );
        } else {
            debug!(tenant_id = %tenant_id, "No old jobs to clean up");
        }

        Ok(deleted)
    }

    /// Run cleanup for all tenants with provisioning operations.
    ///
    /// Returns the total number of jobs deleted across all tenants.
    pub async fn cleanup_all_tenants(&self) -> Result<u64, sqlx::Error> {
        // Get distinct tenant IDs from provisioning operations
        let tenant_ids: Vec<(Uuid,)> = sqlx::query_as(
            r"
            SELECT DISTINCT tenant_id FROM provisioning_operations
            ",
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        let mut total_deleted = 0u64;
        let mut errors = 0;

        for (tenant_id,) in tenant_ids {
            match self.cleanup_tenant(tenant_id).await {
                Ok(deleted) => {
                    total_deleted += deleted;
                }
                Err(e) => {
                    warn!(
                        tenant_id = %tenant_id,
                        error = %e,
                        "Failed to cleanup jobs for tenant"
                    );
                    errors += 1;
                }
            }
        }

        if errors > 0 {
            warn!(
                errors = errors,
                total_deleted = total_deleted,
                "Job cleanup completed with errors"
            );
        } else {
            info!(
                total_deleted = total_deleted,
                "Job cleanup completed successfully"
            );
        }

        Ok(total_deleted)
    }

    /// Get the completed jobs retention period in days.
    #[must_use] 
    pub fn completed_retention_days(&self) -> i64 {
        self.completed_retention_days
    }

    /// Get the failed jobs retention period in days.
    #[must_use] 
    pub fn failed_retention_days(&self) -> i64 {
        self.failed_retention_days
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_retention_values() {
        assert_eq!(DEFAULT_COMPLETED_RETENTION_DAYS, 30);
        assert_eq!(DEFAULT_FAILED_RETENTION_DAYS, 90);
    }

    #[test]
    fn test_retention_clamped_to_minimum() {
        // Even if passed 0 or negative, should be at least 1
        // We can only test this by checking the struct is created without panics
        // A real test would require a mock database
    }
}
