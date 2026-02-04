//! Schema Cleanup Job for F046 Schema Discovery.
//!
//! Periodically removes old schema versions to prevent unbounded storage growth.
//! By default, keeps the last 10 versions per connector.

use std::sync::Arc;

use sqlx::PgPool;
use tracing::{debug, info, warn};
use uuid::Uuid;

use xavyo_db::models::ConnectorSchemaVersion;

/// Default number of schema versions to retain per connector.
pub const DEFAULT_SCHEMA_RETENTION_COUNT: i32 = 10;

/// Job for cleaning up old schema versions.
///
/// This job runs periodically to remove schema versions older than the retention
/// count, keeping storage usage bounded.
pub struct SchemaCleanupJob {
    pool: Arc<PgPool>,
    retention_count: i32,
}

impl SchemaCleanupJob {
    /// Create a new schema cleanup job with default retention.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self::with_retention(pool, DEFAULT_SCHEMA_RETENTION_COUNT)
    }

    /// Create a new schema cleanup job with custom retention count.
    #[must_use] 
    pub fn with_retention(pool: PgPool, retention_count: i32) -> Self {
        let retention_count = retention_count.max(1); // At least keep 1 version
        Self {
            pool: Arc::new(pool),
            retention_count,
        }
    }

    /// Run cleanup for a specific connector.
    ///
    /// Returns the number of versions deleted.
    pub async fn cleanup_connector(&self, connector_id: Uuid) -> Result<u64, sqlx::Error> {
        let deleted = ConnectorSchemaVersion::cleanup_old_versions(
            &self.pool,
            connector_id,
            self.retention_count,
        )
        .await?;

        if deleted > 0 {
            info!(
                connector_id = %connector_id,
                deleted = deleted,
                retained = self.retention_count,
                "Cleaned up old schema versions"
            );
        } else {
            debug!(
                connector_id = %connector_id,
                retained = self.retention_count,
                "No schema versions to clean up"
            );
        }

        Ok(deleted)
    }

    /// Run cleanup for all connectors with versioned schemas.
    ///
    /// Returns the total number of versions deleted across all connectors.
    pub async fn cleanup_all(&self) -> Result<u64, sqlx::Error> {
        // Get distinct connector IDs that have schema versions
        let connector_ids: Vec<(Uuid,)> = sqlx::query_as(
            r"
            SELECT DISTINCT connector_id
            FROM connector_schema_versions
            ",
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        let mut total_deleted = 0u64;

        for (connector_id,) in connector_ids {
            match self.cleanup_connector(connector_id).await {
                Ok(deleted) => total_deleted += deleted,
                Err(e) => {
                    warn!(
                        connector_id = %connector_id,
                        error = %e,
                        "Failed to cleanup schema versions for connector"
                    );
                }
            }
        }

        if total_deleted > 0 {
            info!(
                total_deleted = total_deleted,
                retained_per_connector = self.retention_count,
                "Schema cleanup job completed"
            );
        }

        Ok(total_deleted)
    }

    /// Get the configured retention count.
    #[must_use] 
    pub fn retention_count(&self) -> i32 {
        self.retention_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_retention_count() {
        assert_eq!(DEFAULT_SCHEMA_RETENTION_COUNT, 10);
    }

    #[test]
    fn test_retention_count_minimum() {
        // Test that retention count is clamped to at least 1
        // We can't easily test the job without a database, but we can test the constants
        assert!(DEFAULT_SCHEMA_RETENTION_COUNT >= 1);
    }
}
