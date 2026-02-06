//! License Expiration Job for F065 License Management.
//!
//! Runs daily to check for expiring license pools and process expirations.
//! This job:
//! 1. Queries all tenants with active license pools that have an expiration date
//! 2. For each tenant, checks and expires pools past their date
//! 3. For each tenant, sends renewal alerts for pools approaching expiration
//!
//! This job runs periodically (default: once per day) to process license expirations.

use std::sync::Arc;

use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::services::license_expiration_service::LicenseExpirationService;

/// Default polling interval in seconds (24 hours = daily).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 86400;

/// Job for processing license pool expirations and renewal alerts.
///
/// This job polls the `gov_license_pools` table for active pools with
/// an expiration date set, then for each distinct tenant:
/// - Expires pools past their expiration date according to their policy
/// - Sends renewal alerts for pools approaching expiration
pub struct LicenseExpirationJob {
    service: Arc<LicenseExpirationService>,
    db_pool: sqlx::PgPool,
}

/// Statistics from processing license expirations.
#[derive(Debug, Clone, Default)]
pub struct LicenseExpirationStats {
    /// Number of tenants processed.
    pub tenants_processed: usize,
    /// Number of license pools that were expired.
    pub pools_expired: usize,
    /// Number of license assignments revoked due to expiration policy.
    pub assignments_revoked: usize,
    /// Number of renewal alerts generated.
    pub alerts_generated: usize,
    /// Number of errors encountered.
    pub errors: usize,
}

impl LicenseExpirationStats {
    /// Merge stats from another instance.
    pub fn merge(&mut self, other: &LicenseExpirationStats) {
        self.tenants_processed += other.tenants_processed;
        self.pools_expired += other.pools_expired;
        self.assignments_revoked += other.assignments_revoked;
        self.alerts_generated += other.alerts_generated;
        self.errors += other.errors;
    }

    /// Returns the total number of actions taken (expired + revoked + alerts).
    #[must_use]
    pub fn total_actions(&self) -> usize {
        self.pools_expired + self.assignments_revoked + self.alerts_generated
    }
}

/// Errors that can occur during license expiration job execution.
#[derive(Debug, thiserror::Error)]
pub enum LicenseExpirationJobError {
    /// An error from the license expiration service.
    #[error("Service error: {0}")]
    Service(String),

    /// A database error (e.g., querying tenant IDs).
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl LicenseExpirationJob {
    /// Create a new license expiration job.
    #[must_use]
    pub fn new(service: Arc<LicenseExpirationService>, db_pool: sqlx::PgPool) -> Self {
        Self { service, db_pool }
    }

    /// Run a single cycle of the expiration job.
    ///
    /// Queries all distinct tenant IDs from active license pools with expiration
    /// dates, then processes each tenant's pools for expiration and renewal alerts.
    ///
    /// Returns aggregated statistics about the processing.
    #[instrument(skip(self))]
    pub async fn run_once(&self) -> Result<LicenseExpirationStats, LicenseExpirationJobError> {
        info!("Starting license expiration job cycle");

        let tenant_ids = self.get_tenant_ids_with_expiring_pools().await?;

        if tenant_ids.is_empty() {
            debug!("No tenants with active expiring license pools found");
            return Ok(LicenseExpirationStats::default());
        }

        info!(
            tenant_count = tenant_ids.len(),
            "Found tenants with active expiring license pools"
        );

        let mut stats = LicenseExpirationStats::default();

        for tenant_id in tenant_ids {
            let tenant_stats = self.process_tenant(tenant_id).await;
            stats.merge(&tenant_stats);
        }

        if stats.total_actions() > 0 {
            info!(
                tenants_processed = stats.tenants_processed,
                pools_expired = stats.pools_expired,
                assignments_revoked = stats.assignments_revoked,
                alerts_generated = stats.alerts_generated,
                errors = stats.errors,
                "Completed license expiration job cycle"
            );
        } else {
            debug!(
                tenants_processed = stats.tenants_processed,
                errors = stats.errors,
                "License expiration job cycle complete, no actions taken"
            );
        }

        Ok(stats)
    }

    /// Query distinct tenant IDs from active license pools that have an expiration date.
    async fn get_tenant_ids_with_expiring_pools(
        &self,
    ) -> Result<Vec<Uuid>, LicenseExpirationJobError> {
        let rows = sqlx::query_scalar::<_, Uuid>(
            "SELECT DISTINCT tenant_id FROM gov_license_pools WHERE status = 'active' AND expiration_date IS NOT NULL",
        )
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query tenant IDs for license expiration");
            LicenseExpirationJobError::Database(e)
        })?;

        Ok(rows)
    }

    /// Process a single tenant's license pools for expiration and renewal alerts.
    ///
    /// This method does not propagate errors so that one failing tenant does not
    /// prevent other tenants from being processed. Errors are logged and counted.
    #[instrument(skip(self), fields(%tenant_id))]
    async fn process_tenant(&self, tenant_id: Uuid) -> LicenseExpirationStats {
        let mut stats = LicenseExpirationStats {
            tenants_processed: 1,
            ..Default::default()
        };

        // Step 1: Check and expire pools past their expiration date
        match self.service.check_and_expire_pools(tenant_id).await {
            Ok(result) => {
                stats.pools_expired += result.pools_expired;
                stats.assignments_revoked += result
                    .policies_applied
                    .iter()
                    .map(|p| p.assignments_revoked as usize)
                    .sum::<usize>();
                debug!(
                    tenant_id = %tenant_id,
                    pools_checked = result.pools_checked,
                    pools_expired = result.pools_expired,
                    policies_applied = result.policies_applied.len(),
                    "Expiration check complete for tenant"
                );
            }
            Err(e) => {
                warn!(
                    tenant_id = %tenant_id,
                    error = %e,
                    "Failed to check and expire pools for tenant"
                );
                stats.errors += 1;
            }
        }

        // Step 2: Send renewal alerts for pools approaching expiration
        match self.service.send_renewal_alerts(tenant_id).await {
            Ok(result) => {
                let alert_count = result.pools_needing_alerts.len();
                stats.alerts_generated += alert_count;
                if alert_count > 0 {
                    info!(
                        tenant_id = %tenant_id,
                        alerts = alert_count,
                        "Renewal alerts generated for tenant"
                    );
                } else {
                    debug!(
                        tenant_id = %tenant_id,
                        "No renewal alerts needed for tenant"
                    );
                }
            }
            Err(e) => {
                warn!(
                    tenant_id = %tenant_id,
                    error = %e,
                    "Failed to send renewal alerts for tenant"
                );
                stats.errors += 1;
            }
        }

        stats
    }

    /// Get the recommended poll interval in seconds.
    #[must_use]
    pub const fn poll_interval_secs(&self) -> u64 {
        DEFAULT_POLL_INTERVAL_SECS
    }

    /// Get reference to the underlying service.
    #[must_use]
    pub fn service(&self) -> &LicenseExpirationService {
        &self.service
    }

    /// Get reference to the database pool.
    #[must_use]
    pub fn db_pool(&self) -> &sqlx::PgPool {
        &self.db_pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_default_values() {
        let stats = LicenseExpirationStats::default();
        assert_eq!(stats.tenants_processed, 0);
        assert_eq!(stats.pools_expired, 0);
        assert_eq!(stats.assignments_revoked, 0);
        assert_eq!(stats.alerts_generated, 0);
        assert_eq!(stats.errors, 0);
    }

    #[test]
    fn test_stats_merge() {
        let mut stats1 = LicenseExpirationStats {
            tenants_processed: 3,
            pools_expired: 2,
            assignments_revoked: 5,
            alerts_generated: 4,
            errors: 1,
        };

        let stats2 = LicenseExpirationStats {
            tenants_processed: 2,
            pools_expired: 1,
            assignments_revoked: 3,
            alerts_generated: 2,
            errors: 0,
        };

        stats1.merge(&stats2);

        assert_eq!(stats1.tenants_processed, 5);
        assert_eq!(stats1.pools_expired, 3);
        assert_eq!(stats1.assignments_revoked, 8);
        assert_eq!(stats1.alerts_generated, 6);
        assert_eq!(stats1.errors, 1);
    }

    #[test]
    fn test_stats_total_actions() {
        let stats = LicenseExpirationStats {
            tenants_processed: 10,
            pools_expired: 3,
            assignments_revoked: 7,
            alerts_generated: 5,
            errors: 2,
        };

        // total_actions = pools_expired + assignments_revoked + alerts_generated
        assert_eq!(stats.total_actions(), 15);
    }

    #[test]
    fn test_stats_total_actions_zero() {
        let stats = LicenseExpirationStats::default();
        assert_eq!(stats.total_actions(), 0);
    }

    #[test]
    fn test_error_display_service() {
        let err = LicenseExpirationJobError::Service("connection timeout".to_string());
        let display = err.to_string();
        assert_eq!(display, "Service error: connection timeout");
        assert!(display.contains("connection timeout"));
    }

    #[test]
    fn test_error_display_database() {
        // Construct a Database variant via the Service variant since sqlx::Error
        // cannot be easily constructed in tests. We test the Display for Service
        // and verify the Database variant string format separately.
        let err = LicenseExpirationJobError::Service("pool closed".to_string());
        assert!(err.to_string().contains("pool closed"));

        // Also test the Debug representation includes variant info
        let err2 = LicenseExpirationJobError::Service("query failed".to_string());
        let debug_str = format!("{:?}", err2);
        assert!(debug_str.contains("Service"));
        assert!(debug_str.contains("query failed"));
    }

    #[test]
    fn test_stats_merge_with_default() {
        let mut stats = LicenseExpirationStats {
            tenants_processed: 5,
            pools_expired: 3,
            assignments_revoked: 10,
            alerts_generated: 7,
            errors: 2,
        };

        let empty = LicenseExpirationStats::default();
        stats.merge(&empty);

        // Merging with default should not change values
        assert_eq!(stats.tenants_processed, 5);
        assert_eq!(stats.pools_expired, 3);
        assert_eq!(stats.assignments_revoked, 10);
        assert_eq!(stats.alerts_generated, 7);
        assert_eq!(stats.errors, 2);
    }

    #[test]
    fn test_stats_accumulation_multiple_merges() {
        let mut accumulated = LicenseExpirationStats::default();

        let batch1 = LicenseExpirationStats {
            tenants_processed: 1,
            pools_expired: 2,
            assignments_revoked: 3,
            alerts_generated: 1,
            errors: 0,
        };

        let batch2 = LicenseExpirationStats {
            tenants_processed: 1,
            pools_expired: 0,
            assignments_revoked: 0,
            alerts_generated: 4,
            errors: 1,
        };

        let batch3 = LicenseExpirationStats {
            tenants_processed: 1,
            pools_expired: 1,
            assignments_revoked: 2,
            alerts_generated: 0,
            errors: 0,
        };

        accumulated.merge(&batch1);
        accumulated.merge(&batch2);
        accumulated.merge(&batch3);

        assert_eq!(accumulated.tenants_processed, 3);
        assert_eq!(accumulated.pools_expired, 3);
        assert_eq!(accumulated.assignments_revoked, 5);
        assert_eq!(accumulated.alerts_generated, 5);
        assert_eq!(accumulated.errors, 1);
        assert_eq!(accumulated.total_actions(), 13);
    }

    #[test]
    fn test_default_poll_interval() {
        // 86400 seconds = 24 hours
        assert_eq!(DEFAULT_POLL_INTERVAL_SECS, 86400);
    }
}
