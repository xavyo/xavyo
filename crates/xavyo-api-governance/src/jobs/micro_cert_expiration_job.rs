//! Micro-certification Expiration Job for F055.
//!
//! Polls for micro-certifications that need:
//! - Reminders sent (approaching deadline)
//! - Escalation to backup reviewer (escalation deadline passed)
//! - Expiration processing (deadline passed - auto-revoke or mark expired)
//!
//! This job runs periodically (default: every minute) to process expirations.

use std::sync::Arc;

use chrono::Utc;
use tracing::{debug, error, info, instrument, warn};

use xavyo_db::models::{GovMicroCertTrigger, GovMicroCertification};

use crate::services::MicroCertificationService;

/// Default polling interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Default batch size for processing.
pub const DEFAULT_BATCH_SIZE: i64 = 50;

/// Job for processing micro-certification expirations, reminders, and escalations.
///
/// This job polls the `gov_micro_certifications` table for:
/// 1. Certifications approaching deadline (need reminder)
/// 2. Certifications past escalation deadline (need escalation)
/// 3. Certifications past final deadline (need expiration/auto-revoke)
pub struct MicroCertExpirationJob {
    service: Arc<MicroCertificationService>,
    batch_size: i64,
}

/// Statistics from processing expirations.
#[derive(Debug, Clone, Default)]
pub struct MicroCertExpirationStats {
    /// Total certifications processed.
    pub processed: usize,
    /// Reminders sent.
    pub reminders_sent: usize,
    /// Escalations performed.
    pub escalations: usize,
    /// Auto-revokes executed.
    pub auto_revoked: usize,
    /// Marked as expired (no auto-revoke).
    pub expired: usize,
    /// Failed operations.
    pub failed: usize,
}

impl MicroCertExpirationStats {
    /// Merge stats from another instance.
    pub fn merge(&mut self, other: &MicroCertExpirationStats) {
        self.processed += other.processed;
        self.reminders_sent += other.reminders_sent;
        self.escalations += other.escalations;
        self.auto_revoked += other.auto_revoked;
        self.expired += other.expired;
        self.failed += other.failed;
    }
}

impl MicroCertExpirationJob {
    /// Create a new micro-certification expiration job.
    #[must_use]
    pub fn new(service: MicroCertificationService) -> Self {
        Self {
            service: Arc::new(service),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create with existing Arc service.
    #[must_use]
    pub fn with_arc_service(service: Arc<MicroCertificationService>) -> Self {
        Self {
            service,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create with custom batch size.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Run a single poll cycle - process all expirations across all tenants.
    ///
    /// Returns statistics about the processing.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<MicroCertExpirationStats, MicroCertExpirationJobError> {
        info!("Starting micro-certification expiration poll cycle");

        let now = Utc::now();
        let mut stats = MicroCertExpirationStats::default();

        // Step 1: Send reminders for certifications approaching deadline
        let reminder_stats = self.process_reminders(now).await?;
        stats.merge(&reminder_stats);

        // Step 2: Escalate certifications past escalation deadline
        let escalation_stats = self.process_escalations(now).await?;
        stats.merge(&escalation_stats);

        // Step 3: Process expired certifications (auto-revoke or mark expired)
        let expiration_stats = self.process_expirations(now).await?;
        stats.merge(&expiration_stats);

        if stats.processed > 0 {
            info!(
                processed = stats.processed,
                reminders_sent = stats.reminders_sent,
                escalations = stats.escalations,
                auto_revoked = stats.auto_revoked,
                expired = stats.expired,
                failed = stats.failed,
                "Completed micro-certification expiration poll cycle"
            );
        } else {
            debug!("No pending expirations to process");
        }

        Ok(stats)
    }

    // =========================================================================
    // T072: Send reminders
    // =========================================================================

    /// Process certifications that need reminders.
    #[instrument(skip(self))]
    async fn process_reminders(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<MicroCertExpirationStats, MicroCertExpirationJobError> {
        let mut stats = MicroCertExpirationStats::default();

        let certifications = GovMicroCertification::find_all_needing_reminder(
            self.service.pool(),
            now,
            self.batch_size,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to find certifications needing reminder");
            MicroCertExpirationJobError::Database(e.to_string())
        })?;

        if certifications.is_empty() {
            return Ok(stats);
        }

        debug!(
            count = certifications.len(),
            "Found certifications needing reminder"
        );

        for cert in certifications {
            stats.processed += 1;

            match self
                .service
                .mark_reminder_sent(cert.tenant_id, cert.id)
                .await
            {
                Ok(true) => {
                    stats.reminders_sent += 1;
                    debug!(
                        certification_id = %cert.id,
                        tenant_id = %cert.tenant_id,
                        "Reminder sent"
                    );
                }
                Ok(false) => {
                    debug!(certification_id = %cert.id, "Reminder already sent or not pending");
                }
                Err(e) => {
                    warn!(
                        certification_id = %cert.id,
                        error = %e,
                        "Failed to send reminder"
                    );
                    stats.failed += 1;
                }
            }
        }

        Ok(stats)
    }

    // =========================================================================
    // T073: Escalate to backup reviewer
    // =========================================================================

    /// Process certifications that need escalation.
    #[instrument(skip(self))]
    async fn process_escalations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<MicroCertExpirationStats, MicroCertExpirationJobError> {
        let mut stats = MicroCertExpirationStats::default();

        let certifications = GovMicroCertification::find_all_needing_escalation(
            self.service.pool(),
            now,
            self.batch_size,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to find certifications needing escalation");
            MicroCertExpirationJobError::Database(e.to_string())
        })?;

        if certifications.is_empty() {
            return Ok(stats);
        }

        debug!(
            count = certifications.len(),
            "Found certifications needing escalation"
        );

        for cert in certifications {
            stats.processed += 1;

            match self.service.mark_escalated(cert.tenant_id, cert.id).await {
                Ok(Some(_)) => {
                    stats.escalations += 1;
                    info!(
                        certification_id = %cert.id,
                        tenant_id = %cert.tenant_id,
                        backup_reviewer_id = ?cert.backup_reviewer_id,
                        "Certification escalated to backup reviewer"
                    );
                }
                Ok(None) => {
                    debug!(certification_id = %cert.id, "Certification already escalated or not pending");
                }
                Err(e) => {
                    warn!(
                        certification_id = %cert.id,
                        error = %e,
                        "Failed to escalate certification"
                    );
                    stats.failed += 1;
                }
            }
        }

        Ok(stats)
    }

    // =========================================================================
    // T074: Process expirations (auto-revoke or mark expired)
    // =========================================================================

    /// Process certifications that have passed their deadline.
    #[instrument(skip(self))]
    async fn process_expirations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<MicroCertExpirationStats, MicroCertExpirationJobError> {
        let mut stats = MicroCertExpirationStats::default();

        let certifications = GovMicroCertification::find_all_past_deadline(
            self.service.pool(),
            now,
            self.batch_size,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to find expired certifications");
            MicroCertExpirationJobError::Database(e.to_string())
        })?;

        if certifications.is_empty() {
            return Ok(stats);
        }

        info!(
            count = certifications.len(),
            "Found expired certifications to process"
        );

        for cert in certifications {
            stats.processed += 1;

            // Get the trigger rule to check auto_revoke setting
            let rule = GovMicroCertTrigger::find_by_id(
                self.service.pool(),
                cert.tenant_id,
                cert.trigger_rule_id,
            )
            .await
            .map_err(|e| MicroCertExpirationJobError::Database(e.to_string()))?;

            match rule {
                Some(rule) if rule.auto_revoke => {
                    // Auto-revoke the certification and assignment
                    match self
                        .service
                        .mark_auto_revoked(cert.tenant_id, cert.id)
                        .await
                    {
                        Ok(Some(updated)) => {
                            stats.auto_revoked += 1;
                            info!(
                                certification_id = %cert.id,
                                tenant_id = %cert.tenant_id,
                                assignment_id = ?cert.assignment_id,
                                revoked_assignment_id = ?updated.revoked_assignment_id,
                                "Certification auto-revoked due to timeout"
                            );
                        }
                        Ok(None) => {
                            debug!(certification_id = %cert.id, "Certification already processed");
                        }
                        Err(e) => {
                            warn!(
                                certification_id = %cert.id,
                                error = %e,
                                "Failed to auto-revoke certification"
                            );
                            stats.failed += 1;
                        }
                    }
                }
                _ => {
                    // Mark as expired without revoking
                    match self.service.mark_expired(cert.tenant_id, cert.id).await {
                        Ok(Some(_)) => {
                            stats.expired += 1;
                            info!(
                                certification_id = %cert.id,
                                tenant_id = %cert.tenant_id,
                                "Certification marked as expired (no auto-revoke)"
                            );
                        }
                        Ok(None) => {
                            debug!(certification_id = %cert.id, "Certification already processed");
                        }
                        Err(e) => {
                            warn!(
                                certification_id = %cert.id,
                                error = %e,
                                "Failed to mark certification as expired"
                            );
                            stats.failed += 1;
                        }
                    }
                }
            }
        }

        Ok(stats)
    }

    /// Get the recommended poll interval.
    #[must_use]
    pub const fn poll_interval_secs(&self) -> u64 {
        DEFAULT_POLL_INTERVAL_SECS
    }

    /// Get reference to the service.
    #[must_use]
    pub fn service(&self) -> &MicroCertificationService {
        &self.service
    }
}

/// Errors that can occur during expiration job execution.
#[derive(Debug, thiserror::Error)]
pub enum MicroCertExpirationJobError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Error processing expirations.
    #[error("Processing error: {0}")]
    Processing(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_POLL_INTERVAL_SECS, 60);
        assert_eq!(DEFAULT_BATCH_SIZE, 50);
    }

    #[test]
    fn test_expiration_stats_default() {
        let stats = MicroCertExpirationStats::default();
        assert_eq!(stats.processed, 0);
        assert_eq!(stats.reminders_sent, 0);
        assert_eq!(stats.escalations, 0);
        assert_eq!(stats.auto_revoked, 0);
        assert_eq!(stats.expired, 0);
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn test_expiration_stats_merge() {
        let mut stats1 = MicroCertExpirationStats {
            processed: 10,
            reminders_sent: 3,
            escalations: 2,
            auto_revoked: 4,
            expired: 1,
            failed: 0,
        };

        let stats2 = MicroCertExpirationStats {
            processed: 5,
            reminders_sent: 2,
            escalations: 1,
            auto_revoked: 1,
            expired: 0,
            failed: 1,
        };

        stats1.merge(&stats2);

        assert_eq!(stats1.processed, 15);
        assert_eq!(stats1.reminders_sent, 5);
        assert_eq!(stats1.escalations, 3);
        assert_eq!(stats1.auto_revoked, 5);
        assert_eq!(stats1.expired, 1);
        assert_eq!(stats1.failed, 1);
    }

    #[test]
    fn test_job_error_display() {
        let err = MicroCertExpirationJobError::Processing("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let db_err = MicroCertExpirationJobError::Database("connection failed".to_string());
        assert!(db_err.to_string().contains("connection failed"));
    }
}
