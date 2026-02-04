//! SIEM Health service (F078).
//!
//! Provides delivery health summaries, health history windows,
//! dead letter queue management, and re-delivery triggering.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{SiemDeliveryHealth, SiemDestination, SiemExportEvent};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for SIEM delivery health and dead letter management.
pub struct SiemHealthService {
    pool: PgPool,
}

impl SiemHealthService {
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get health summary for a destination (last 24 hours).
    ///
    /// Combines aggregated delivery health metrics with the destination's
    /// current circuit breaker state and dead letter count.
    pub async fn get_health_summary(
        &self,
        tenant_id: Uuid,
        destination_id: Uuid,
    ) -> Result<HealthSummaryData> {
        // Verify destination exists
        let destination = SiemDestination::find_by_id(&self.pool, tenant_id, destination_id)
            .await?
            .ok_or(GovernanceError::SiemDestinationNotFound(destination_id))?;

        // Get aggregated health metrics (last 24h)
        let health_summary =
            SiemDeliveryHealth::get_summary(&self.pool, tenant_id, destination_id).await?;

        // Count dead letter events
        let dead_letter_count =
            SiemExportEvent::count_by_status(&self.pool, tenant_id, destination_id, "dead_letter")
                .await?;

        Ok(HealthSummaryData {
            destination_id,
            total_events_sent: health_summary
                .as_ref()
                .map_or(0, |h| h.total_events_sent),
            total_events_delivered: health_summary
                .as_ref()
                .map_or(0, |h| h.total_events_delivered),
            total_events_failed: health_summary
                .as_ref()
                .map_or(0, |h| h.total_events_failed),
            total_events_dropped: health_summary
                .as_ref()
                .map_or(0, |h| h.total_events_dropped),
            avg_latency_ms: health_summary.as_ref().and_then(|h| h.avg_latency_ms),
            last_success_at: health_summary.as_ref().and_then(|h| h.last_success_at),
            last_failure_at: health_summary.as_ref().and_then(|h| h.last_failure_at),
            success_rate_percent: health_summary
                .as_ref()
                .map_or(0.0, |h| h.success_rate_percent),
            circuit_state: destination.circuit_state,
            dead_letter_count,
        })
    }

    /// Get health history windows for a destination over a time range.
    pub async fn get_health_history(
        &self,
        tenant_id: Uuid,
        destination_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SiemDeliveryHealth>, i64)> {
        // Verify destination exists
        SiemDestination::find_by_id(&self.pool, tenant_id, destination_id)
            .await?
            .ok_or(GovernanceError::SiemDestinationNotFound(destination_id))?;

        let windows = SiemDeliveryHealth::list_history(
            &self.pool,
            tenant_id,
            destination_id,
            from,
            to,
            limit,
            offset,
        )
        .await?;

        let total =
            SiemDeliveryHealth::count_history(&self.pool, tenant_id, destination_id, from, to)
                .await?;

        Ok((windows, total))
    }

    /// List dead letter events for a destination.
    pub async fn list_dead_letter_events(
        &self,
        tenant_id: Uuid,
        destination_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SiemExportEvent>, i64)> {
        // Verify destination exists
        SiemDestination::find_by_id(&self.pool, tenant_id, destination_id)
            .await?
            .ok_or(GovernanceError::SiemDestinationNotFound(destination_id))?;

        let events =
            SiemExportEvent::list_dead_letter(&self.pool, tenant_id, destination_id, limit, offset)
                .await?;

        let total =
            SiemExportEvent::count_by_status(&self.pool, tenant_id, destination_id, "dead_letter")
                .await?;

        Ok((events, total))
    }

    /// Re-queue all dead letter events for a destination for re-delivery.
    /// Returns the number of events re-queued.
    pub async fn redeliver_events(&self, tenant_id: Uuid, destination_id: Uuid) -> Result<u64> {
        // Verify destination exists
        SiemDestination::find_by_id(&self.pool, tenant_id, destination_id)
            .await?
            .ok_or(GovernanceError::SiemDestinationNotFound(destination_id))?;

        let count =
            SiemExportEvent::redeliver_dead_letter(&self.pool, tenant_id, destination_id).await?;

        Ok(count)
    }
}

/// Health summary data returned by the service.
#[derive(Debug, Clone)]
pub struct HealthSummaryData {
    pub destination_id: Uuid,
    pub total_events_sent: i64,
    pub total_events_delivered: i64,
    pub total_events_failed: i64,
    pub total_events_dropped: i64,
    pub avg_latency_ms: Option<i32>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub success_rate_percent: f64,
    pub circuit_state: String,
    pub dead_letter_count: i64,
}
