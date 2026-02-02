//! NHI Usage Service for F061.
//!
//! Provides usage tracking for Non-Human Identities:
//! - Recording authentication/access events
//! - Usage summary and analytics
//! - Staleness detection

use chrono::Utc;
use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use uuid::Uuid;

use xavyo_governance::GovernanceError;

use crate::models::{
    NhiUsageEventResponse, NhiUsageListQuery, NhiUsageListResponse,
    NhiUsageSummaryExtendedResponse, RecordUsageRequest, StaleNhiInfo, StalenessReportResponse,
};

#[cfg(feature = "kafka")]
use xavyo_events::{events::nhi::NhiUsageRecorded, EventProducer};

use xavyo_db::{
    CreateGovNhiUsageEvent, GovNhiUsageEvent, GovServiceAccount, NhiUsageEventFilter,
    NhiUsageOutcome, ServiceAccountFilter, ServiceAccountStatus,
};

type Result<T> = std::result::Result<T, GovernanceError>;

/// Service for managing NHI usage tracking.
pub struct NhiUsageService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl NhiUsageService {
    /// Create a new usage service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Set the event producer for Kafka integration.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    // =========================================================================
    // Record Usage
    // =========================================================================

    /// Record a usage event for an NHI.
    ///
    /// This is the primary method called during NHI authentication or API calls.
    pub async fn record_usage(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        request: RecordUsageRequest,
    ) -> Result<NhiUsageEventResponse> {
        // Validate NHI exists
        let _ = GovServiceAccount::find_by_id(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(nhi_id))?;

        // Create the usage event
        let create_data = CreateGovNhiUsageEvent {
            nhi_id,
            target_resource: request.target_resource.clone(),
            action: request.action.clone(),
            outcome: request.outcome,
            source_ip: request.source_ip.clone(),
            user_agent: request.user_agent.clone(),
            duration_ms: request.duration_ms,
            metadata: request.metadata.clone(),
        };

        let event = GovNhiUsageEvent::create(&self.pool, tenant_id, create_data)
            .await
            .map_err(GovernanceError::Database)?;

        // Update NHI's last_used_at if this was a successful event
        if request.outcome == NhiUsageOutcome::Success {
            let _ = GovServiceAccount::update_last_used(&self.pool, tenant_id, nhi_id).await;
        }

        tracing::debug!(
            tenant_id = %tenant_id,
            nhi_id = %nhi_id,
            resource = %request.target_resource,
            action = %request.action,
            outcome = ?request.outcome,
            "NHI usage event recorded"
        );

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_usage_event(tenant_id, nhi_id, &request).await;

        Ok(NhiUsageEventResponse::from(event))
    }

    /// Record multiple usage events in batch (for high-volume scenarios).
    pub async fn record_usage_batch(
        &self,
        tenant_id: Uuid,
        events: Vec<(Uuid, RecordUsageRequest)>,
    ) -> Result<Vec<NhiUsageEventResponse>> {
        let mut results = Vec::with_capacity(events.len());

        for (nhi_id, request) in events {
            match self.record_usage(tenant_id, nhi_id, request).await {
                Ok(event) => results.push(event),
                Err(e) => {
                    tracing::warn!(error = %e, nhi_id = %nhi_id, "Failed to record usage event");
                    // Continue processing other events
                }
            }
        }

        Ok(results)
    }

    // =========================================================================
    // Query Usage
    // =========================================================================

    /// Get usage events for an NHI with filtering and pagination.
    pub async fn list_usage(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        query: NhiUsageListQuery,
    ) -> Result<NhiUsageListResponse> {
        // Validate NHI exists
        let _ = GovServiceAccount::find_by_id(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(nhi_id))?;

        let filter = NhiUsageEventFilter {
            nhi_id: Some(nhi_id),
            target_resource: query.target_resource.clone(),
            outcome: query.outcome,
            start_date: query.start_date,
            end_date: query.end_date,
        };

        let limit = query.limit.unwrap_or(50);
        let offset = query.offset.unwrap_or(0);

        let events = GovNhiUsageEvent::list(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovNhiUsageEvent::count(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        let items: Vec<NhiUsageEventResponse> = events
            .into_iter()
            .map(NhiUsageEventResponse::from)
            .collect();

        Ok(NhiUsageListResponse {
            items,
            total,
            limit: limit as i32,
            offset: offset as i32,
        })
    }

    /// Get usage summary for an NHI.
    pub async fn get_summary(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        period_days: Option<i32>,
    ) -> Result<NhiUsageSummaryExtendedResponse> {
        // Validate NHI exists
        let nhi = GovServiceAccount::find_by_id(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(nhi_id))?;

        let period = period_days.unwrap_or(30);

        let summary = GovNhiUsageEvent::get_summary(&self.pool, tenant_id, nhi_id, period)
            .await
            .map_err(GovernanceError::Database)?;

        let top_resources =
            GovNhiUsageEvent::get_top_resources(&self.pool, tenant_id, nhi_id, period, 10)
                .await
                .map_err(GovernanceError::Database)?;

        // Calculate success rate
        let success_rate = if summary.total_events > 0 {
            (summary.successful_events as f64 / summary.total_events as f64) * 100.0
        } else {
            0.0
        };

        Ok(NhiUsageSummaryExtendedResponse {
            nhi_id,
            nhi_name: nhi.name,
            period_days: period,
            total_events: summary.total_events,
            successful_events: summary.successful_events,
            failed_events: summary.failed_events,
            denied_events: summary.denied_events,
            success_rate,
            unique_resources: summary.unique_resources,
            top_resources: top_resources
                .into_iter()
                .map(|r| crate::models::ResourceAccessInfo {
                    resource: r.target_resource,
                    access_count: r.access_count,
                    last_access: r.last_access,
                })
                .collect(),
            last_used_at: summary.last_used_at,
        })
    }

    // =========================================================================
    // Staleness Detection
    // =========================================================================

    /// Get a staleness report for all NHIs in the tenant.
    ///
    /// Returns NHIs that haven't been used within their inactivity threshold
    /// or a default period.
    pub async fn get_staleness_report(
        &self,
        tenant_id: Uuid,
        min_inactive_days: Option<i32>,
    ) -> Result<StalenessReportResponse> {
        let threshold = min_inactive_days.unwrap_or(30);

        // Get all active NHIs
        let filter = ServiceAccountFilter {
            status: Some(ServiceAccountStatus::Active),
            inactive_days: Some(threshold),
            ..Default::default()
        };

        let nhis = GovServiceAccount::list(&self.pool, tenant_id, &filter, 1000, 0)
            .await
            .map_err(GovernanceError::Database)?;

        let now = Utc::now();
        let mut stale_nhis: Vec<StaleNhiInfo> = Vec::new();

        for nhi in nhis {
            let days_inactive = nhi
                .last_used_at
                .map(|last| (now - last).num_days())
                .unwrap_or(
                    // If never used, calculate from creation date
                    (now - nhi.created_at).num_days(),
                );

            let individual_threshold = nhi.inactivity_threshold_days.unwrap_or(90);

            // Only include if truly stale (beyond individual threshold)
            if days_inactive >= individual_threshold as i64 {
                stale_nhis.push(StaleNhiInfo {
                    nhi_id: nhi.id,
                    name: nhi.name.clone(),
                    owner_id: nhi.owner_id,
                    days_inactive: days_inactive as i32,
                    last_used_at: nhi.last_used_at,
                    inactivity_threshold_days: individual_threshold,
                    in_grace_period: nhi.is_in_grace_period(),
                    grace_period_ends_at: nhi.grace_period_ends_at,
                });
            }
        }

        // Sort by days inactive descending (most stale first)
        stale_nhis.sort_by(|a, b| b.days_inactive.cmp(&a.days_inactive));

        let total_stale = stale_nhis.len() as i64;
        let critical_count = stale_nhis.iter().filter(|n| n.days_inactive > 180).count() as i64;
        let warning_count = stale_nhis
            .iter()
            .filter(|n| n.days_inactive > 90 && n.days_inactive <= 180)
            .count() as i64;

        Ok(StalenessReportResponse {
            generated_at: now,
            min_inactive_days: threshold,
            total_stale,
            critical_count,
            warning_count,
            stale_nhis,
        })
    }

    // =========================================================================
    // Kafka Event Emission (Private)
    // =========================================================================

    #[cfg(feature = "kafka")]
    async fn emit_usage_event(&self, tenant_id: Uuid, nhi_id: Uuid, request: &RecordUsageRequest) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiUsageRecorded {
                nhi_id,
                tenant_id,
                target_resource: request.target_resource.clone(),
                action: request.action.clone(),
                outcome: format!("{:?}", request.outcome).to_lowercase(),
                recorded_at: Utc::now(),
            };

            if let Err(e) = producer.publish(&event).await {
                tracing::warn!(error = %e, "Failed to publish NhiUsageRecorded event");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_service_construction() {
        // Basic test to ensure module compiles
        assert!(true);
    }
}
