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
    CreateGovNhiUsageEvent, GovNhiUsageEvent, NhiIdentity, NhiUsageEventFilter, NhiUsageOutcome,
};
use xavyo_nhi::NhiLifecycleState;

type Result<T> = std::result::Result<T, GovernanceError>;

/// Service for managing NHI usage tracking.
pub struct NhiUsageService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl NhiUsageService {
    /// Create a new usage service.
    #[must_use]
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
        let _ = NhiIdentity::find_by_id(&self.pool, tenant_id, nhi_id)
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

        // Update NHI's last_used_at if this was a successful event.
        // Persist errors must not look like usage was recorded for inactivity.
        if request.outcome == NhiUsageOutcome::Success {
            nhi_last_used_recorded(
                touch_nhi_last_activity(&self.pool, tenant_id, nhi_id)
                    .await
                    .map_err(GovernanceError::Database),
            )?;
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
        let _ = NhiIdentity::find_by_id(&self.pool, tenant_id, nhi_id)
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
        let offset = query.offset.unwrap_or(0).max(0);

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
        let nhi = NhiIdentity::find_by_id(&self.pool, tenant_id, nhi_id)
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

        let nhis = sqlx::query_as::<_, NhiIdentity>(
            r"
            SELECT * FROM nhi_identities
            WHERE tenant_id = $1
              AND lifecycle_state = $2
            ORDER BY name ASC
            LIMIT 1000
            ",
        )
        .bind(tenant_id)
        .bind(NhiLifecycleState::Active.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let now = Utc::now();
        let mut stale_nhis: Vec<StaleNhiInfo> = Vec::new();

        for nhi in nhis {
            let Some(owner_id) = nhi.owner_id else {
                continue;
            };
            let days_inactive = nhi
                .last_activity_at
                .map_or((now - nhi.created_at).num_days(), |last| {
                    (now - last).num_days()
                });

            let individual_threshold = nhi.inactivity_threshold_days.unwrap_or(90);

            // Only include if truly stale (beyond individual threshold)
            if days_inactive >= i64::from(individual_threshold)
                && days_inactive >= i64::from(threshold)
            {
                stale_nhis.push(StaleNhiInfo {
                    nhi_id: nhi.id,
                    name: nhi.name.clone(),
                    owner_id,
                    days_inactive: days_inactive as i32,
                    last_used_at: nhi.last_activity_at,
                    inactivity_threshold_days: individual_threshold,
                    in_grace_period: nhi.grace_period_ends_at.is_some_and(|ends| ends > now),
                    grace_period_ends_at: nhi.grace_period_ends_at,
                });
            }
        }

        // Sort by days inactive descending (most stale first)
        stale_nhis.sort_by_key(|n| std::cmp::Reverse(n.days_inactive));

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

/// Persist last_used_at after successful NHI usage. Errors must not skip
/// inactivity tracking.
fn nhi_last_used_recorded<T, E>(result: std::result::Result<T, E>) -> std::result::Result<T, E> {
    result
}

async fn touch_nhi_last_activity(
    pool: &PgPool,
    tenant_id: Uuid,
    nhi_id: Uuid,
) -> std::result::Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r"
        UPDATE nhi_identities
        SET last_activity_at = NOW(), updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(nhi_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_construction() {
        // Basic test to ensure module compiles
    }

    #[test]
    fn nhi_last_used_recorded_propagates_errors() {
        assert!(nhi_last_used_recorded(Ok::<(), &str>(())).is_ok());
        assert!(nhi_last_used_recorded(Err::<(), _>("db")).is_err());
    }

    #[test]
    fn record_usage_does_not_swallow_last_used_persist() {
        let src = include_str!("nhi_usage_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let record = production
            .split("pub async fn record_usage")
            .nth(1)
            .and_then(|s| s.split("pub async fn record_usage_batch").next())
            .expect("record_usage");
        assert!(
            record.contains("nhi_last_used_recorded(")
                && record.contains("touch_nhi_last_activity(")
                && record.contains("NhiIdentity::find_by_id"),
            "last_used persist must fail closed against nhi_identities"
        );
        assert!(
            !record.contains("GovServiceAccount::update_last_used")
                && !record.contains("let _ = touch_nhi_last_activity"),
            "must not swallow last_used persist after successful usage"
        );
    }

    #[test]
    fn usage_queries_unified_nhi_identities() {
        let src = include_str!("nhi_usage_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("NhiIdentity::find_by_id")
                && production.contains("FROM nhi_identities")
                && !production.contains("GovServiceAccount::"),
            "NHI usage GET/POST must look up nhi_identities, not the dropped gov_service_accounts table"
        );
    }
}
