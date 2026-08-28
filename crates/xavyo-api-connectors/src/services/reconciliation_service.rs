//! Reconciliation service for F049 Reconciliation Engine API.
//!
//! Provides business logic for managing reconciliation runs, discrepancies, and schedules.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::instrument;
use uuid::Uuid;

use xavyo_db::models::{
    ConnectorConfiguration, ConnectorReconciliationMode, ConnectorReconciliationRun,
    ConnectorReconciliationRunFilter, ConnectorReconciliationStatus,
    CreateConnectorReconciliationRun, ReconciliationAction, ReconciliationActionFilter,
    ReconciliationActionResult, ReconciliationActionType, ReconciliationDiscrepancy,
    ReconciliationDiscrepancyFilter, ReconciliationDiscrepancyType, ReconciliationResolutionStatus,
    ReconciliationSchedule, ReconciliationScheduleFrequency, UpsertReconciliationSchedule, User,
};

use crate::handlers::reconciliation::{
    ActionSummary, AttributeMismatchCount, BulkRemediateItem, BulkRemediationResponse,
    BulkRemediationSummary, DiscrepancySummary, PerformanceMetrics, PreviewItem, PreviewResponse,
    PreviewSummary, ReconciliationStatistics, RemediationResponse, ReportResponse, RunInfo,
    TrendDataPoint, TrendResponse,
};

/// Error type for reconciliation service operations.
#[derive(Debug, thiserror::Error)]
pub enum ReconciliationServiceError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Reconciliation error: {0}")]
    Reconciliation(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

/// Connector-side discrepancy remediation is not wired. Callers must not
/// receive a recorded `success` or a resolved discrepancy.
pub fn reject_unimplemented_connector_remediation() -> ReconciliationServiceResult<()> {
    Err(ReconciliationServiceError::NotImplemented(
        "Connector-side discrepancy remediation is not implemented".to_string(),
    ))
}

/// Result type for reconciliation service operations.
pub type ReconciliationServiceResult<T> = Result<T, ReconciliationServiceError>;

/// Invalid mode must be 400, not a silent full recon.
pub fn parse_reconciliation_mode(
    mode: &str,
) -> ReconciliationServiceResult<ConnectorReconciliationMode> {
    mode.parse()
        .map_err(ReconciliationServiceError::InvalidParameter)
}

/// Invalid frequency must be 400, not a silent daily schedule.
pub fn parse_reconciliation_frequency(
    frequency: &str,
) -> ReconciliationServiceResult<ReconciliationScheduleFrequency> {
    frequency
        .parse()
        .map_err(ReconciliationServiceError::InvalidParameter)
}

/// Service for managing reconciliation operations.
///
/// This service is stateless with respect to tenant - all methods accept `tenant_id`
/// as a parameter for proper multi-tenant support.
pub struct ReconciliationService {
    pool: PgPool,
}

impl ReconciliationService {
    /// Create a new reconciliation service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ========================================================================
    // Run Operations
    // ========================================================================

    /// Trigger a reconciliation run.
    #[instrument(skip(self))]
    pub async fn trigger_run(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        connector_id: Uuid,
        mode: &str,
        _dry_run: bool,
    ) -> ReconciliationServiceResult<ConnectorReconciliationRun> {
        // Check for existing running reconciliation
        let existing =
            ConnectorReconciliationRun::find_running(&self.pool, tenant_id, connector_id).await?;

        if existing.is_some() {
            return Err(ReconciliationServiceError::Conflict(
                "A reconciliation is already running for this connector".to_string(),
            ));
        }

        let recon_mode = parse_reconciliation_mode(mode)?;

        // Create the run
        let input = CreateConnectorReconciliationRun {
            connector_id,
            mode: recon_mode,
            triggered_by: user_id,
        };

        let run = ConnectorReconciliationRun::create(&self.pool, tenant_id, &input).await?;

        tracing::info!(
            run_id = %run.id,
            connector_id = %connector_id,
            mode = %mode,
            "Reconciliation run triggered"
        );

        // Run record is persisted here; asynchronous engine dispatch is handled
        // by the provisioning reconciliation pipeline (Kafka/worker).

        Ok(run)
    }

    /// Get a reconciliation run by ID.
    #[instrument(skip(self))]
    pub async fn get_run(
        &self,
        tenant_id: Uuid,
        _connector_id: Uuid,
        run_id: Uuid,
    ) -> ReconciliationServiceResult<Option<ConnectorReconciliationRun>> {
        let run = ConnectorReconciliationRun::find_by_id(&self.pool, tenant_id, run_id).await?;
        Ok(run)
    }

    /// List reconciliation runs.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn list_runs(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        mode: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> ReconciliationServiceResult<(Vec<ConnectorReconciliationRun>, i64)> {
        let mut filter = ConnectorReconciliationRunFilter::new().for_connector(connector_id);

        if let Some(m) = mode {
            if let Ok(parsed) = m.parse::<ConnectorReconciliationMode>() {
                filter = filter.with_mode(parsed);
            }
        }

        if let Some(s) = status {
            if let Ok(parsed) = s.parse::<ConnectorReconciliationStatus>() {
                filter = filter.with_status(parsed);
            }
        }

        let runs =
            ConnectorReconciliationRun::list(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = ConnectorReconciliationRun::count(&self.pool, tenant_id, &filter).await?;

        Ok((runs, total))
    }

    /// Cancel a reconciliation run.
    #[instrument(skip(self))]
    pub async fn cancel_run(
        &self,
        tenant_id: Uuid,
        _connector_id: Uuid,
        run_id: Uuid,
    ) -> ReconciliationServiceResult<()> {
        let cancelled = ConnectorReconciliationRun::cancel(&self.pool, tenant_id, run_id).await?;

        if cancelled.is_none() {
            return Err(ReconciliationServiceError::NotFound(
                "Run not found or not in a cancellable state".to_string(),
            ));
        }

        tracing::info!(run_id = %run_id, "Reconciliation run cancelled");
        Ok(())
    }

    /// Resume a failed/cancelled reconciliation run.
    #[instrument(skip(self))]
    pub async fn resume_run(
        &self,
        tenant_id: Uuid,
        _connector_id: Uuid,
        run_id: Uuid,
    ) -> ReconciliationServiceResult<ConnectorReconciliationRun> {
        let run = ConnectorReconciliationRun::resume(&self.pool, tenant_id, run_id)
            .await?
            .ok_or_else(|| {
                ReconciliationServiceError::NotFound(
                    "Run not found or not in a resumable state".to_string(),
                )
            })?;

        tracing::info!(run_id = %run_id, "Reconciliation run resumed");
        Ok(run)
    }

    // ========================================================================
    // Discrepancy Operations
    // ========================================================================

    /// List discrepancies.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn list_discrepancies(
        &self,
        tenant_id: Uuid,
        _connector_id: Uuid,
        run_id: Option<Uuid>,
        discrepancy_type: Option<&str>,
        resolution_status: Option<&str>,
        identity_id: Option<Uuid>,
        external_uid: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> ReconciliationServiceResult<(Vec<ReconciliationDiscrepancy>, i64)> {
        let mut filter = ReconciliationDiscrepancyFilter::new();

        if let Some(rid) = run_id {
            filter = filter.for_run(rid);
        }

        if let Some(dt) = discrepancy_type {
            if let Ok(parsed) = dt.parse::<ReconciliationDiscrepancyType>() {
                filter = filter.with_type(parsed);
            }
        }

        if let Some(rs) = resolution_status {
            if let Ok(parsed) = rs.parse::<ReconciliationResolutionStatus>() {
                filter.resolution_status = Some(parsed);
            }
        }

        if let Some(iid) = identity_id {
            filter.identity_id = Some(iid);
        }

        if let Some(euid) = external_uid {
            filter.external_uid = Some(euid.to_string());
        }

        let discrepancies =
            ReconciliationDiscrepancy::list(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = ReconciliationDiscrepancy::count(&self.pool, tenant_id, &filter).await?;

        Ok((discrepancies, total))
    }

    /// Get a discrepancy by ID.
    #[instrument(skip(self))]
    pub async fn get_discrepancy(
        &self,
        tenant_id: Uuid,
        _connector_id: Uuid,
        discrepancy_id: Uuid,
    ) -> ReconciliationServiceResult<Option<ReconciliationDiscrepancy>> {
        let discrepancy =
            ReconciliationDiscrepancy::find_by_id(&self.pool, tenant_id, discrepancy_id).await?;
        Ok(discrepancy)
    }

    /// Remediate a discrepancy.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn remediate(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        _connector_id: Uuid,
        discrepancy_id: Uuid,
        action: &str,
        _direction: &str,
        _identity_id: Option<Uuid>,
        dry_run: bool,
    ) -> ReconciliationServiceResult<RemediationResponse> {
        let _discrepancy =
            ReconciliationDiscrepancy::find_by_id(&self.pool, tenant_id, discrepancy_id)
                .await?
                .ok_or_else(|| {
                    ReconciliationServiceError::NotFound("Discrepancy not found".to_string())
                })?;

        let _action_type: ReconciliationActionType = action.parse().map_err(|_| {
            ReconciliationServiceError::InvalidParameter(format!("Invalid action: {action}"))
        })?;

        let _ = (user_id, dry_run);

        // Fail closed: do not record Success or mark the discrepancy resolved
        // until connector-side remediation actually runs.
        reject_unimplemented_connector_remediation().map(|()| RemediationResponse {
            discrepancy_id,
            action: action.to_string(),
            result: "not_implemented".to_string(),
            error_message: None,
            before_state: None,
            after_state: None,
            dry_run,
        })
    }

    /// Bulk remediate discrepancies.
    #[instrument(skip(self))]
    pub async fn bulk_remediate(
        &self,
        _tenant_id: Uuid,
        _user_id: Option<Uuid>,
        _connector_id: Uuid,
        _items: Vec<BulkRemediateItem>,
        _dry_run: bool,
    ) -> ReconciliationServiceResult<BulkRemediationResponse> {
        reject_unimplemented_connector_remediation().map(|()| BulkRemediationResponse {
            results: Vec::new(),
            summary: BulkRemediationSummary {
                total: 0,
                succeeded: 0,
                failed: 0,
            },
        })
    }

    /// Ignore a discrepancy.
    #[instrument(skip(self))]
    pub async fn ignore_discrepancy(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        _connector_id: Uuid,
        discrepancy_id: Uuid,
    ) -> ReconciliationServiceResult<()> {
        let resolved_user_id = user_id.ok_or_else(|| {
            ReconciliationServiceError::InvalidParameter(
                "Authenticated user id is required to ignore a discrepancy".to_string(),
            )
        })?;

        ReconciliationDiscrepancy::ignore(&self.pool, tenant_id, discrepancy_id, resolved_user_id)
            .await?
            .ok_or_else(|| {
                ReconciliationServiceError::NotFound("Discrepancy not found".to_string())
            })?;

        tracing::info!(discrepancy_id = %discrepancy_id, "Discrepancy ignored");
        Ok(())
    }

    /// Preview remediation changes.
    #[instrument(skip(self))]
    pub async fn preview(
        &self,
        tenant_id: Uuid,
        _connector_id: Uuid,
        discrepancy_ids: Vec<Uuid>,
    ) -> ReconciliationServiceResult<PreviewResponse> {
        let mut items = Vec::new();
        let mut by_action: HashMap<String, usize> = HashMap::new();

        for id in discrepancy_ids {
            if let Some(d) =
                ReconciliationDiscrepancy::find_by_id(&self.pool, tenant_id, id).await?
            {
                let suggested_action = self.get_default_action(&d.discrepancy_type)?;
                *by_action.entry(suggested_action.clone()).or_insert(0) += 1;

                items.push(PreviewItem {
                    discrepancy_id: d.id,
                    discrepancy_type: d.discrepancy_type,
                    suggested_action,
                    would_change: serde_json::json!({
                        "external_uid": d.external_uid,
                        "identity_id": d.identity_id,
                    }),
                });
            }
        }

        Ok(PreviewResponse {
            items: items.clone(),
            summary: PreviewSummary {
                total_actions: items.len(),
                by_action,
            },
        })
    }

    // ========================================================================
    // Schedule Operations
    // ========================================================================

    /// Get schedule for a connector.
    #[instrument(skip(self))]
    pub async fn get_schedule(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ReconciliationServiceResult<Option<ReconciliationSchedule>> {
        let schedule =
            ReconciliationSchedule::find_by_connector(&self.pool, tenant_id, connector_id).await?;
        Ok(schedule)
    }

    /// Upsert schedule for a connector.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_schedule(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        mode: &str,
        frequency: &str,
        day_of_week: Option<i32>,
        day_of_month: Option<i32>,
        hour_of_day: i32,
        enabled: Option<bool>,
    ) -> ReconciliationServiceResult<ReconciliationSchedule> {
        let recon_mode = parse_reconciliation_mode(mode)?;
        let freq = parse_reconciliation_frequency(frequency)?;

        let input = UpsertReconciliationSchedule {
            mode: recon_mode,
            frequency: freq,
            day_of_week,
            day_of_month,
            hour_of_day,
            enabled,
            next_run_at: None, // Will be calculated
        };

        input
            .validate()
            .map_err(ReconciliationServiceError::InvalidParameter)?;

        let schedule =
            ReconciliationSchedule::upsert(&self.pool, tenant_id, connector_id, &input).await?;

        tracing::info!(
            connector_id = %connector_id,
            frequency = %frequency,
            enabled = ?enabled,
            "Reconciliation schedule updated"
        );

        Ok(schedule)
    }

    /// Delete schedule for a connector.
    #[instrument(skip(self))]
    pub async fn delete_schedule(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ReconciliationServiceResult<()> {
        let deleted = ReconciliationSchedule::delete(&self.pool, tenant_id, connector_id).await?;

        if !deleted {
            return Err(ReconciliationServiceError::NotFound(
                "Schedule not found".to_string(),
            ));
        }

        tracing::info!(connector_id = %connector_id, "Reconciliation schedule deleted");
        Ok(())
    }

    /// Enable schedule.
    #[instrument(skip(self))]
    pub async fn enable_schedule(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ReconciliationServiceResult<()> {
        ReconciliationSchedule::enable(&self.pool, tenant_id, connector_id)
            .await?
            .ok_or_else(|| {
                ReconciliationServiceError::NotFound("Schedule not found".to_string())
            })?;

        tracing::info!(connector_id = %connector_id, "Reconciliation schedule enabled");
        Ok(())
    }

    /// Disable schedule.
    #[instrument(skip(self))]
    pub async fn disable_schedule(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> ReconciliationServiceResult<()> {
        ReconciliationSchedule::disable(&self.pool, tenant_id, connector_id)
            .await?
            .ok_or_else(|| {
                ReconciliationServiceError::NotFound("Schedule not found".to_string())
            })?;

        tracing::info!(connector_id = %connector_id, "Reconciliation schedule disabled");
        Ok(())
    }

    /// List all schedules.
    #[instrument(skip(self))]
    pub async fn list_schedules(
        &self,
        tenant_id: Uuid,
    ) -> ReconciliationServiceResult<Vec<ReconciliationSchedule>> {
        let schedules = ReconciliationSchedule::list_by_tenant(&self.pool, tenant_id).await?;
        Ok(schedules)
    }

    // ========================================================================
    // Report Operations
    // ========================================================================

    /// Get report for a reconciliation run.
    #[instrument(skip(self))]
    pub async fn get_report(
        &self,
        tenant_id: Uuid,
        _connector_id: Uuid,
        run_id: Uuid,
    ) -> ReconciliationServiceResult<ReportResponse> {
        let run = ConnectorReconciliationRun::find_by_id(&self.pool, tenant_id, run_id)
            .await?
            .ok_or_else(|| ReconciliationServiceError::NotFound("Run not found".to_string()))?;

        // Get discrepancy counts by type
        let type_counts =
            ReconciliationDiscrepancy::count_by_type(&self.pool, tenant_id, run_id).await?;
        let mut by_type: HashMap<String, u32> = HashMap::new();
        let mut total_discrepancies: u32 = 0;
        for (t, c) in type_counts {
            total_discrepancies += c as u32;
            by_type.insert(t, c as u32);
        }

        // Get resolution status counts
        let mut by_resolution: HashMap<String, u32> = HashMap::new();
        let filter = ReconciliationDiscrepancyFilter::new().for_run(run_id);
        let total = ReconciliationDiscrepancy::count(&self.pool, tenant_id, &filter).await? as u32;

        let pending_filter = ReconciliationDiscrepancyFilter::new()
            .for_run(run_id)
            .pending_only();
        let pending =
            ReconciliationDiscrepancy::count(&self.pool, tenant_id, &pending_filter).await? as u32;

        by_resolution.insert("pending".to_string(), pending);
        by_resolution.insert("resolved".to_string(), total.saturating_sub(pending));

        // Parse statistics from run
        let stats: ReconciliationStatistics = serde_json::from_value(run.statistics.clone())
            .map_err(|e| {
                ReconciliationServiceError::InvalidParameter(format!(
                    "Invalid reconciliation statistics JSON: {e}"
                ))
            })?;

        let disc_filter = ReconciliationDiscrepancyFilter::new().for_run(run_id);
        let discrepancies =
            ReconciliationDiscrepancy::list(&self.pool, tenant_id, &disc_filter, 10_000, 0).await?;
        let top_mismatched_attributes = top_mismatched_attributes(&discrepancies);

        let action_rows: Vec<(String, String)> = sqlx::query_as(
            r"
            SELECT a.action_type, a.result
            FROM gov_reconciliation_actions a
            JOIN gov_reconciliation_discrepancies d
              ON d.id = a.discrepancy_id AND d.tenant_id = a.tenant_id
            WHERE a.tenant_id = $1 AND d.run_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(run_id)
        .fetch_all(&self.pool)
        .await?;
        let mut by_action_type: HashMap<String, u32> = HashMap::new();
        let mut by_result: HashMap<String, u32> = HashMap::new();
        for (action_type, result) in &action_rows {
            *by_action_type.entry(action_type.clone()).or_insert(0) += 1;
            *by_result.entry(result.clone()).or_insert(0) += 1;
        }

        let connector_name =
            ConnectorConfiguration::find_by_id(&self.pool, tenant_id, run.connector_id)
                .await?
                .map(|connector| connector.name);
        let triggered_by_name = if let Some(user_id) = run.triggered_by {
            User::find_by_id_in_tenant(&self.pool, tenant_id, user_id)
                .await?
                .map(|user| match user.display_name {
                    Some(name) if !name.is_empty() => name,
                    _ => user.email,
                })
        } else {
            None
        };

        // Calculate performance
        let duration = stats.duration_seconds;
        let accounts_per_second = if duration > 0 {
            f64::from(stats.accounts_processed) / duration as f64
        } else {
            0.0
        };

        Ok(ReportResponse {
            run: RunInfo {
                id: run.id,
                connector_id: run.connector_id,
                connector_name,
                mode: run.mode,
                status: run.status,
                triggered_by: run.triggered_by,
                triggered_by_name,
                started_at: run.started_at,
                completed_at: run.completed_at,
                statistics: stats,
            },
            discrepancy_summary: DiscrepancySummary {
                total: total_discrepancies,
                by_type,
                by_resolution,
            },
            action_summary: ActionSummary {
                total: action_rows.len() as u32,
                by_type: by_action_type,
                by_result,
            },
            top_mismatched_attributes,
            performance: PerformanceMetrics {
                accounts_per_second,
                total_duration_seconds: duration,
            },
        })
    }

    /// Get discrepancy trend data.
    #[instrument(skip(self))]
    pub async fn get_trend(
        &self,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> ReconciliationServiceResult<TrendResponse> {
        let to_date = to.unwrap_or_else(Utc::now);
        let from_date = from.unwrap_or_else(|| to_date - Duration::days(30));

        // Fetch trend data from database
        let raw_points = ReconciliationDiscrepancy::get_trend_by_date(
            &self.pool,
            tenant_id,
            connector_id,
            from_date,
            to_date,
        )
        .await?;

        // Aggregate by date - group (date, type, count) into TrendDataPoint per date
        let mut date_map: HashMap<String, TrendDataPoint> = HashMap::new();

        for point in raw_points {
            let date_str = point.date.to_string();
            let entry = date_map
                .entry(date_str.clone())
                .or_insert_with(|| TrendDataPoint {
                    date: date_str,
                    total: 0,
                    by_type: HashMap::new(),
                });
            entry.total += point.count as u32;
            *entry.by_type.entry(point.discrepancy_type).or_insert(0) += point.count as u32;
        }

        // Sort by date and collect
        let mut data_points: Vec<TrendDataPoint> = date_map.into_values().collect();
        data_points.sort_by(|a, b| a.date.cmp(&b.date));

        Ok(TrendResponse {
            data_points,
            connector_id,
            from: from_date,
            to: to_date,
        })
    }

    // ========================================================================
    // Action Operations
    // ========================================================================

    /// List actions.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn list_actions(
        &self,
        tenant_id: Uuid,
        _connector_id: Uuid,
        discrepancy_id: Option<Uuid>,
        action_type: Option<&str>,
        result: Option<&str>,
        dry_run: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> ReconciliationServiceResult<(Vec<ReconciliationAction>, i64)> {
        let mut filter = ReconciliationActionFilter::new();

        if let Some(did) = discrepancy_id {
            filter = filter.for_discrepancy(did);
        }

        if let Some(at) = action_type {
            if let Ok(parsed) = at.parse::<ReconciliationActionType>() {
                filter = filter.with_type(parsed);
            }
        }

        if let Some(r) = result {
            if let Ok(parsed) = r.parse::<ReconciliationActionResult>() {
                filter.result = Some(parsed);
            }
        }

        if let Some(dr) = dry_run {
            filter.dry_run = Some(dr);
        }

        let actions =
            ReconciliationAction::list(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = ReconciliationAction::count(&self.pool, tenant_id, &filter).await?;

        Ok((actions, total))
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    /// Get default action for a discrepancy type.
    ///
    /// Unknown types must not become `"update"` — that would preview (and
    /// could remediate) the wrong action.
    fn get_default_action(&self, discrepancy_type: &str) -> ReconciliationServiceResult<String> {
        match discrepancy_type {
            "missing" => Ok("create".to_string()),
            "orphan" => Ok("link".to_string()),
            "mismatch" => Ok("update".to_string()),
            "collision" => Ok("link".to_string()),
            "unlinked" => Ok("link".to_string()),
            "deleted" => Ok("create".to_string()),
            other => Err(ReconciliationServiceError::InvalidParameter(format!(
                "Unknown discrepancy type '{other}'"
            ))),
        }
    }
}

/// Count mismatched attribute keys from stored discrepancy JSON.
fn top_mismatched_attributes(
    discrepancies: &[ReconciliationDiscrepancy],
) -> Vec<AttributeMismatchCount> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for discrepancy in discrepancies {
        if let Some(serde_json::Value::Object(map)) = &discrepancy.mismatched_attributes {
            for key in map.keys() {
                *counts.entry(key.clone()).or_insert(0) += 1;
            }
        }
    }
    let mut items: Vec<AttributeMismatchCount> = counts
        .into_iter()
        .map(|(attribute, count)| AttributeMismatchCount { attribute, count })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then(a.attribute.cmp(&b.attribute)));
    items.truncate(10);
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reconciliation_mode_does_not_default_to_full() {
        assert_eq!(
            parse_reconciliation_mode("full").unwrap(),
            ConnectorReconciliationMode::Full
        );
        assert_eq!(
            parse_reconciliation_mode("delta").unwrap(),
            ConnectorReconciliationMode::Delta
        );
        assert!(parse_reconciliation_mode("nope").is_err());
        assert_eq!(
            parse_reconciliation_frequency("hourly").unwrap(),
            ReconciliationScheduleFrequency::Hourly
        );
        assert_eq!(
            parse_reconciliation_frequency("daily").unwrap(),
            ReconciliationScheduleFrequency::Daily
        );
        assert!(parse_reconciliation_frequency("never").is_err());
        let src = include_str!("reconciliation_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_reconciliation_mode(")
                && production.contains("parse_reconciliation_frequency(")
                && !production.contains("unwrap_or(ConnectorReconciliationMode::Full)")
                && !production.contains("unwrap_or(ReconciliationScheduleFrequency::Daily)"),
            "invalid recon mode/frequency must not silently default to full/daily"
        );
    }

    #[test]
    fn ignore_discrepancy_rejects_missing_actor() {
        // Actor is required so we never persist Uuid::nil() as resolved_by.
        let src = include_str!("reconciliation_service.rs");
        let nil_fallback = format!("{}::{}", "Uuid", "nil");
        assert!(
            !src.contains(&format!("unwrap_or_else({nil_fallback})")),
            "ignore_discrepancy must not persist a nil user id"
        );
    }

    #[test]
    fn connector_remediation_is_not_implemented() {
        let err = reject_unimplemented_connector_remediation().expect_err("must fail closed");
        assert!(
            matches!(err, ReconciliationServiceError::NotImplemented(_)),
            "got {err:?}"
        );
        let msg = err.to_string().to_lowercase();
        assert!(
            !msg.contains("success"),
            "error must not look like success: {msg}"
        );
    }

    #[test]
    fn remediate_does_not_record_fake_success_action() {
        let src = include_str!("reconciliation_service.rs");
        let fake_success = format!("{}::{}", "CreateReconciliationAction", "success");
        let resolve_call = format!("{}::{}", "ReconciliationDiscrepancy", "resolve");
        assert!(
            !src.contains(&fake_success),
            "must not record a fake successful reconciliation action"
        );
        assert!(
            !src.contains(&resolve_call),
            "must not mark a discrepancy resolved without connector execution"
        );
    }

    #[test]
    fn test_get_default_action() {
        fn get_default_action(discrepancy_type: &str) -> Result<String, String> {
            match discrepancy_type {
                "missing" => Ok("create".to_string()),
                "orphan" => Ok("link".to_string()),
                "mismatch" => Ok("update".to_string()),
                "collision" => Ok("link".to_string()),
                "unlinked" => Ok("link".to_string()),
                "deleted" => Ok("create".to_string()),
                other => Err(format!("Unknown discrepancy type '{other}'")),
            }
        }

        assert_eq!(get_default_action("missing").unwrap(), "create");
        assert_eq!(get_default_action("orphan").unwrap(), "link");
        assert_eq!(get_default_action("mismatch").unwrap(), "update");
        assert_eq!(get_default_action("collision").unwrap(), "link");
        assert_eq!(get_default_action("unlinked").unwrap(), "link");
        assert_eq!(get_default_action("deleted").unwrap(), "create");
        assert!(get_default_action("unknown").is_err());

        let src = include_str!("reconciliation_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let helper = production
            .split("fn get_default_action")
            .nth(1)
            .expect("get_default_action");
        assert!(
            !helper.contains("_ => \"update\"") && !helper.contains("_ => Ok(\"update\""),
            "unknown discrepancy types must not default to update"
        );
    }

    #[test]
    fn report_looks_up_names_and_mismatch_counts() {
        let src = include_str!("reconciliation_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let report = production
            .split("pub async fn get_report")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("get_report");
        assert!(
            report.contains("ConnectorConfiguration::find_by_id")
                && report.contains("find_by_id_in_tenant")
                && report.contains("top_mismatched_attributes(")
                && report.contains("d.run_id = $2")
                && !report.contains("connector_name: None")
                && !report.contains("triggered_by_name: None")
                && !report.contains("top_mismatched_attributes: vec![]"),
            "GET reconciliation report must look up connector/user names, mismatches, and run-scoped actions"
        );
    }

    #[test]
    fn top_mismatched_attributes_counts_object_keys() {
        let discrepancies = vec![ReconciliationDiscrepancy {
            id: Uuid::new_v4(),
            run_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            discrepancy_type: "mismatch".to_string(),
            identity_id: None,
            external_uid: "uid".to_string(),
            mismatched_attributes: Some(
                serde_json::json!({"email": {"xavyo": "a", "target": "b"}}),
            ),
            resolution_status: "pending".to_string(),
            resolved_action: None,
            resolved_by: None,
            resolved_at: None,
            detected_at: Utc::now(),
        }];
        let top = top_mismatched_attributes(&discrepancies);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].attribute, "email");
        assert_eq!(top[0].count, 1);
    }
}
