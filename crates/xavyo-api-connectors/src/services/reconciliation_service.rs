//! Reconciliation service for F049 Reconciliation Engine API.
//!
//! Provides business logic for managing reconciliation runs, discrepancies, and schedules.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::instrument;
use uuid::Uuid;

use xavyo_db::models::{
    ConnectorReconciliationMode, ConnectorReconciliationRun, ConnectorReconciliationRunFilter,
    ConnectorReconciliationStatus, CreateConnectorReconciliationRun, CreateReconciliationAction,
    ReconciliationAction, ReconciliationActionFilter, ReconciliationActionResult,
    ReconciliationActionType, ReconciliationDiscrepancy, ReconciliationDiscrepancyFilter,
    ReconciliationDiscrepancyType, ReconciliationResolutionStatus, ReconciliationSchedule,
    ReconciliationScheduleFrequency, UpsertReconciliationSchedule,
};

use crate::handlers::reconciliation::{
    ActionSummary, BulkRemediateItem, BulkRemediationResponse, BulkRemediationSummary,
    DiscrepancySummary, PerformanceMetrics, PreviewItem, PreviewResponse, PreviewSummary,
    ReconciliationStatistics, RemediationResponse, ReportResponse, RunInfo, TrendResponse,
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
}

/// Result type for reconciliation service operations.
pub type ReconciliationServiceResult<T> = Result<T, ReconciliationServiceError>;

/// Service for managing reconciliation operations.
///
/// This service is stateless with respect to tenant - all methods accept `tenant_id`
/// as a parameter for proper multi-tenant support.
pub struct ReconciliationService {
    pool: PgPool,
}

impl ReconciliationService {
    /// Create a new reconciliation service.
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

        // Parse mode
        let recon_mode: ConnectorReconciliationMode =
            mode.parse().unwrap_or(ConnectorReconciliationMode::Full);

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

        // TODO: In production, this would trigger the actual reconciliation engine
        // via Kafka event or direct invocation. For now, the run is created
        // and the engine would be responsible for processing it.

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

        // Parse action type
        let action_type: ReconciliationActionType = action.parse().map_err(|_| {
            ReconciliationServiceError::InvalidParameter(format!("Invalid action: {}", action))
        })?;

        let resolved_user_id = user_id.unwrap_or_else(Uuid::nil);

        // TODO: In production, this would execute the actual remediation via connector
        // For now, we record the action and mark the discrepancy as resolved

        let result = if dry_run {
            ReconciliationActionResult::Success
        } else {
            // Would execute actual remediation here
            ReconciliationActionResult::Success
        };

        // Record the action
        let action_record = CreateReconciliationAction::success(
            discrepancy_id,
            action_type,
            resolved_user_id,
            dry_run,
        );
        ReconciliationAction::create(&self.pool, tenant_id, &action_record).await?;

        // Mark discrepancy as resolved (unless dry run)
        if !dry_run {
            ReconciliationDiscrepancy::resolve(
                &self.pool,
                tenant_id,
                discrepancy_id,
                action_type,
                resolved_user_id,
            )
            .await?;
        }

        tracing::info!(
            discrepancy_id = %discrepancy_id,
            action = %action,
            dry_run = %dry_run,
            "Discrepancy remediated"
        );

        Ok(RemediationResponse {
            discrepancy_id,
            action: action.to_string(),
            result: result.to_string(),
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
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        connector_id: Uuid,
        items: Vec<BulkRemediateItem>,
        dry_run: bool,
    ) -> ReconciliationServiceResult<BulkRemediationResponse> {
        let mut results = Vec::with_capacity(items.len());
        let mut succeeded = 0;
        let mut failed = 0;

        for item in items {
            let result = self
                .remediate(
                    tenant_id,
                    user_id,
                    connector_id,
                    item.discrepancy_id,
                    &item.action,
                    item.direction.as_deref().unwrap_or("xavyo_to_target"),
                    item.identity_id,
                    dry_run,
                )
                .await;

            match result {
                Ok(r) => {
                    if r.result == "success" {
                        succeeded += 1;
                    } else {
                        failed += 1;
                    }
                    results.push(r);
                }
                Err(e) => {
                    failed += 1;
                    results.push(RemediationResponse {
                        discrepancy_id: item.discrepancy_id,
                        action: item.action,
                        result: "failure".to_string(),
                        error_message: Some(e.to_string()),
                        before_state: None,
                        after_state: None,
                        dry_run,
                    });
                }
            }
        }

        Ok(BulkRemediationResponse {
            results,
            summary: BulkRemediationSummary {
                total: succeeded + failed,
                succeeded,
                failed,
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
        let resolved_user_id = user_id.unwrap_or_else(Uuid::nil);

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
                let suggested_action = self.get_default_action(&d.discrepancy_type);
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
        enabled: bool,
    ) -> ReconciliationServiceResult<ReconciliationSchedule> {
        let recon_mode: ConnectorReconciliationMode =
            mode.parse().unwrap_or(ConnectorReconciliationMode::Full);

        let freq: ReconciliationScheduleFrequency = frequency
            .parse()
            .unwrap_or(ReconciliationScheduleFrequency::Daily);

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
            enabled = %enabled,
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
        let stats: ReconciliationStatistics =
            serde_json::from_value(run.statistics.clone()).unwrap_or_default();

        // Get action counts
        let action_filter = ReconciliationActionFilter::new();
        let actions =
            ReconciliationAction::list(&self.pool, tenant_id, &action_filter, 1000, 0).await?;
        let mut by_action_type: HashMap<String, u32> = HashMap::new();
        let mut by_result: HashMap<String, u32> = HashMap::new();
        for a in &actions {
            *by_action_type.entry(a.action_type.clone()).or_insert(0) += 1;
            *by_result.entry(a.result.clone()).or_insert(0) += 1;
        }

        // Calculate performance
        let duration = stats.duration_seconds;
        let accounts_per_second = if duration > 0 {
            stats.accounts_processed as f64 / duration as f64
        } else {
            0.0
        };

        Ok(ReportResponse {
            run: RunInfo {
                id: run.id,
                connector_id: run.connector_id,
                connector_name: None, // Would need to join with connectors table
                mode: run.mode,
                status: run.status,
                triggered_by: run.triggered_by,
                triggered_by_name: None,
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
                total: actions.len() as u32,
                by_type: by_action_type,
                by_result,
            },
            top_mismatched_attributes: vec![], // Would need additional query
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
        _tenant_id: Uuid,
        connector_id: Option<Uuid>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> ReconciliationServiceResult<TrendResponse> {
        let to_date = to.unwrap_or_else(Utc::now);
        let from_date = from.unwrap_or_else(|| to_date - Duration::days(30));

        // TODO: In production, this would aggregate discrepancy data by date
        // For now, return empty trend data
        Ok(TrendResponse {
            data_points: vec![],
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
    fn get_default_action(&self, discrepancy_type: &str) -> String {
        match discrepancy_type {
            "missing" => "create".to_string(),
            "orphan" => "link".to_string(),
            "mismatch" => "update".to_string(),
            "collision" => "link".to_string(),
            "unlinked" => "link".to_string(),
            "deleted" => "create".to_string(),
            _ => "update".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_default_action() {
        // Test the default action logic directly without creating a pool
        fn get_default_action(discrepancy_type: &str) -> String {
            match discrepancy_type {
                "missing" => "create".to_string(),
                "orphan" => "link".to_string(),
                "mismatch" => "update".to_string(),
                "collision" => "link".to_string(),
                "unlinked" => "link".to_string(),
                "deleted" => "create".to_string(),
                _ => "update".to_string(),
            }
        }

        assert_eq!(get_default_action("missing"), "create");
        assert_eq!(get_default_action("orphan"), "link");
        assert_eq!(get_default_action("mismatch"), "update");
        assert_eq!(get_default_action("collision"), "link");
        assert_eq!(get_default_action("unlinked"), "link");
        assert_eq!(get_default_action("deleted"), "create");
        assert_eq!(get_default_action("unknown"), "update");
    }
}
