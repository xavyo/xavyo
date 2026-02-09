//! Script Analytics Service (F066).
//! Execution analytics, dashboard data, and alert threshold checks.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use xavyo_db::models::{
    gov_provisioning_script::GovProvisioningScript,
    gov_script_execution_log::{GovScriptExecutionLog, ScriptStats},
    gov_script_types::GovScriptStatus,
};
use xavyo_governance::error::{GovernanceError, Result};

// ============================================================================
// Data Structures
// ============================================================================

/// Aggregated dashboard data.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardData {
    /// Total number of provisioning scripts.
    pub total_scripts: i64,
    /// Number of scripts with active status.
    pub active_scripts: i64,
    /// Total execution count within the window.
    pub total_executions: i64,
    /// Success rate as a percentage (0.0 - 100.0).
    pub success_rate: f64,
    /// Average execution duration in milliseconds.
    pub avg_duration_ms: f64,
    /// Per-script summary rows.
    pub scripts: Vec<ScriptSummaryData>,
}

/// Per-script summary for the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct ScriptSummaryData {
    /// Script identifier.
    pub script_id: Uuid,
    /// Script display name.
    pub name: String,
    /// Total executions within the window.
    pub total_executions: i64,
    /// Successful execution count.
    pub success_count: i64,
    /// Failed execution count.
    pub failure_count: i64,
    /// Average execution duration in milliseconds.
    pub avg_duration_ms: f64,
}

/// Detailed per-script analytics.
#[derive(Debug, Clone, Serialize)]
pub struct ScriptAnalyticsData {
    /// Script identifier.
    pub script_id: Uuid,
    /// Script display name.
    pub name: String,
    /// Total executions within the window.
    pub total_executions: i64,
    /// Success rate as a percentage (0.0 - 100.0).
    pub success_rate: f64,
    /// Average execution duration in milliseconds.
    pub avg_duration_ms: f64,
    /// Daily trend data points.
    pub daily_trends: Vec<DailyTrendData>,
    /// Most common errors within the window.
    pub top_errors: Vec<ErrorSummaryData>,
}

/// Daily trend data point.
#[derive(Debug, Clone, Serialize)]
pub struct DailyTrendData {
    /// Date string (YYYY-MM-DD).
    pub date: String,
    /// Total executions on this date.
    pub executions: i64,
    /// Successful executions on this date.
    pub successes: i64,
    /// Failed executions on this date.
    pub failures: i64,
    /// Average duration in milliseconds on this date.
    pub avg_duration_ms: f64,
}

/// Error summary data.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorSummaryData {
    /// The error message.
    pub error_message: String,
    /// Number of occurrences.
    pub count: i64,
    /// When this error last occurred.
    pub last_occurred: DateTime<Utc>,
}

/// Helper struct for top errors query.
#[derive(Debug, FromRow)]
struct TopErrorRow {
    error_message: String,
    error_count: i64,
    last_occurred: DateTime<Utc>,
}

// ============================================================================
// Service
// ============================================================================

/// Service for script execution analytics and dashboard data.
pub struct ScriptAnalyticsService {
    pool: PgPool,
}

impl ScriptAnalyticsService {
    /// Create a new script analytics service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the dashboard overview with aggregated stats.
    ///
    /// By default, aggregates data from the last 30 days. Override with `days`.
    pub async fn get_dashboard(&self, tenant_id: Uuid, days: Option<i32>) -> Result<DashboardData> {
        let window_days = days.unwrap_or(30);
        let since = Utc::now() - Duration::days(i64::from(window_days));

        // 1. Count total scripts
        let total_scripts = sqlx::query_scalar::<_, i64>(
            r"
            SELECT COUNT(*) FROM gov_provisioning_scripts
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // 2. Count active scripts
        let active_scripts =
            GovProvisioningScript::count_by_status(&self.pool, tenant_id, GovScriptStatus::Active)
                .await
                .map_err(GovernanceError::Database)?;

        // 3. Get dashboard stats from execution logs
        let stats = GovScriptExecutionLog::get_dashboard_stats(&self.pool, tenant_id, since)
            .await
            .map_err(GovernanceError::Database)?;

        // 4. Get per-script stats
        let per_script_stats =
            GovScriptExecutionLog::get_per_script_stats(&self.pool, tenant_id, since)
                .await
                .map_err(GovernanceError::Database)?;

        // 5. Build per-script summaries by joining with script names
        let scripts = self
            .build_script_summaries(tenant_id, &per_script_stats)
            .await?;

        // 6. Calculate success rate
        let success_rate = if stats.total_executions > 0 {
            (stats.success_count as f64 / stats.total_executions as f64) * 100.0
        } else {
            0.0
        };

        Ok(DashboardData {
            total_scripts,
            active_scripts,
            total_executions: stats.total_executions,
            success_rate,
            avg_duration_ms: stats.avg_duration_ms,
            scripts,
        })
    }

    /// Get detailed analytics for a specific script.
    ///
    /// By default, aggregates data from the last 30 days. Override with `days`.
    pub async fn get_script_analytics(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        days: Option<i32>,
    ) -> Result<ScriptAnalyticsData> {
        let window_days = days.unwrap_or(30);
        let since = Utc::now() - Duration::days(i64::from(window_days));

        // 1. Get the script (for name)
        let script = GovProvisioningScript::get_by_id(&self.pool, script_id, tenant_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ProvisioningScriptNotFound(script_id))?;

        // 2. Get per-script stats
        let all_stats = GovScriptExecutionLog::get_per_script_stats(&self.pool, tenant_id, since)
            .await
            .map_err(GovernanceError::Database)?;

        let script_stats = all_stats
            .iter()
            .find(|s| s.script_id == Some(script_id))
            .cloned();

        let (total_executions, success_count, _failure_count, avg_duration_ms) = match script_stats
        {
            Some(s) => (
                s.total_executions,
                s.success_count,
                s.failure_count,
                s.avg_duration_ms,
            ),
            None => (0, 0, 0, 0.0),
        };

        // 3. Calculate success rate
        let success_rate = if total_executions > 0 {
            (success_count as f64 / total_executions as f64) * 100.0
        } else {
            0.0
        };

        // 4. Get daily trends
        let trend_rows =
            GovScriptExecutionLog::get_daily_trends(&self.pool, script_id, tenant_id, window_days)
                .await
                .map_err(GovernanceError::Database)?;

        let daily_trends: Vec<DailyTrendData> = trend_rows
            .into_iter()
            .map(|row| DailyTrendData {
                date: row.date.to_string(),
                executions: row.executions,
                successes: row.successes,
                failures: row.failures,
                avg_duration_ms: row.avg_duration_ms,
            })
            .collect();

        // 5. Get top errors
        let top_errors = self.get_top_errors(tenant_id, script_id, since).await?;

        Ok(ScriptAnalyticsData {
            script_id,
            name: script.name,
            total_executions,
            success_rate,
            avg_duration_ms,
            daily_trends,
            top_errors,
        })
    }

    /// Check if a script's error rate exceeds a threshold.
    ///
    /// Returns `true` if the error rate (0.0 - 100.0) exceeds the given
    /// `threshold_percent` within the specified time window.
    pub async fn check_error_threshold(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        threshold_percent: f64,
        window_hours: i32,
    ) -> Result<bool> {
        let since = Utc::now() - Duration::hours(i64::from(window_hours));

        let error_rate =
            GovScriptExecutionLog::get_error_rate(&self.pool, script_id, tenant_id, since)
                .await
                .map_err(GovernanceError::Database)?;

        // get_error_rate returns 0.0..1.0, convert to percentage
        let error_rate_percent = error_rate * 100.0;

        Ok(error_rate_percent > threshold_percent)
    }

    // ========================================================================
    // Execution Log Queries
    // ========================================================================

    /// List execution logs for a tenant with filtering and pagination.
    pub async fn list_execution_logs(
        &self,
        tenant_id: Uuid,
        filter: &xavyo_db::models::gov_script_execution_log::ExecutionLogFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovScriptExecutionLog>, i64)> {
        GovScriptExecutionLog::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get a single execution log entry by ID.
    pub async fn get_execution_log(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<GovScriptExecutionLog>> {
        GovScriptExecutionLog::get_by_id(&self.pool, id, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    // ========================================================================
    // Private Helpers
    // ========================================================================

    /// Build per-script summary data by joining stats with script names.
    async fn build_script_summaries(
        &self,
        tenant_id: Uuid,
        stats: &[ScriptStats],
    ) -> Result<Vec<ScriptSummaryData>> {
        let mut summaries = Vec::with_capacity(stats.len());

        for stat in stats {
            let script_id = match stat.script_id {
                Some(id) => id,
                None => continue, // skip entries without a script_id
            };

            // Look up the script name
            let name =
                match GovProvisioningScript::get_by_id(&self.pool, script_id, tenant_id).await {
                    Ok(Some(script)) => script.name,
                    Ok(None) => format!("Deleted script ({script_id})"),
                    Err(_) => format!("Unknown ({script_id})"),
                };

            summaries.push(ScriptSummaryData {
                script_id,
                name,
                total_executions: stat.total_executions,
                success_count: stat.success_count,
                failure_count: stat.failure_count,
                avg_duration_ms: stat.avg_duration_ms,
            });
        }

        Ok(summaries)
    }

    /// Get the top error messages for a script within a time window.
    async fn get_top_errors(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Vec<ErrorSummaryData>> {
        let rows = sqlx::query_as::<_, TopErrorRow>(
            r"
            SELECT
                error_message,
                COUNT(*) AS error_count,
                MAX(executed_at) AS last_occurred
            FROM gov_script_execution_logs
            WHERE tenant_id = $1
              AND script_id = $2
              AND executed_at >= $3
              AND execution_status = 'failure'
              AND error_message IS NOT NULL
            GROUP BY error_message
            ORDER BY error_count DESC
            LIMIT 10
            ",
        )
        .bind(tenant_id)
        .bind(script_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(rows
            .into_iter()
            .map(|row| ErrorSummaryData {
                error_message: row.error_message,
                count: row.error_count,
                last_occurred: row.last_occurred,
            })
            .collect())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_data_serialization() {
        let data = DashboardData {
            total_scripts: 10,
            active_scripts: 7,
            total_executions: 500,
            success_rate: 92.5,
            avg_duration_ms: 42.3,
            scripts: vec![ScriptSummaryData {
                script_id: Uuid::new_v4(),
                name: "Username Generator".to_string(),
                total_executions: 200,
                success_count: 190,
                failure_count: 10,
                avg_duration_ms: 35.0,
            }],
        };

        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"total_scripts\":10"));
        assert!(json.contains("\"active_scripts\":7"));
        assert!(json.contains("\"total_executions\":500"));
        assert!(json.contains("\"Username Generator\""));
    }

    #[test]
    fn test_dashboard_data_empty() {
        let data = DashboardData {
            total_scripts: 0,
            active_scripts: 0,
            total_executions: 0,
            success_rate: 0.0,
            avg_duration_ms: 0.0,
            scripts: vec![],
        };

        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"total_scripts\":0"));
        assert!(json.contains("\"scripts\":[]"));
    }

    #[test]
    fn test_script_summary_data_serialization() {
        let summary = ScriptSummaryData {
            script_id: Uuid::new_v4(),
            name: "Email Formatter".to_string(),
            total_executions: 100,
            success_count: 95,
            failure_count: 5,
            avg_duration_ms: 28.5,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"name\":\"Email Formatter\""));
        assert!(json.contains("\"total_executions\":100"));
        assert!(json.contains("\"success_count\":95"));
        assert!(json.contains("\"failure_count\":5"));
    }

    #[test]
    fn test_script_analytics_data_serialization() {
        let analytics = ScriptAnalyticsData {
            script_id: Uuid::new_v4(),
            name: "AD Account Setup".to_string(),
            total_executions: 300,
            success_rate: 96.7,
            avg_duration_ms: 55.0,
            daily_trends: vec![DailyTrendData {
                date: "2026-01-27".to_string(),
                executions: 20,
                successes: 19,
                failures: 1,
                avg_duration_ms: 48.0,
            }],
            top_errors: vec![ErrorSummaryData {
                error_message: "Connection timeout".to_string(),
                count: 5,
                last_occurred: Utc::now(),
            }],
        };

        let json = serde_json::to_string(&analytics).unwrap();
        assert!(json.contains("\"name\":\"AD Account Setup\""));
        assert!(json.contains("\"daily_trends\""));
        assert!(json.contains("\"top_errors\""));
        assert!(json.contains("\"Connection timeout\""));
    }

    #[test]
    fn test_daily_trend_data_serialization() {
        let trend = DailyTrendData {
            date: "2026-01-25".to_string(),
            executions: 50,
            successes: 48,
            failures: 2,
            avg_duration_ms: 40.0,
        };

        let json = serde_json::to_string(&trend).unwrap();
        assert!(json.contains("\"date\":\"2026-01-25\""));
        assert!(json.contains("\"executions\":50"));
        assert!(json.contains("\"successes\":48"));
        assert!(json.contains("\"failures\":2"));
    }

    #[test]
    fn test_error_summary_data_serialization() {
        let now = Utc::now();
        let error = ErrorSummaryData {
            error_message: "Script runtime error: undefined variable".to_string(),
            count: 12,
            last_occurred: now,
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"error_message\":\"Script runtime error: undefined variable\""));
        assert!(json.contains("\"count\":12"));
        assert!(json.contains("\"last_occurred\""));
    }

    #[test]
    fn test_success_rate_calculation() {
        // With executions
        let total = 200i64;
        let success = 180i64;
        let rate = (success as f64 / total as f64) * 100.0;
        assert!((rate - 90.0).abs() < f64::EPSILON);

        // Zero executions
        let total = 0i64;
        let rate: f64 = if total > 0 { 50.0 } else { 0.0 };
        assert!((rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_error_threshold_logic() {
        // error_rate from model is 0.0..1.0, we multiply by 100
        let error_rate = 0.15; // 15%
        let error_rate_percent = error_rate * 100.0;

        // Threshold at 10% should trigger
        assert!(error_rate_percent > 10.0);

        // Threshold at 20% should not trigger
        assert!(error_rate_percent.partial_cmp(&20.0) != Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn test_error_threshold_zero_rate() {
        let error_rate = 0.0;
        let error_rate_percent = error_rate * 100.0;

        // Any positive threshold should not trigger
        assert!(error_rate_percent.partial_cmp(&1.0) != Some(std::cmp::Ordering::Greater));
        assert!(error_rate_percent.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn test_dashboard_data_success_rate_full_success() {
        let total = 500i64;
        let success = 500i64;
        let rate = if total > 0 {
            (success as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        assert!((rate - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dashboard_data_success_rate_no_success() {
        let total = 100i64;
        let success = 0i64;
        let rate = if total > 0 {
            (success as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        assert!((rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_script_analytics_empty_trends_and_errors() {
        let analytics = ScriptAnalyticsData {
            script_id: Uuid::new_v4(),
            name: "Empty Script".to_string(),
            total_executions: 0,
            success_rate: 0.0,
            avg_duration_ms: 0.0,
            daily_trends: vec![],
            top_errors: vec![],
        };

        assert!(analytics.daily_trends.is_empty());
        assert!(analytics.top_errors.is_empty());
        assert_eq!(analytics.total_executions, 0);
    }

    #[test]
    fn test_script_summary_all_failures() {
        let summary = ScriptSummaryData {
            script_id: Uuid::new_v4(),
            name: "Broken Script".to_string(),
            total_executions: 50,
            success_count: 0,
            failure_count: 50,
            avg_duration_ms: 100.0,
        };

        assert_eq!(summary.success_count, 0);
        assert_eq!(summary.failure_count, 50);
        assert_eq!(summary.total_executions, 50);
    }
}
