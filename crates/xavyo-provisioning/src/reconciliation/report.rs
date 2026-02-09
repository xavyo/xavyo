//! Reconciliation report generation.
//!
//! Generates detailed reports with statistics and action logs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::statistics::RunStatistics;
use super::types::ReconciliationMode;

/// Complete reconciliation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationReport {
    /// Run information.
    pub run: RunInfo,
    /// Discrepancy summary.
    pub discrepancy_summary: DiscrepancySummary,
    /// Action summary.
    pub action_summary: ActionSummary,
    /// Top mismatched attributes.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub top_mismatched_attributes: Vec<AttributeMismatchCount>,
    /// Performance metrics.
    pub performance: PerformanceMetrics,
}

/// Run information for the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    /// Run ID.
    pub id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Connector name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,
    /// Mode.
    pub mode: ReconciliationMode,
    /// Status.
    pub status: String,
    /// Triggered by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<Uuid>,
    /// Triggered by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by_name: Option<String>,
    /// Started at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// Completed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Statistics.
    pub statistics: RunStatistics,
}

/// Summary of discrepancies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscrepancySummary {
    /// Total discrepancies.
    pub total: u32,
    /// By type.
    pub by_type: HashMap<String, u32>,
    /// By resolution status.
    pub by_resolution: HashMap<String, u32>,
}

impl DiscrepancySummary {
    /// Create empty summary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            total: 0,
            by_type: HashMap::new(),
            by_resolution: HashMap::new(),
        }
    }
}

impl Default for DiscrepancySummary {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSummary {
    /// Total actions.
    pub total: u32,
    /// By type.
    pub by_type: HashMap<String, u32>,
    /// By result.
    pub by_result: HashMap<String, u32>,
}

impl ActionSummary {
    /// Create empty summary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            total: 0,
            by_type: HashMap::new(),
            by_result: HashMap::new(),
        }
    }
}

impl Default for ActionSummary {
    fn default() -> Self {
        Self::new()
    }
}

/// Count of mismatches for an attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMismatchCount {
    /// Attribute name.
    pub attribute: String,
    /// Number of mismatches.
    pub count: u32,
}

/// Performance metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Accounts processed per second.
    pub accounts_per_second: f64,
    /// Total duration in seconds.
    pub total_duration_seconds: u64,
}

impl PerformanceMetrics {
    /// Calculate from statistics.
    #[must_use]
    pub fn from_statistics(stats: &RunStatistics) -> Self {
        let accounts_per_second = if stats.duration_seconds > 0 {
            f64::from(stats.accounts_processed) / stats.duration_seconds as f64
        } else {
            0.0
        };

        Self {
            accounts_per_second,
            total_duration_seconds: stats.duration_seconds,
        }
    }
}

/// Report generator.
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generate a report from run data.
    #[must_use]
    pub fn generate(
        run_info: RunInfo,
        discrepancy_summary: DiscrepancySummary,
        action_summary: ActionSummary,
        top_mismatched_attributes: Vec<AttributeMismatchCount>,
    ) -> ReconciliationReport {
        let performance = PerformanceMetrics::from_statistics(&run_info.statistics);

        ReconciliationReport {
            run: run_info,
            discrepancy_summary,
            action_summary,
            top_mismatched_attributes,
            performance,
        }
    }

    /// Generate CSV export of discrepancies.
    #[must_use]
    pub fn generate_csv(discrepancies: &[DiscrepancyCsvRow]) -> String {
        let mut csv = String::new();

        // Header
        csv.push_str(
            "id,type,identity_id,external_uid,resolution_status,resolved_action,detected_at\n",
        );

        // Rows
        for d in discrepancies {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                d.id,
                d.discrepancy_type,
                d.identity_id.as_deref().unwrap_or(""),
                d.external_uid,
                d.resolution_status,
                d.resolved_action.as_deref().unwrap_or(""),
                d.detected_at,
            ));
        }

        csv
    }
}

/// Row for CSV export.
#[derive(Debug, Clone)]
pub struct DiscrepancyCsvRow {
    /// Discrepancy ID.
    pub id: String,
    /// Discrepancy type.
    pub discrepancy_type: String,
    /// Identity ID.
    pub identity_id: Option<String>,
    /// External UID.
    pub external_uid: String,
    /// Resolution status.
    pub resolution_status: String,
    /// Resolved action.
    pub resolved_action: Option<String>,
    /// Detected at.
    pub detected_at: String,
}

/// Trend data for discrepancies over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscrepancyTrend {
    /// Data points.
    pub data_points: Vec<TrendDataPoint>,
    /// Connector ID filter (if applied).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<Uuid>,
    /// From date.
    pub from: DateTime<Utc>,
    /// To date.
    pub to: DateTime<Utc>,
}

/// Single data point in trend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDataPoint {
    /// Date.
    pub date: String,
    /// Total discrepancies.
    pub total: u32,
    /// By type.
    pub by_type: HashMap<String, u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discrepancy_summary_new() {
        let summary = DiscrepancySummary::new();
        assert_eq!(summary.total, 0);
        assert!(summary.by_type.is_empty());
        assert!(summary.by_resolution.is_empty());
    }

    #[test]
    fn test_action_summary_new() {
        let summary = ActionSummary::new();
        assert_eq!(summary.total, 0);
        assert!(summary.by_type.is_empty());
        assert!(summary.by_result.is_empty());
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_performance_metrics_calculation() {
        let mut stats = RunStatistics::default();
        stats.accounts_processed = 1000;
        stats.duration_seconds = 100;

        let metrics = PerformanceMetrics::from_statistics(&stats);

        assert!((metrics.accounts_per_second - 10.0).abs() < f64::EPSILON);
        assert_eq!(metrics.total_duration_seconds, 100);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_performance_metrics_zero_duration() {
        let mut stats = RunStatistics::default();
        stats.accounts_processed = 1000;
        stats.duration_seconds = 0;

        let metrics = PerformanceMetrics::from_statistics(&stats);

        assert!((metrics.accounts_per_second - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_csv_generation() {
        let rows = vec![
            DiscrepancyCsvRow {
                id: "id1".to_string(),
                discrepancy_type: "missing".to_string(),
                identity_id: Some("identity1".to_string()),
                external_uid: "uid=test1".to_string(),
                resolution_status: "pending".to_string(),
                resolved_action: None,
                detected_at: "2026-01-25T10:00:00Z".to_string(),
            },
            DiscrepancyCsvRow {
                id: "id2".to_string(),
                discrepancy_type: "orphan".to_string(),
                identity_id: None,
                external_uid: "uid=test2".to_string(),
                resolution_status: "resolved".to_string(),
                resolved_action: Some("delete".to_string()),
                detected_at: "2026-01-25T11:00:00Z".to_string(),
            },
        ];

        let csv = ReportGenerator::generate_csv(&rows);

        assert!(csv.contains(
            "id,type,identity_id,external_uid,resolution_status,resolved_action,detected_at"
        ));
        assert!(csv.contains("id1,missing,identity1,uid=test1,pending,,2026-01-25T10:00:00Z"));
        assert!(csv.contains("id2,orphan,,uid=test2,resolved,delete,2026-01-25T11:00:00Z"));
    }

    #[test]
    fn test_report_generation() {
        let run_info = RunInfo {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: Some("LDAP".to_string()),
            mode: ReconciliationMode::Full,
            status: "completed".to_string(),
            triggered_by: None,
            triggered_by_name: None,
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            statistics: RunStatistics {
                accounts_total: 1000,
                accounts_processed: 1000,
                discrepancies_found: 50,
                ..Default::default()
            },
        };

        let mut discrepancy_summary = DiscrepancySummary::new();
        discrepancy_summary.total = 50;
        discrepancy_summary.by_type.insert("orphan".to_string(), 30);
        discrepancy_summary
            .by_type
            .insert("mismatch".to_string(), 20);

        let action_summary = ActionSummary::new();

        let top_mismatched = vec![
            AttributeMismatchCount {
                attribute: "email".to_string(),
                count: 15,
            },
            AttributeMismatchCount {
                attribute: "department".to_string(),
                count: 5,
            },
        ];

        let report = ReportGenerator::generate(
            run_info,
            discrepancy_summary,
            action_summary,
            top_mismatched,
        );

        assert_eq!(report.discrepancy_summary.total, 50);
        assert_eq!(report.top_mismatched_attributes.len(), 2);
        assert_eq!(report.top_mismatched_attributes[0].attribute, "email");
    }
}
