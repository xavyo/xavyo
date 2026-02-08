//! Request and response models for outlier detection API (F059).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use utoipa::{IntoParams, ToSchema};

use super::batch_simulation::{BatchSimulationResponse, BatchSimulationResultResponse};
use super::policy_simulation::{PolicySimulationResponse, PolicySimulationResultResponse};
use super::simulation_comparison::SimulationComparisonResponse;

use xavyo_db::{
    FactorBreakdown, FactorScore, OutlierAlertSeverity, OutlierAlertType, OutlierAnalysisStatus,
    OutlierClassification, OutlierDispositionStatus, OutlierTriggerType, PeerGroupScore,
    ScoringWeights,
};

// ============================================================================
// Configuration Models
// ============================================================================

/// Request to update outlier detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateOutlierConfigRequest {
    /// Z-score threshold for outlier classification (0.0-5.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_threshold: Option<f64>,

    /// Minimum frequency for a role to be considered "normal" (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_threshold: Option<f64>,

    /// Minimum users in peer group for statistical validity (2-100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_peer_group_size: Option<i32>,

    /// Weights for each scoring factor (must sum to 1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scoring_weights: Option<ScoringWeights>,

    /// Cron expression for scheduled analysis (null to disable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_cron: Option<String>,

    /// Days to retain analysis results (30-3650).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<i32>,

    /// Whether outlier detection is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_enabled: Option<bool>,
}

/// Response containing outlier detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OutlierConfigResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub confidence_threshold: f64,
    pub frequency_threshold: f64,
    pub min_peer_group_size: i32,
    pub scoring_weights: ScoringWeights,
    pub schedule_cron: Option<String>,
    pub retention_days: i32,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// Analysis Models
// ============================================================================

/// Request to trigger a new outlier analysis.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TriggerAnalysisRequest {
    /// How the analysis was triggered.
    pub triggered_by: OutlierTriggerType,
}

/// Response containing analysis details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OutlierAnalysisResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: OutlierAnalysisStatus,
    pub triggered_by: OutlierTriggerType,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub users_analyzed: i32,
    pub outliers_detected: i32,
    pub progress_percent: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for listing analyses.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListAnalysesQuery {
    pub status: Option<OutlierAnalysisStatus>,
    pub triggered_by: Option<OutlierTriggerType>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Default for ListAnalysesQuery {
    fn default() -> Self {
        Self {
            status: None,
            triggered_by: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

// ============================================================================
// Result Models
// ============================================================================

/// Response containing outlier result details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OutlierResultResponse {
    pub id: Uuid,
    pub analysis_id: Uuid,
    pub user_id: Uuid,
    pub overall_score: f64,
    pub classification: OutlierClassification,
    pub peer_scores: Vec<PeerGroupScore>,
    pub factor_breakdown: FactorBreakdown,
    pub previous_score: Option<f64>,
    pub score_change: Option<f64>,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for listing results.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListResultsQuery {
    pub analysis_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub classification: Option<OutlierClassification>,
    pub min_score: Option<f64>,
    pub max_score: Option<f64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Default for ListResultsQuery {
    fn default() -> Self {
        Self {
            analysis_id: None,
            user_id: None,
            classification: None,
            min_score: None,
            max_score: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Summary statistics for outlier results.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OutlierSummaryResponse {
    pub total_users: i64,
    pub outlier_count: i64,
    pub normal_count: i64,
    pub unclassifiable_count: i64,
    pub avg_score: f64,
    pub max_score: f64,
    pub analysis_id: Option<Uuid>,
    pub analysis_completed_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Disposition Models
// ============================================================================

/// Request to create or update a disposition.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateDispositionRequest {
    pub status: OutlierDispositionStatus,
    pub justification: Option<String>,
    /// Optional expiration for temporary exceptions.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response containing disposition details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DispositionResponse {
    pub id: Uuid,
    pub result_id: Uuid,
    pub user_id: Uuid,
    pub status: OutlierDispositionStatus,
    pub justification: Option<String>,
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Query parameters for listing dispositions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListDispositionsQuery {
    pub user_id: Option<Uuid>,
    pub status: Option<OutlierDispositionStatus>,
    pub reviewed_by: Option<Uuid>,
    pub include_expired: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Default for ListDispositionsQuery {
    fn default() -> Self {
        Self {
            user_id: None,
            status: None,
            reviewed_by: None,
            include_expired: Some(false),
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Summary of dispositions by status.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DispositionSummaryResponse {
    pub new_count: i64,
    pub legitimate_count: i64,
    pub requires_remediation_count: i64,
    pub under_investigation_count: i64,
    pub remediated_count: i64,
}

// ============================================================================
// Alert Models
// ============================================================================

/// Response containing alert details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AlertResponse {
    pub id: Uuid,
    pub analysis_id: Uuid,
    pub user_id: Uuid,
    pub alert_type: OutlierAlertType,
    pub severity: OutlierAlertSeverity,
    pub score: f64,
    pub classification: OutlierClassification,
    pub is_read: bool,
    pub is_dismissed: bool,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for listing alerts.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListAlertsQuery {
    pub user_id: Option<Uuid>,
    pub analysis_id: Option<Uuid>,
    pub alert_type: Option<OutlierAlertType>,
    pub severity: Option<OutlierAlertSeverity>,
    pub is_read: Option<bool>,
    pub is_dismissed: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Default for ListAlertsQuery {
    fn default() -> Self {
        Self {
            user_id: None,
            analysis_id: None,
            alert_type: None,
            severity: None,
            is_read: None,
            is_dismissed: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Summary of alerts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AlertSummaryResponse {
    pub total_count: i64,
    pub unread_count: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
}

// ============================================================================
// Report Models
// ============================================================================

/// Request to generate an outlier report.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GenerateOutlierReportRequest {
    /// Start date for the report period.
    pub start_date: DateTime<Utc>,
    /// End date for the report period.
    pub end_date: DateTime<Utc>,
    /// Whether to include trends over time.
    #[serde(default)]
    pub include_trends: bool,
    /// Whether to include peer group breakdown.
    #[serde(default)]
    pub include_peer_breakdown: bool,
}

/// Outlier trend data point.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OutlierTrendPoint {
    pub date: DateTime<Utc>,
    pub analysis_id: Uuid,
    pub outlier_count: i64,
    pub total_users: i64,
    pub avg_score: f64,
}

/// Peer group outlier breakdown.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerGroupBreakdown {
    pub peer_group_id: Uuid,
    pub peer_group_name: String,
    pub outlier_count: i64,
    pub member_count: i64,
    pub avg_deviation: f64,
}

/// Outlier report response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OutlierReportResponse {
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
    pub total_analyses: i64,
    pub total_users_analyzed: i64,
    pub total_outliers_detected: i64,
    pub average_outlier_rate: f64,
    pub trends: Option<Vec<OutlierTrendPoint>>,
    pub peer_group_breakdown: Option<Vec<PeerGroupBreakdown>>,
    pub generated_at: DateTime<Utc>,
}

// ============================================================================
// User History Models
// ============================================================================

/// User outlier history response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserOutlierHistoryResponse {
    pub user_id: Uuid,
    pub results: Vec<OutlierResultResponse>,
    pub current_disposition: Option<DispositionResponse>,
}

// ============================================================================
// Paginated Response
// ============================================================================

/// Generic paginated response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[aliases(
    PaginatedOutlierAnalysisResponse = PaginatedResponse<OutlierAnalysisResponse>,
    PaginatedOutlierResultResponse = PaginatedResponse<OutlierResultResponse>,
    PaginatedDispositionResponse = PaginatedResponse<DispositionResponse>,
    PaginatedAlertResponse = PaginatedResponse<AlertResponse>,
    PaginatedBatchSimulationResponse = PaginatedResponse<BatchSimulationResponse>,
    PaginatedBatchSimulationResultResponse = PaginatedResponse<BatchSimulationResultResponse>,
    PaginatedPolicySimulationResponse = PaginatedResponse<PolicySimulationResponse>,
    PaginatedPolicySimulationResultResponse = PaginatedResponse<PolicySimulationResultResponse>,
    PaginatedSimulationComparisonResponse = PaginatedResponse<SimulationComparisonResponse>,
)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

impl<T> PaginatedResponse<T> {
    #[must_use]
    pub fn new(items: Vec<T>, total: i64, limit: i64, offset: i64) -> Self {
        Self {
            items,
            total,
            limit,
            offset,
        }
    }
}

// ============================================================================
// Score Details (for factor explanations)
// ============================================================================

/// Detailed factor score with explanation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DetailedFactorScore {
    pub factor_name: String,
    pub raw_value: f64,
    pub weight: f64,
    pub contribution: f64,
    pub details: String,
    /// How this compares to peers.
    pub peer_average: Option<f64>,
    pub peer_std_dev: Option<f64>,
    pub z_score: Option<f64>,
}

impl From<(&str, &FactorScore)> for DetailedFactorScore {
    fn from((name, score): (&str, &FactorScore)) -> Self {
        Self {
            factor_name: name.to_string(),
            raw_value: score.raw_value,
            weight: score.weight,
            contribution: score.contribution,
            details: score.details.clone(),
            peer_average: None,
            peer_std_dev: None,
            z_score: None,
        }
    }
}
