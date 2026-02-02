//! Request and response models for risk score endpoints.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_db::{GovRiskScore, GovRiskScoreHistory, RiskLevel, RiskScoreTrend, TrendDirection};

/// Score breakdown per factor.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FactorBreakdown {
    /// Factor ID.
    pub factor_id: Uuid,

    /// Factor name.
    pub factor_name: String,

    /// Factor category (static/dynamic).
    pub category: String,

    /// Raw value from factor.
    pub raw_value: f64,

    /// Weight applied.
    pub weight: f64,

    /// Contribution to score.
    pub contribution: i32,
}

/// Peer comparison data.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerComparisonData {
    /// Peer group ID.
    pub group_id: Uuid,

    /// Peer group name.
    pub group_name: String,

    /// User's entitlement count.
    pub user_entitlement_count: i32,

    /// Group average entitlements.
    pub group_average: f64,

    /// Group standard deviation.
    pub group_stddev: f64,

    /// Deviation from mean (in standard deviations).
    pub deviation: f64,

    /// Whether user is an outlier.
    pub is_outlier: bool,
}

/// Risk score response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskScoreResponse {
    /// Score record ID.
    pub id: Uuid,

    /// User ID.
    pub user_id: Uuid,

    /// Total risk score (0-100).
    pub total_score: i32,

    /// Risk level classification.
    pub risk_level: RiskLevel,

    /// Score from static factors.
    pub static_score: i32,

    /// Score from dynamic factors.
    pub dynamic_score: i32,

    /// Per-factor breakdown.
    pub factor_breakdown: Vec<FactorBreakdown>,

    /// Peer comparison (if available).
    pub peer_comparison: Option<PeerComparisonData>,

    /// When the score was calculated.
    pub calculated_at: DateTime<Utc>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovRiskScore> for RiskScoreResponse {
    fn from(score: GovRiskScore) -> Self {
        let factor_breakdown: Vec<FactorBreakdown> =
            serde_json::from_value(score.factor_breakdown.clone()).unwrap_or_default();

        let peer_comparison: Option<PeerComparisonData> = score
            .peer_comparison
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        Self {
            id: score.id,
            user_id: score.user_id,
            total_score: score.total_score,
            risk_level: score.risk_level,
            static_score: score.static_score,
            dynamic_score: score.dynamic_score,
            factor_breakdown,
            peer_comparison,
            calculated_at: score.calculated_at,
            created_at: score.created_at,
            updated_at: score.updated_at,
        }
    }
}

/// Query parameters for listing risk scores.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListRiskScoresQuery {
    /// Filter by risk level.
    pub risk_level: Option<RiskLevel>,

    /// Filter by minimum score.
    #[param(minimum = 0, maximum = 100)]
    pub min_score: Option<i32>,

    /// Filter by maximum score.
    #[param(minimum = 0, maximum = 100)]
    pub max_score: Option<i32>,

    /// Sort order.
    pub sort_by: Option<RiskScoreSortOption>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

/// Sort options for risk scores.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskScoreSortOption {
    /// Sort by score descending (highest first).
    #[default]
    ScoreDesc,
    /// Sort by score ascending (lowest first).
    ScoreAsc,
    /// Sort by calculation time descending.
    CalculatedAtDesc,
    /// Sort by calculation time ascending.
    CalculatedAtAsc,
}

impl Default for ListRiskScoresQuery {
    fn default() -> Self {
        Self {
            risk_level: None,
            min_score: None,
            max_score: None,
            sort_by: Some(RiskScoreSortOption::ScoreDesc),
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of risk scores.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskScoreListResponse {
    /// List of scores.
    pub items: Vec<RiskScoreResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Risk score summary by level.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskScoreSummary {
    /// Count of users per risk level.
    pub by_level: Vec<LevelCount>,

    /// Total users with scores.
    pub total_users: i64,

    /// Average score.
    pub average_score: f64,
}

/// Count per risk level.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LevelCount {
    /// Risk level.
    pub level: RiskLevel,

    /// Count of users.
    pub count: i64,
}

/// Historical risk score entry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskScoreHistoryEntry {
    /// History record ID.
    pub id: Uuid,

    /// Score at snapshot.
    pub score: i32,

    /// Risk level at snapshot.
    pub risk_level: RiskLevel,

    /// Snapshot date.
    pub snapshot_date: NaiveDate,

    /// Record creation time.
    pub created_at: DateTime<Utc>,
}

impl From<GovRiskScoreHistory> for RiskScoreHistoryEntry {
    fn from(h: GovRiskScoreHistory) -> Self {
        Self {
            id: h.id,
            score: h.score,
            risk_level: h.risk_level,
            snapshot_date: h.snapshot_date,
            created_at: h.created_at,
        }
    }
}

/// Query parameters for risk score history.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct RiskScoreHistoryQuery {
    /// Start date for history range.
    pub start_date: Option<NaiveDate>,

    /// End date for history range.
    pub end_date: Option<NaiveDate>,

    /// Maximum number of entries (default: 90).
    #[param(minimum = 1, maximum = 365)]
    pub limit: Option<i64>,
}

impl Default for RiskScoreHistoryQuery {
    fn default() -> Self {
        Self {
            start_date: None,
            end_date: None,
            limit: Some(90),
        }
    }
}

/// Risk score history response with trend.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskScoreHistoryResponse {
    /// User ID.
    pub user_id: Uuid,

    /// Current score.
    pub current_score: i32,

    /// Trend analysis.
    pub trend: RiskTrendResponse,

    /// Historical entries.
    pub history: Vec<RiskScoreHistoryEntry>,
}

/// Risk trend response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskTrendResponse {
    /// Score 30 days ago.
    pub score_30d_ago: Option<i32>,

    /// Score 60 days ago.
    pub score_60d_ago: Option<i32>,

    /// Score 90 days ago.
    pub score_90d_ago: Option<i32>,

    /// Change over 30 days.
    pub change_30d: Option<i32>,

    /// Change over 60 days.
    pub change_60d: Option<i32>,

    /// Change over 90 days.
    pub change_90d: Option<i32>,

    /// Overall trend direction.
    pub direction: TrendDirection,
}

impl From<RiskScoreTrend> for RiskTrendResponse {
    fn from(t: RiskScoreTrend) -> Self {
        Self {
            score_30d_ago: t.score_30d_ago,
            score_60d_ago: t.score_60d_ago,
            score_90d_ago: t.score_90d_ago,
            change_30d: t.change_30d,
            change_60d: t.change_60d,
            change_90d: t.change_90d,
            direction: t.direction,
        }
    }
}

/// Request to calculate risk score.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CalculateScoreRequest {
    /// Whether to include peer comparison.
    #[serde(default)]
    pub include_peer_comparison: bool,
}

/// Response for batch score calculation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchCalculateResponse {
    /// Number of scores calculated.
    pub calculated: i64,

    /// Number of errors encountered.
    pub errors: i64,

    /// Time taken in milliseconds.
    pub duration_ms: u64,
}

/// Enforcement action required based on risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementAction {
    /// No action required.
    None,
    /// Alert has been generated.
    Alert,
    /// MFA is required.
    RequireMfa,
    /// Access is blocked.
    Block,
}

/// Risk enforcement check response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskEnforcementResponse {
    /// User ID.
    pub user_id: Uuid,

    /// Current score.
    pub score: i32,

    /// Risk level.
    pub risk_level: RiskLevel,

    /// Required enforcement action.
    pub action: EnforcementAction,

    /// Threshold that triggered the action (if any).
    pub threshold_id: Option<Uuid>,

    /// Threshold name.
    pub threshold_name: Option<String>,
}

// --- Enforcement Policy types (F073) ---

/// Enforcement policy response for admin API.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EnforcementPolicyResponse {
    /// Policy ID (nil UUID if using default).
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Enforcement mode.
    pub enforcement_mode: String,

    /// Whether to fail-open when risk service is unavailable.
    pub fail_open: bool,

    /// Speed threshold for impossible travel (km/h).
    pub impossible_travel_speed_kmh: i32,

    /// Whether impossible travel detection is enabled.
    pub impossible_travel_enabled: bool,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<xavyo_db::GovRiskEnforcementPolicy> for EnforcementPolicyResponse {
    fn from(policy: xavyo_db::GovRiskEnforcementPolicy) -> Self {
        Self {
            id: policy.id,
            tenant_id: policy.tenant_id,
            enforcement_mode: format!("{:?}", policy.enforcement_mode).to_lowercase(),
            fail_open: policy.fail_open,
            impossible_travel_speed_kmh: policy.impossible_travel_speed_kmh,
            impossible_travel_enabled: policy.impossible_travel_enabled,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        }
    }
}

/// Request body for creating or updating an enforcement policy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpsertEnforcementPolicyRequest {
    /// Enforcement mode: "disabled", "monitor", or "enforce".
    pub enforcement_mode: Option<String>,

    /// Whether to fail-open when risk service is unavailable.
    pub fail_open: Option<bool>,

    /// Speed threshold for impossible travel detection (100-2000 km/h).
    pub impossible_travel_speed_kmh: Option<i32>,

    /// Whether impossible travel detection is enabled.
    pub impossible_travel_enabled: Option<bool>,
}
