//! API models for role mining and analytics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_db::{
    CandidatePromotionStatus, ConsolidationStatus, EntitlementUsage, MetricsTrendDirection,
    MiningJobParameters, MiningJobStatus, PrivilegeFlagStatus, ScenarioType, SimulationChanges,
    SimulationStatus,
};

// ============================================================================
// Mining Job Models
// ============================================================================

/// Response for a mining job.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MiningJobResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub status: MiningJobStatus,
    pub parameters: MiningJobParameters,
    pub progress_percent: i32,
    pub candidate_count: i32,
    pub excessive_privilege_count: i32,
    pub consolidation_suggestion_count: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a mining job.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateMiningJobRequest {
    pub name: String,
    #[serde(default)]
    pub parameters: Option<MiningJobParametersRequest>,
}

/// Mining job parameters (input version).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default)]
pub struct MiningJobParametersRequest {
    #[serde(default = "default_min_users")]
    pub min_users: i32,
    #[serde(default = "default_min_entitlements")]
    pub min_entitlements: i32,
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f64,
    #[serde(default = "default_true")]
    pub include_excessive_privilege: bool,
    #[serde(default = "default_true")]
    pub include_consolidation: bool,
    #[serde(default = "default_consolidation_threshold")]
    pub consolidation_threshold: f64,
    #[serde(default = "default_deviation_threshold")]
    pub deviation_threshold: f64,
    #[serde(default)]
    pub peer_group_attribute: Option<String>,
}

fn default_min_users() -> i32 {
    3
}
fn default_min_entitlements() -> i32 {
    2
}
fn default_confidence_threshold() -> f64 {
    0.6
}
fn default_true() -> bool {
    true
}
fn default_consolidation_threshold() -> f64 {
    70.0
}
fn default_deviation_threshold() -> f64 {
    50.0
}

/// Query parameters for listing mining jobs.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListMiningJobsQuery {
    pub status: Option<MiningJobStatus>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// List response for mining jobs.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MiningJobListResponse {
    pub items: Vec<MiningJobResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Role Candidate Models
// ============================================================================

/// Response for a role candidate.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleCandidateResponse {
    pub id: Uuid,
    pub job_id: Uuid,
    pub proposed_name: String,
    pub confidence_score: f64,
    pub member_count: i32,
    pub entitlement_ids: Vec<Uuid>,
    pub user_ids: Vec<Uuid>,
    pub promotion_status: CandidatePromotionStatus,
    pub promoted_role_id: Option<Uuid>,
    pub dismissed_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request to promote a candidate to a role.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PromoteCandidateRequest {
    pub role_name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Request to dismiss a candidate.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DismissCandidateRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

/// Query parameters for listing candidates.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListCandidatesQuery {
    pub status: Option<CandidatePromotionStatus>,
    pub min_confidence: Option<f64>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// List response for role candidates.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleCandidateListResponse {
    pub items: Vec<RoleCandidateResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Access Pattern Models
// ============================================================================

/// Response for an access pattern.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AccessPatternResponse {
    pub id: Uuid,
    pub job_id: Uuid,
    pub entitlement_ids: Vec<Uuid>,
    pub frequency: i32,
    pub user_count: i32,
    pub sample_user_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for listing access patterns.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListAccessPatternsQuery {
    pub min_frequency: Option<i32>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// List response for access patterns.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AccessPatternListResponse {
    pub items: Vec<AccessPatternResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Excessive Privilege Models
// ============================================================================

/// Response for an excessive privilege flag.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExcessivePrivilegeResponse {
    pub id: Uuid,
    pub job_id: Uuid,
    pub user_id: Uuid,
    pub peer_group_id: Option<Uuid>,
    pub deviation_percent: f64,
    pub excess_entitlements: Vec<Uuid>,
    pub peer_average: f64,
    pub user_count: i32,
    pub status: PrivilegeFlagStatus,
    pub notes: Option<String>,
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Request to review an excessive privilege flag.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReviewPrivilegeRequest {
    pub action: PrivilegeReviewAction,
    #[serde(default)]
    pub notes: Option<String>,
}

/// Review action for excessive privilege.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeReviewAction {
    Accept,
    Remediate,
}

/// Query parameters for listing excessive privileges.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListExcessivePrivilegesQuery {
    pub status: Option<PrivilegeFlagStatus>,
    pub user_id: Option<Uuid>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// List response for excessive privileges.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExcessivePrivilegeListResponse {
    pub items: Vec<ExcessivePrivilegeResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Consolidation Suggestion Models
// ============================================================================

/// Response for a consolidation suggestion.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConsolidationSuggestionResponse {
    pub id: Uuid,
    pub job_id: Uuid,
    pub role_a_id: Uuid,
    pub role_b_id: Uuid,
    pub overlap_percent: f64,
    pub shared_entitlements: Vec<Uuid>,
    pub unique_to_a: Vec<Uuid>,
    pub unique_to_b: Vec<Uuid>,
    pub status: ConsolidationStatus,
    pub dismissed_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request to dismiss a consolidation suggestion.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DismissConsolidationRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

/// Query parameters for listing consolidation suggestions.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListConsolidationSuggestionsQuery {
    pub status: Option<ConsolidationStatus>,
    pub min_overlap: Option<f64>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// List response for consolidation suggestions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConsolidationSuggestionListResponse {
    pub items: Vec<ConsolidationSuggestionResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Simulation Models
// ============================================================================

/// Response for a role simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub scenario_type: ScenarioType,
    pub target_role_id: Option<Uuid>,
    pub changes: SimulationChanges,
    pub status: SimulationStatus,
    pub affected_users: Vec<Uuid>,
    pub access_gained: serde_json::Value,
    pub access_lost: serde_json::Value,
    pub applied_by: Option<Uuid>,
    pub applied_at: Option<DateTime<Utc>>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Request to create a simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateSimulationRequest {
    pub name: String,
    pub scenario_type: ScenarioType,
    #[serde(default)]
    pub target_role_id: Option<Uuid>,
    pub changes: SimulationChanges,
}

/// Query parameters for listing simulations.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListSimulationsQuery {
    pub status: Option<SimulationStatus>,
    pub scenario_type: Option<ScenarioType>,
    pub target_role_id: Option<Uuid>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// List response for simulations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationListResponse {
    pub items: Vec<SimulationResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Metrics Models
// ============================================================================

/// Response for role metrics.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleMetricsResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub role_id: Uuid,
    pub utilization_rate: f64,
    pub coverage_rate: f64,
    pub user_count: i32,
    pub active_user_count: i32,
    pub entitlement_usage: Vec<EntitlementUsage>,
    pub trend_direction: MetricsTrendDirection,
    pub calculated_at: DateTime<Utc>,
}

/// Request to calculate metrics for roles.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CalculateMetricsRequest {
    #[serde(default)]
    pub role_ids: Option<Vec<Uuid>>,
}

/// Query parameters for listing role metrics.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListMetricsQuery {
    pub role_id: Option<Uuid>,
    pub trend_direction: Option<MetricsTrendDirection>,
    pub min_utilization: Option<f64>,
    pub max_utilization: Option<f64>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// List response for role metrics.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleMetricsListResponse {
    pub items: Vec<RoleMetricsResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn default_limit() -> i64 {
    50
}

// ============================================================================
// Conversions
// ============================================================================

impl From<xavyo_db::GovRoleMiningJob> for MiningJobResponse {
    fn from(j: xavyo_db::GovRoleMiningJob) -> Self {
        // Parse parameters before moving any fields
        let parameters = j.parse_parameters();
        Self {
            id: j.id,
            tenant_id: j.tenant_id,
            name: j.name,
            status: j.status,
            parameters,
            progress_percent: j.progress_percent,
            candidate_count: j.candidate_count,
            excessive_privilege_count: j.excessive_privilege_count,
            consolidation_suggestion_count: j.consolidation_suggestion_count,
            started_at: j.started_at,
            completed_at: j.completed_at,
            error_message: j.error_message,
            created_by: j.created_by,
            created_at: j.created_at,
            updated_at: j.updated_at,
        }
    }
}

impl From<xavyo_db::GovRoleCandidate> for RoleCandidateResponse {
    fn from(c: xavyo_db::GovRoleCandidate) -> Self {
        Self {
            id: c.id,
            job_id: c.job_id,
            proposed_name: c.proposed_name,
            confidence_score: c.confidence_score,
            member_count: c.member_count,
            entitlement_ids: c.entitlement_ids,
            user_ids: c.user_ids,
            promotion_status: c.promotion_status,
            promoted_role_id: c.promoted_role_id,
            dismissed_reason: c.dismissed_reason,
            created_at: c.created_at,
        }
    }
}

impl From<xavyo_db::GovAccessPattern> for AccessPatternResponse {
    fn from(p: xavyo_db::GovAccessPattern) -> Self {
        Self {
            id: p.id,
            job_id: p.job_id,
            entitlement_ids: p.entitlement_ids,
            frequency: p.frequency,
            user_count: p.user_count,
            sample_user_ids: p.sample_user_ids,
            created_at: p.created_at,
        }
    }
}

impl From<xavyo_db::GovExcessivePrivilege> for ExcessivePrivilegeResponse {
    fn from(e: xavyo_db::GovExcessivePrivilege) -> Self {
        Self {
            id: e.id,
            job_id: e.job_id,
            user_id: e.user_id,
            peer_group_id: e.peer_group_id,
            deviation_percent: e.deviation_percent,
            excess_entitlements: e.excess_entitlements,
            peer_average: e.peer_average,
            user_count: e.user_count,
            status: e.status,
            notes: e.notes,
            reviewed_by: e.reviewed_by,
            reviewed_at: e.reviewed_at,
            created_at: e.created_at,
        }
    }
}

impl From<xavyo_db::GovConsolidationSuggestion> for ConsolidationSuggestionResponse {
    fn from(s: xavyo_db::GovConsolidationSuggestion) -> Self {
        Self {
            id: s.id,
            job_id: s.job_id,
            role_a_id: s.role_a_id,
            role_b_id: s.role_b_id,
            overlap_percent: s.overlap_percent,
            shared_entitlements: s.shared_entitlements,
            unique_to_a: s.unique_to_a,
            unique_to_b: s.unique_to_b,
            status: s.status,
            dismissed_reason: s.dismissed_reason,
            created_at: s.created_at,
        }
    }
}

impl From<xavyo_db::GovRoleSimulation> for SimulationResponse {
    fn from(s: xavyo_db::GovRoleSimulation) -> Self {
        // Parse changes before moving any fields
        let changes = s.parse_changes();
        Self {
            id: s.id,
            tenant_id: s.tenant_id,
            name: s.name,
            scenario_type: s.scenario_type,
            target_role_id: s.target_role_id,
            changes,
            status: s.status,
            affected_users: s.affected_users,
            access_gained: s.access_gained,
            access_lost: s.access_lost,
            applied_by: s.applied_by,
            applied_at: s.applied_at,
            created_by: s.created_by,
            created_at: s.created_at,
        }
    }
}

impl From<xavyo_db::GovRoleMetrics> for RoleMetricsResponse {
    fn from(m: xavyo_db::GovRoleMetrics) -> Self {
        Self {
            id: m.id,
            tenant_id: m.tenant_id,
            role_id: m.role_id,
            utilization_rate: m.utilization_rate,
            coverage_rate: m.coverage_rate,
            user_count: m.user_count,
            active_user_count: m.active_user_count,
            entitlement_usage: m.parse_entitlement_usage(),
            trend_direction: m.trend_direction,
            calculated_at: m.calculated_at,
        }
    }
}

impl From<MiningJobParametersRequest> for MiningJobParameters {
    fn from(p: MiningJobParametersRequest) -> Self {
        Self {
            min_users: p.min_users,
            min_entitlements: p.min_entitlements,
            confidence_threshold: p.confidence_threshold,
            include_excessive_privilege: p.include_excessive_privilege,
            include_consolidation: p.include_consolidation,
            consolidation_threshold: p.consolidation_threshold,
            deviation_threshold: p.deviation_threshold,
            peer_group_attribute: p.peer_group_attribute,
        }
    }
}
