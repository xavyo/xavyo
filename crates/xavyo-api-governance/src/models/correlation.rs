//! Request and response models for Correlation Engine endpoints (F067).
//!
//! The correlation engine matches imported accounts from connected target systems
//! to identities in the IDP, using configurable rules, scoring thresholds, and
//! manual review workflows.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

// ============================================================================
// Correlation Rule Models (US1, US6)
// ============================================================================

/// Request to create a new correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateCorrelationRuleRequest {
    /// Display name for the rule (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Source attribute to match against (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Source attribute must be between 1 and 255 characters"
    ))]
    pub source_attribute: String,

    /// Target attribute to match against (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Target attribute must be between 1 and 255 characters"
    ))]
    pub target_attribute: String,

    /// Type of matching to perform (e.g., "exact", "fuzzy", "expression").
    pub match_type: String,

    /// Matching algorithm to use (e.g., "levenshtein", "`jaro_winkler`").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,

    /// Minimum similarity threshold for fuzzy matching (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,

    /// Weight of this rule in the aggregate confidence score.
    pub weight: f64,

    /// Custom matching expression (for "expression" match type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,

    /// Evaluation tier for multi-pass correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<i32>,

    /// Whether a match on this rule definitively confirms identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_definitive: Option<bool>,

    /// Whether to normalize attribute values before comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalize: Option<bool>,

    /// Priority for rule evaluation order (lower = higher priority).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
}

/// Request to update an existing correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateCorrelationRuleRequest {
    /// Updated display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated source attribute.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Source attribute must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_attribute: Option<String>,

    /// Updated target attribute.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Target attribute must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_attribute: Option<String>,

    /// Updated match type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,

    /// Updated matching algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,

    /// Updated similarity threshold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,

    /// Updated weight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,

    /// Updated custom expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,

    /// Updated evaluation tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<i32>,

    /// Updated definitive match flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_definitive: Option<bool>,

    /// Updated normalization flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalize: Option<bool>,

    /// Updated active status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,

    /// Updated priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
}

/// Correlation rule response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationRuleResponse {
    /// Unique rule identifier.
    pub id: Uuid,

    /// Tenant that owns this rule.
    pub tenant_id: Uuid,

    /// Connector this rule is scoped to (null for global rules).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<Uuid>,

    /// Display name for the rule.
    pub name: String,

    /// Source attribute to match against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_attribute: Option<String>,

    /// Target attribute to match against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_attribute: Option<String>,

    /// Type of matching performed.
    pub match_type: String,

    /// Matching algorithm used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,

    /// Similarity threshold for fuzzy matching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,

    /// Weight in aggregate confidence score.
    pub weight: f64,

    /// Custom matching expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,

    /// Evaluation tier for multi-pass correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<i32>,

    /// Whether a match definitively confirms identity.
    pub is_definitive: bool,

    /// Whether attribute values are normalized before comparison.
    pub normalize: bool,

    /// Whether the rule is active.
    pub is_active: bool,

    /// Evaluation priority (lower = higher priority).
    pub priority: i32,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Paginated list of correlation rules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationRuleListResponse {
    /// List of correlation rules.
    pub items: Vec<CorrelationRuleResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for the query.
    pub limit: i64,

    /// Offset used for the query.
    pub offset: i64,
}

/// Query parameters for listing correlation rules.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListCorrelationRulesQuery {
    /// Filter by match type.
    pub match_type: Option<String>,

    /// Filter by active status.
    pub is_active: Option<bool>,

    /// Filter by evaluation tier.
    pub tier: Option<i32>,

    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

/// Request to validate a custom correlation expression.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ValidateExpressionRequest {
    /// The expression to validate.
    pub expression: String,

    /// Optional test input data for expression evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_input: Option<serde_json::Value>,
}

/// Response from expression validation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidateExpressionResponse {
    /// Whether the expression is syntactically valid.
    pub valid: bool,

    /// Result of evaluating the expression against test input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,

    /// Error message if the expression is invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// Correlation Threshold Models (US1)
// ============================================================================

/// Request to create or update correlation thresholds for a connector.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpsertCorrelationThresholdRequest {
    /// Confidence score above which matches are auto-confirmed (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_confirm_threshold: Option<f64>,

    /// Confidence score above which matches go to manual review (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manual_review_threshold: Option<f64>,

    /// Whether tuning mode is enabled (logs decisions without acting).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tuning_mode: Option<bool>,

    /// Whether to include deactivated identities in matching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_deactivated: Option<bool>,

    /// Number of accounts to process per batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<i32>,
}

/// Correlation threshold response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationThresholdResponse {
    /// Unique threshold configuration identifier.
    pub id: Uuid,

    /// Connector these thresholds apply to.
    pub connector_id: Uuid,

    /// Confidence score above which matches are auto-confirmed.
    pub auto_confirm_threshold: f64,

    /// Confidence score above which matches go to manual review.
    pub manual_review_threshold: f64,

    /// Whether tuning mode is enabled.
    pub tuning_mode: bool,

    /// Whether deactivated identities are included in matching.
    pub include_deactivated: bool,

    /// Number of accounts processed per batch.
    pub batch_size: i32,

    /// When the threshold configuration was created.
    pub created_at: DateTime<Utc>,

    /// When the threshold configuration was last updated.
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// Correlation Case Models (US3)
// ============================================================================

/// Summary response for a correlation case requiring manual review.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationCaseSummaryResponse {
    /// Unique case identifier.
    pub id: Uuid,

    /// Connector the account belongs to.
    pub connector_id: Uuid,

    /// Display name of the connector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,

    /// Identifier of the unmatched account.
    pub account_identifier: String,

    /// Current status of the case (e.g., "pending", "confirmed", "rejected").
    pub status: String,

    /// What triggered the case (e.g., "import", "reconciliation", "manual").
    pub trigger_type: String,

    /// Highest confidence score among candidates.
    pub highest_confidence: f64,

    /// Number of identity candidates.
    pub candidate_count: i32,

    /// User assigned to review this case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<Uuid>,

    /// When the case was created.
    pub created_at: DateTime<Utc>,
}

/// Detailed response for a correlation case including candidates.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationCaseDetailResponse {
    /// Unique case identifier.
    pub id: Uuid,

    /// Connector the account belongs to.
    pub connector_id: Uuid,

    /// Display name of the connector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,

    /// Identifier of the unmatched account.
    pub account_identifier: String,

    /// Linked account identifier (if resolved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<Uuid>,

    /// Current status of the case.
    pub status: String,

    /// What triggered the case.
    pub trigger_type: String,

    /// Highest confidence score among candidates.
    pub highest_confidence: f64,

    /// Number of identity candidates.
    pub candidate_count: i32,

    /// User assigned to review this case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<Uuid>,

    /// Attributes of the account being correlated.
    pub account_attributes: serde_json::Value,

    /// List of identity candidates with scoring details.
    pub candidates: Vec<CorrelationCandidateDetailResponse>,

    /// User who resolved the case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<Uuid>,

    /// When the case was resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,

    /// Reason provided for resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_reason: Option<String>,

    /// Snapshot of the rules used during correlation.
    pub rules_snapshot: serde_json::Value,

    /// When the case was created.
    pub created_at: DateTime<Utc>,

    /// When the case was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Detailed response for a correlation candidate.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationCandidateDetailResponse {
    /// Unique candidate identifier.
    pub id: Uuid,

    /// Identity this candidate refers to.
    pub identity_id: Uuid,

    /// Display name of the candidate identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_display_name: Option<String>,

    /// Attributes of the candidate identity.
    pub identity_attributes: serde_json::Value,

    /// Aggregate confidence score across all rules.
    pub aggregate_confidence: f64,

    /// Breakdown of scores per matching attribute/rule.
    pub per_attribute_scores: serde_json::Value,

    /// Whether the candidate identity is deactivated.
    pub is_deactivated: bool,

    /// Whether this candidate was flagged as a definitive match.
    pub is_definitive_match: bool,
}

/// Request to confirm a correlation case with a specific candidate.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ConfirmCaseRequest {
    /// The candidate identity to confirm as the match.
    pub candidate_id: Uuid,

    /// Optional reason for the confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request to reject all candidates for a correlation case.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RejectCaseRequest {
    /// Optional reason for the rejection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request to create a new identity from an unmatched correlation case.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateIdentityFromCaseRequest {
    /// Optional reason for creating a new identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request to reassign a correlation case to a different reviewer.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ReassignCaseRequest {
    /// The user to assign the case to.
    pub assigned_to: Uuid,

    /// Optional reason for the reassignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Query parameters for listing correlation cases.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListCorrelationCasesQuery {
    /// Filter by case status.
    pub status: Option<String>,

    /// Filter by connector.
    pub connector_id: Option<Uuid>,

    /// Filter by assigned reviewer.
    pub assigned_to: Option<Uuid>,

    /// Filter by trigger type.
    pub trigger_type: Option<String>,

    /// Filter cases created on or after this date.
    pub start_date: Option<DateTime<Utc>>,

    /// Filter cases created on or before this date.
    pub end_date: Option<DateTime<Utc>>,

    /// Field to sort by (e.g., "`created_at`", "`highest_confidence`").
    pub sort_by: Option<String>,

    /// Sort order ("asc" or "desc").
    pub sort_order: Option<String>,

    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

// ============================================================================
// Correlation Engine Models (US2, US4)
// ============================================================================

/// Request to trigger correlation for a connector.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct TriggerCorrelationRequest {
    /// Optional list of specific account IDs to evaluate.
    /// If omitted, all uncorrelated accounts for the connector are evaluated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_ids: Option<Vec<Uuid>>,
}

/// Response after triggering a correlation job.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TriggerCorrelationResponse {
    /// Unique job identifier for tracking progress.
    pub job_id: Uuid,

    /// Number of accounts that will be evaluated.
    pub accounts_to_evaluate: i64,

    /// Initial job status.
    pub status: String,
}

/// Response containing correlation job status and progress.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationJobStatusResponse {
    /// Unique job identifier.
    pub job_id: Uuid,

    /// Current job status (e.g., "running", "completed", "failed").
    pub status: String,

    /// Total number of accounts to evaluate.
    pub total_accounts: i64,

    /// Number of accounts processed so far.
    pub processed_accounts: i64,

    /// Number of accounts auto-confirmed.
    pub auto_confirmed: i64,

    /// Number of accounts queued for manual review.
    pub queued_for_review: i64,

    /// Number of accounts with no match found.
    pub no_match: i64,

    /// Number of accounts that encountered errors.
    pub errors: i64,

    /// When the job started.
    pub started_at: DateTime<Utc>,

    /// When the job completed (if finished).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Correlation Audit Models (US5)
// ============================================================================

/// Audit event response for correlation actions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationAuditEventResponse {
    /// Unique audit event identifier.
    pub id: Uuid,

    /// Connector involved in the correlation.
    pub connector_id: Uuid,

    /// Account involved (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<Uuid>,

    /// Correlation case involved (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<Uuid>,

    /// Identity involved (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<Uuid>,

    /// Type of event (e.g., "`auto_confirm`", "`manual_confirm`", "reject", "`create_identity`").
    pub event_type: String,

    /// Outcome of the event (e.g., "success", "failure").
    pub outcome: String,

    /// Confidence score at the time of the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f64>,

    /// Number of candidates evaluated.
    pub candidate_count: i32,

    /// Summary of candidate details at the time of the event.
    pub candidates_summary: serde_json::Value,

    /// Snapshot of the rules used during correlation.
    pub rules_snapshot: serde_json::Value,

    /// Snapshot of the thresholds used during correlation.
    pub thresholds_snapshot: serde_json::Value,

    /// Type of actor (e.g., "system", "user").
    pub actor_type: String,

    /// ID of the actor who performed the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// Reason provided for the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// When the event occurred.
    pub created_at: DateTime<Utc>,
}

/// Paginated list of correlation audit events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationAuditListResponse {
    /// List of audit events.
    pub items: Vec<CorrelationAuditEventResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for the query.
    pub limit: i64,

    /// Offset used for the query.
    pub offset: i64,
}

/// Query parameters for listing correlation audit events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListCorrelationAuditQuery {
    /// Filter by connector.
    pub connector_id: Option<Uuid>,

    /// Filter by event type.
    pub event_type: Option<String>,

    /// Filter by outcome.
    pub outcome: Option<String>,

    /// Filter events on or after this date.
    pub start_date: Option<DateTime<Utc>>,

    /// Filter events on or before this date.
    pub end_date: Option<DateTime<Utc>>,

    /// Filter by actor.
    pub actor_id: Option<Uuid>,

    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

// ============================================================================
// Correlation Statistics Models (US7)
// ============================================================================

/// Response containing correlation statistics for a connector.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationStatisticsResponse {
    /// Connector the statistics are for.
    pub connector_id: Uuid,

    /// Start of the statistics period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_start: Option<DateTime<Utc>>,

    /// End of the statistics period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_end: Option<DateTime<Utc>>,

    /// Total accounts evaluated in the period.
    pub total_evaluated: i64,

    /// Number of accounts auto-confirmed.
    pub auto_confirmed_count: i64,

    /// Percentage of accounts auto-confirmed.
    pub auto_confirmed_percentage: f64,

    /// Number of accounts sent to manual review.
    pub manual_review_count: i64,

    /// Percentage of accounts sent to manual review.
    pub manual_review_percentage: f64,

    /// Number of accounts with no match.
    pub no_match_count: i64,

    /// Percentage of accounts with no match.
    pub no_match_percentage: f64,

    /// Average confidence score across all evaluations.
    pub average_confidence: f64,

    /// Current depth of the manual review queue.
    pub review_queue_depth: i64,

    /// Optimization suggestions based on the statistics.
    pub suggestions: Vec<String>,
}

/// Response containing correlation trend data over time.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CorrelationTrendsResponse {
    /// Connector the trends are for.
    pub connector_id: Uuid,

    /// Start of the trend period.
    pub period_start: DateTime<Utc>,

    /// End of the trend period.
    pub period_end: DateTime<Utc>,

    /// Daily trend data points.
    pub daily_trends: Vec<DailyTrendData>,

    /// Optimization suggestions based on the trends.
    pub suggestions: Vec<String>,
}

/// A single day's correlation trend data.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DailyTrendData {
    /// Date in ISO 8601 format (YYYY-MM-DD).
    pub date: String,

    /// Total accounts evaluated on this day.
    pub total_evaluated: i64,

    /// Number of accounts auto-confirmed.
    pub auto_confirmed: i64,

    /// Number of accounts sent to manual review.
    pub manual_review: i64,

    /// Number of accounts with no match.
    pub no_match: i64,

    /// Average confidence score for the day.
    pub average_confidence: f64,
}

/// Query parameters for correlation statistics.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListCorrelationStatsQuery {
    /// Start of the statistics period.
    pub start_date: Option<DateTime<Utc>>,

    /// End of the statistics period.
    pub end_date: Option<DateTime<Utc>>,
}

/// Query parameters for correlation trends.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListCorrelationTrendsQuery {
    /// Start of the trend period (required).
    pub start_date: DateTime<Utc>,

    /// End of the trend period (required).
    pub end_date: DateTime<Utc>,
}
