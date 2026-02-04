//! Request and response models for birthright policy endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    BirthrightPolicyStatus, ConditionOperator, EvaluationMode, GovBirthrightPolicy, PolicyCondition,
};

// ============================================================================
// Policy Condition Models
// ============================================================================

/// Request model for a policy condition.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct PolicyConditionRequest {
    /// Attribute name to match (e.g., "department", "location", "role").
    #[validate(length(
        min = 1,
        max = 100,
        message = "Attribute must be between 1 and 100 characters"
    ))]
    pub attribute: String,

    /// Operator for comparison.
    pub operator: ConditionOperator,

    /// Value to compare against.
    /// For "in" and "`not_in`" operators, this should be a JSON array.
    pub value: serde_json::Value,
}

impl From<PolicyConditionRequest> for PolicyCondition {
    fn from(req: PolicyConditionRequest) -> Self {
        Self {
            attribute: req.attribute,
            operator: req.operator.as_str().to_string(),
            value: req.value,
        }
    }
}

/// Response model for a policy condition.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyConditionResponse {
    /// Attribute name.
    pub attribute: String,

    /// Operator for comparison.
    pub operator: ConditionOperator,

    /// Value to compare against.
    pub value: serde_json::Value,
}

impl From<PolicyCondition> for PolicyConditionResponse {
    fn from(condition: PolicyCondition) -> Self {
        let operator =
            ConditionOperator::parse(&condition.operator).unwrap_or(ConditionOperator::Equals);
        Self {
            attribute: condition.attribute,
            operator,
            value: condition.value,
        }
    }
}

// ============================================================================
// Policy Request Models
// ============================================================================

/// Request to create a new birthright policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateBirthrightPolicyRequest {
    /// Policy display name (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Policy description.
    pub description: Option<String>,

    /// Priority for evaluation (higher = evaluated first).
    pub priority: i32,

    /// Conditions that must ALL match for policy to apply (AND logic).
    #[validate(length(min = 1, message = "At least one condition is required"))]
    pub conditions: Vec<PolicyConditionRequest>,

    /// Entitlement IDs to grant when conditions match.
    #[validate(length(min = 1, message = "At least one entitlement is required"))]
    pub entitlement_ids: Vec<Uuid>,

    /// Evaluation mode: `first_match` (stop at first match) or `all_match` (apply all matches).
    /// Default: `all_match`.
    #[serde(default)]
    pub evaluation_mode: Option<EvaluationMode>,

    /// Grace period in days for revocation (when user no longer matches).
    /// 0 means immediate revocation.
    #[validate(range(
        min = 0,
        max = 365,
        message = "Grace period must be between 0 and 365 days"
    ))]
    pub grace_period_days: Option<i32>,
}

/// Request to update an existing birthright policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateBirthrightPolicyRequest {
    /// Policy display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Policy description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Priority for evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,

    /// Conditions that must ALL match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<PolicyConditionRequest>>,

    /// Entitlement IDs to grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_ids: Option<Vec<Uuid>>,

    /// Evaluation mode: `first_match` or `all_match`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_mode: Option<EvaluationMode>,

    /// Grace period in days.
    #[validate(range(
        min = 0,
        max = 365,
        message = "Grace period must be between 0 and 365 days"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_days: Option<i32>,
}

/// Request to simulate a policy against user attributes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulatePolicyRequest {
    /// User attributes to test against (e.g., {"department": "Engineering", "location": "US"}).
    pub attributes: serde_json::Value,
}

// ============================================================================
// Policy Query Models
// ============================================================================

/// Query parameters for listing birthright policies.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListBirthrightPoliciesQuery {
    /// Filter by status.
    pub status: Option<BirthrightPolicyStatus>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListBirthrightPoliciesQuery {
    fn default() -> Self {
        Self {
            status: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

// ============================================================================
// Policy Response Models
// ============================================================================

/// Birthright policy response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BirthrightPolicyResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Policy display name.
    pub name: String,

    /// Policy description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Priority for evaluation.
    pub priority: i32,

    /// Conditions that must match.
    pub conditions: Vec<PolicyConditionResponse>,

    /// Entitlement IDs to grant.
    pub entitlement_ids: Vec<Uuid>,

    /// Policy status.
    pub status: BirthrightPolicyStatus,

    /// Evaluation mode (`first_match` or `all_match`).
    pub evaluation_mode: EvaluationMode,

    /// Grace period in days for revocation.
    pub grace_period_days: i32,

    /// Admin who created the policy.
    pub created_by: Uuid,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<GovBirthrightPolicy> for BirthrightPolicyResponse {
    fn from(policy: GovBirthrightPolicy) -> Self {
        let conditions: Vec<PolicyConditionResponse> = policy
            .parse_conditions()
            .into_iter()
            .map(PolicyConditionResponse::from)
            .collect();

        Self {
            id: policy.id,
            tenant_id: policy.tenant_id,
            name: policy.name,
            description: policy.description,
            priority: policy.priority,
            conditions,
            entitlement_ids: policy.entitlement_ids,
            status: policy.status,
            evaluation_mode: policy.evaluation_mode,
            grace_period_days: policy.grace_period_days,
            created_by: policy.created_by,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        }
    }
}

/// Paginated list of birthright policies.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BirthrightPolicyListResponse {
    /// List of policies.
    pub items: Vec<BirthrightPolicyResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Page number.
    pub page: i64,

    /// Page size.
    pub page_size: i64,
}

/// Result of policy simulation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulatePolicyResponse {
    /// Whether the policy matches the provided attributes.
    pub matches: bool,

    /// Details of condition evaluation.
    pub condition_results: Vec<ConditionEvaluationResult>,
}

/// Result of evaluating a single condition.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConditionEvaluationResult {
    /// Attribute name.
    pub attribute: String,

    /// Operator used.
    pub operator: ConditionOperator,

    /// Expected value.
    pub expected: serde_json::Value,

    /// Actual value from attributes.
    pub actual: Option<serde_json::Value>,

    /// Whether this condition matched.
    pub matched: bool,
}

/// Result of simulating all policies against user attributes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulateAllPoliciesResponse {
    /// User attributes that were evaluated.
    pub attributes: serde_json::Value,

    /// Matching policies.
    pub matching_policies: Vec<MatchingPolicyResult>,

    /// Total entitlements that would be granted.
    pub total_entitlements: Vec<Uuid>,
}

/// Summary of a matching policy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MatchingPolicyResult {
    /// Policy ID.
    pub policy_id: Uuid,

    /// Policy name.
    pub policy_name: String,

    /// Policy priority.
    pub priority: i32,

    /// Entitlements this policy would grant.
    pub entitlements: Vec<Uuid>,
}

// ============================================================================
// Impact Analysis Models
// ============================================================================

/// Request for policy impact analysis.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImpactAnalysisRequest {
    /// Optional: Proposed changes to the policy to analyze.
    /// If not provided, analyzes the policy as-is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_conditions: Option<Vec<PolicyConditionRequest>>,

    /// Optional: Proposed entitlements to analyze.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_entitlement_ids: Option<Vec<Uuid>>,

    /// Maximum number of affected users to return in detail (default: 100).
    #[serde(default = "default_max_affected_users")]
    pub max_affected_users: i64,
}

fn default_max_affected_users() -> i64 {
    100
}

impl Default for ImpactAnalysisRequest {
    fn default() -> Self {
        Self {
            proposed_conditions: None,
            proposed_entitlement_ids: None,
            max_affected_users: default_max_affected_users(),
        }
    }
}

/// Response for policy impact analysis.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImpactAnalysisResponse {
    /// The policy being analyzed.
    pub policy_id: Uuid,

    /// Policy name.
    pub policy_name: String,

    /// Summary statistics.
    pub summary: ImpactSummary,

    /// Breakdown by department.
    pub by_department: Vec<DepartmentImpact>,

    /// Breakdown by location.
    pub by_location: Vec<LocationImpact>,

    /// Entitlement impact details.
    pub entitlement_impacts: Vec<EntitlementImpact>,

    /// Sample of affected users (limited by `max_affected_users`).
    pub affected_users: Vec<AffectedUser>,

    /// Whether the result was truncated due to `max_affected_users` limit.
    pub is_truncated: bool,
}

/// Summary of impact analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ImpactSummary {
    /// Total number of users that would match the policy.
    pub total_users_affected: i64,

    /// Number of users who would gain new entitlements.
    pub users_gaining_access: i64,

    /// Number of users who would lose entitlements (if analyzing changes).
    pub users_losing_access: i64,

    /// Number of users with no change.
    pub users_unchanged: i64,

    /// Total entitlements that would be granted.
    pub total_entitlements_granted: i64,
}

/// Impact breakdown by department.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DepartmentImpact {
    /// Department name.
    pub department: String,

    /// Number of users affected in this department.
    pub user_count: i64,

    /// Percentage of total affected users.
    pub percentage: f64,
}

/// Impact breakdown by location.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LocationImpact {
    /// Location name.
    pub location: String,

    /// Number of users affected in this location.
    pub user_count: i64,

    /// Percentage of total affected users.
    pub percentage: f64,
}

/// Impact on a specific entitlement.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EntitlementImpact {
    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Entitlement name (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_name: Option<String>,

    /// Number of users who would receive this entitlement.
    pub users_gaining: i64,

    /// Number of users who already have this entitlement.
    pub users_already_have: i64,
}

/// Details of an affected user.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AffectedUser {
    /// User ID.
    pub user_id: Uuid,

    /// User email (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// User's department.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,

    /// User's location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    /// Impact type for this user.
    pub impact_type: UserImpactType,

    /// Entitlements this user would gain.
    pub entitlements_gaining: Vec<Uuid>,

    /// Entitlements this user would lose (if analyzing changes).
    pub entitlements_losing: Vec<Uuid>,
}

/// Type of impact on a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UserImpactType {
    /// User would gain new entitlements.
    Gaining,
    /// User would lose entitlements.
    Losing,
    /// User's access would remain unchanged.
    Unchanged,
    /// User would both gain and lose entitlements.
    Mixed,
}
