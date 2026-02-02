//! Request/response DTOs for authorization policies (F083).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_db::models::AuthorizationPolicy;

/// Request to create a new authorization policy.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreatePolicyRequest {
    /// Human-readable policy name.
    pub name: String,

    /// Optional policy description.
    pub description: Option<String>,

    /// Policy effect: "allow" or "deny".
    pub effect: String,

    /// Evaluation priority (lower = higher priority). Default: 100.
    pub priority: Option<i32>,

    /// Optional resource type filter (None = match all).
    pub resource_type: Option<String>,

    /// Optional action filter (None = match all).
    pub action: Option<String>,

    /// Optional conditions to attach to this policy (AND-combined).
    pub conditions: Option<Vec<CreateConditionRequest>>,
}

/// Request to create a condition for a policy.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateConditionRequest {
    /// Condition type: "time_window", "user_attribute", or "entitlement_check".
    pub condition_type: String,

    /// Attribute path for user_attribute conditions (e.g., "department").
    pub attribute_path: Option<String>,

    /// Comparison operator (e.g., "equals", "not_equals", "contains", "in_list").
    pub operator: Option<String>,

    /// Condition value (type depends on condition_type).
    pub value: serde_json::Value,
}

/// Request to update an authorization policy.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdatePolicyRequest {
    /// Updated policy name.
    pub name: Option<String>,

    /// Updated description.
    pub description: Option<String>,

    /// Updated effect: "allow" or "deny".
    pub effect: Option<String>,

    /// Updated priority.
    pub priority: Option<i32>,

    /// Updated status: "active" or "inactive".
    pub status: Option<String>,

    /// Updated resource type filter.
    pub resource_type: Option<String>,

    /// Updated action filter.
    pub action: Option<String>,
}

/// Response for a single authorization policy.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Policy name.
    pub name: String,

    /// Policy description.
    pub description: Option<String>,

    /// Policy effect: "allow" or "deny".
    pub effect: String,

    /// Evaluation priority (lower = higher priority).
    pub priority: i32,

    /// Policy status: "active", "inactive".
    pub status: String,

    /// Optional resource type filter.
    pub resource_type: Option<String>,

    /// Optional action filter.
    pub action: Option<String>,

    /// Conditions attached to this policy.
    pub conditions: Vec<ConditionResponse>,

    /// Who created this policy.
    pub created_by: Option<Uuid>,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Response for a single policy condition.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConditionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Condition type.
    pub condition_type: String,

    /// Attribute path for user_attribute conditions.
    pub attribute_path: Option<String>,

    /// Comparison operator.
    pub operator: Option<String>,

    /// Condition value.
    pub value: serde_json::Value,

    /// When the condition was created.
    pub created_at: DateTime<Utc>,
}

/// Response for a paginated list of policies.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyListResponse {
    /// The list of policies.
    pub items: Vec<PolicyResponse>,

    /// Total number of policies matching the filters.
    pub total: i64,

    /// Page size.
    pub limit: i64,

    /// Page offset.
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

fn default_offset() -> i64 {
    0
}

/// Query parameters for listing policies.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListPoliciesQuery {
    /// Filter by status ("active", "inactive").
    pub status: Option<String>,

    /// Filter by effect ("allow", "deny").
    pub effect: Option<String>,

    /// Maximum number of results (default: 50, max: 100).
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination (default: 0).
    #[serde(default = "default_offset")]
    pub offset: i64,
}

impl PolicyResponse {
    /// Create a PolicyResponse from a DB policy and its conditions.
    pub fn from_policy_and_conditions(
        policy: AuthorizationPolicy,
        conditions: Vec<xavyo_db::models::PolicyConditionRecord>,
    ) -> Self {
        Self {
            id: policy.id,
            tenant_id: policy.tenant_id,
            name: policy.name,
            description: policy.description,
            effect: policy.effect,
            priority: policy.priority,
            status: policy.status,
            resource_type: policy.resource_type,
            action: policy.action,
            conditions: conditions
                .into_iter()
                .map(ConditionResponse::from)
                .collect(),
            created_by: policy.created_by,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        }
    }
}

impl From<xavyo_db::models::PolicyConditionRecord> for ConditionResponse {
    fn from(c: xavyo_db::models::PolicyConditionRecord) -> Self {
        Self {
            id: c.id,
            condition_type: c.condition_type,
            attribute_path: c.attribute_path,
            operator: c.operator,
            value: c.value,
            created_at: c.created_at,
        }
    }
}
