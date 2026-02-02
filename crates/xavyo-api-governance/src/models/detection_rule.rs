//! Request and response models for detection rule endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{DetectionRuleType, GovDetectionRule};

/// Detection rule response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DetectionRuleResponse {
    /// Rule ID.
    pub id: Uuid,

    /// Rule display name.
    pub name: String,

    /// Type of detection rule.
    pub rule_type: DetectionRuleType,

    /// Whether this rule is enabled.
    pub is_enabled: bool,

    /// Priority for rule execution (lower = higher priority).
    pub priority: i32,

    /// Rule-specific parameters.
    pub parameters: serde_json::Value,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovDetectionRule> for DetectionRuleResponse {
    fn from(rule: GovDetectionRule) -> Self {
        Self {
            id: rule.id,
            name: rule.name,
            rule_type: rule.rule_type,
            is_enabled: rule.is_enabled,
            priority: rule.priority,
            parameters: rule.parameters,
            description: rule.description,
            created_at: rule.created_at,
            updated_at: rule.updated_at,
        }
    }
}

/// Request to create a new detection rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateDetectionRuleRequest {
    /// Rule display name.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    /// Type of detection rule.
    pub rule_type: DetectionRuleType,

    /// Whether this rule should be enabled on creation.
    #[serde(default = "default_enabled")]
    pub is_enabled: bool,

    /// Priority for rule execution (lower = higher priority).
    #[validate(range(min = 1, message = "Priority must be at least 1"))]
    #[serde(default = "default_priority")]
    pub priority: i32,

    /// Rule-specific parameters.
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,

    /// Human-readable description.
    #[validate(length(max = 500, message = "Description must be at most 500 characters"))]
    #[serde(default)]
    pub description: Option<String>,
}

fn default_enabled() -> bool {
    true
}

fn default_priority() -> i32 {
    100
}

/// Request to update a detection rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateDetectionRuleRequest {
    /// New name for the rule.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Whether this rule is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_enabled: Option<bool>,

    /// Priority for rule execution.
    #[validate(range(min = 1, message = "Priority must be at least 1"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,

    /// Rule-specific parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,

    /// Human-readable description.
    #[validate(length(max = 500, message = "Description must be at most 500 characters"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Query parameters for listing detection rules.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListDetectionRulesQuery {
    /// Filter by rule type.
    pub rule_type: Option<DetectionRuleType>,

    /// Filter by enabled status.
    pub is_enabled: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListDetectionRulesQuery {
    fn default() -> Self {
        Self {
            rule_type: None,
            is_enabled: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of detection rules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DetectionRuleListResponse {
    /// List of rules.
    pub items: Vec<DetectionRuleResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Inactivity rule parameters.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InactivityRuleParameters {
    /// Days of inactivity before flagging as orphan.
    pub days_threshold: i32,
}

/// Custom rule parameters.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CustomRuleParameters {
    /// Expression defining the custom detection logic.
    pub expression: String,
}
