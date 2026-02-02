//! Request and response models for SoD rule endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovSodRule, GovSodRuleStatus, GovSodSeverity};

/// Request to create a new SoD rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateSodRuleRequest {
    /// Display name for the rule.
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: String,

    /// Optional description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// First conflicting entitlement ID.
    pub first_entitlement_id: Uuid,

    /// Second conflicting entitlement ID.
    pub second_entitlement_id: Uuid,

    /// Severity level for violations.
    pub severity: GovSodSeverity,

    /// Business rationale for the rule.
    #[validate(length(
        max = 2000,
        message = "Business rationale must not exceed 2000 characters"
    ))]
    pub business_rationale: Option<String>,
}

/// Request to update an existing SoD rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateSodRuleRequest {
    /// Updated display name.
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: Option<String>,

    /// Updated description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Updated severity level.
    pub severity: Option<GovSodSeverity>,

    /// Updated business rationale.
    #[validate(length(
        max = 2000,
        message = "Business rationale must not exceed 2000 characters"
    ))]
    pub business_rationale: Option<String>,
}

/// Query parameters for listing SoD rules.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListSodRulesQuery {
    /// Filter by rule status.
    pub status: Option<GovSodRuleStatus>,

    /// Filter by severity level.
    pub severity: Option<GovSodSeverity>,

    /// Filter by entitlement (returns rules involving this entitlement).
    pub entitlement_id: Option<Uuid>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListSodRulesQuery {
    fn default() -> Self {
        Self {
            status: None,
            severity: None,
            entitlement_id: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// SoD rule response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodRuleResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// First conflicting entitlement ID.
    pub first_entitlement_id: Uuid,

    /// Second conflicting entitlement ID.
    pub second_entitlement_id: Uuid,

    /// Severity level.
    pub severity: GovSodSeverity,

    /// Rule status.
    pub status: GovSodRuleStatus,

    /// Business rationale.
    pub business_rationale: Option<String>,

    /// User who created the rule.
    pub created_by: Uuid,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovSodRule> for SodRuleResponse {
    fn from(rule: GovSodRule) -> Self {
        Self {
            id: rule.id,
            name: rule.name,
            description: rule.description,
            first_entitlement_id: rule.first_entitlement_id,
            second_entitlement_id: rule.second_entitlement_id,
            severity: rule.severity,
            status: rule.status,
            business_rationale: rule.business_rationale,
            created_by: rule.created_by,
            created_at: rule.created_at,
            updated_at: rule.updated_at,
        }
    }
}

/// Paginated list of SoD rules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodRuleListResponse {
    /// List of rules.
    pub items: Vec<SodRuleResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Request to check for SoD violations before assignment.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SodCheckRequest {
    /// User ID to check.
    pub user_id: Uuid,

    /// Entitlement ID being requested.
    pub entitlement_id: Uuid,
}

/// Result of an SoD check.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodCheckResponse {
    /// Whether the assignment would be allowed.
    pub allowed: bool,

    /// Violations that would be created (empty if allowed).
    pub violations: Vec<SodCheckViolation>,
}

/// A potential violation found during SoD check.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodCheckViolation {
    /// Rule that would be violated.
    pub rule_id: Uuid,

    /// Rule name.
    pub rule_name: String,

    /// Severity level.
    pub severity: GovSodSeverity,

    /// Conflicting entitlement the user already has.
    pub conflicting_entitlement_id: Uuid,

    /// Whether an active exemption exists.
    pub has_exemption: bool,

    /// Source of the conflicting entitlement (F088: includes inheritance info).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<EntitlementSourceInfo>,
}

/// Information about how an entitlement was obtained (F088).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntitlementSourceInfo {
    /// Direct user assignment.
    Direct,
    /// Inherited from group membership.
    Group {
        /// Group ID.
        group_id: Uuid,
        /// Group name.
        group_name: String,
    },
    /// Inherited from legacy string-based role.
    Role {
        /// Role name.
        role_name: String,
    },
    /// From governance role hierarchy (F088).
    GovRole {
        /// The role ID the user is assigned to.
        role_id: Uuid,
        /// The role name the user is assigned to.
        role_name: String,
        /// The source role ID that grants the entitlement (may be ancestor).
        source_role_id: Uuid,
        /// The source role name.
        source_role_name: String,
        /// Whether entitlement is inherited from an ancestor role.
        is_inherited: bool,
    },
}

/// Response for scanning a rule for violations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanRuleResponse {
    /// Rule that was scanned.
    pub rule_id: Uuid,

    /// Number of new violations detected.
    pub violations_detected: i64,

    /// Total active violations for this rule.
    pub total_active_violations: i64,
}
