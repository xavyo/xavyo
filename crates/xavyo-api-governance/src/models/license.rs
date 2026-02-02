//! Request and response models for License Management endpoints (F065).
//!
//! License management tracks software license pools, assignments, entitlement
//! integrations, reclamation rules, and provides analytics for cost optimization.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::models::{
    GovLicenseAssignment, GovLicenseEntitlementLink, GovLicenseIncompatibility, GovLicensePool,
    GovLicenseReclamationRule, LicenseAssignmentSource, LicenseAssignmentStatus,
    LicenseBillingPeriod, LicenseExpirationPolicy, LicenseIncompatibilityWithDetails,
    LicensePoolStatus, LicenseReclamationTrigger, LicenseType,
};

// ============================================================================
// License Pool Models
// ============================================================================

/// Request to create a new license pool.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateLicensePoolRequest {
    /// Pool display name (e.g., "Microsoft 365 E3").
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Vendor name (e.g., "Microsoft").
    #[validate(length(
        min = 1,
        max = 255,
        message = "Vendor must be between 1 and 255 characters"
    ))]
    pub vendor: String,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Total number of licenses purchased.
    #[validate(range(min = 0, message = "Total capacity must be non-negative"))]
    pub total_capacity: i32,

    /// Cost per license unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_per_license: Option<Decimal>,

    /// ISO 4217 currency code (default: USD).
    #[validate(length(equal = 3, message = "Currency must be a 3-letter ISO code"))]
    #[serde(default = "default_currency")]
    pub currency: String,

    /// Billing period for cost tracking.
    pub billing_period: LicenseBillingPeriod,

    /// License type (named or concurrent).
    #[serde(default)]
    pub license_type: LicenseType,

    /// When the license expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,

    /// Policy to enforce when pool expires.
    #[serde(default)]
    pub expiration_policy: LicenseExpirationPolicy,

    /// Days before expiration to start sending alerts (default: 60).
    #[validate(range(min = 1, max = 365, message = "Warning days must be between 1 and 365"))]
    #[serde(default = "default_warning_days")]
    pub warning_days: i32,
}

fn default_currency() -> String {
    "USD".to_string()
}

fn default_warning_days() -> i32 {
    60
}

/// Request to update an existing license pool.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateLicensePoolRequest {
    /// Updated name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated vendor.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Vendor must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    /// Updated description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Updated total capacity.
    #[validate(range(min = 0, message = "Total capacity must be non-negative"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_capacity: Option<i32>,

    /// Updated cost per license.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_per_license: Option<Decimal>,

    /// Updated currency.
    #[validate(length(equal = 3, message = "Currency must be a 3-letter ISO code"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,

    /// Updated billing period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_period: Option<LicenseBillingPeriod>,

    /// Updated expiration date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,

    /// Updated expiration policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_policy: Option<LicenseExpirationPolicy>,

    /// Updated warning days.
    #[validate(range(min = 1, max = 365, message = "Warning days must be between 1 and 365"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_days: Option<i32>,
}

/// License pool response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicensePoolResponse {
    pub id: Uuid,
    pub name: String,
    pub vendor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub total_capacity: i32,
    pub allocated_count: i32,
    pub available_count: i32,
    pub utilization_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_per_license: Option<Decimal>,
    pub currency: String,
    pub billing_period: LicenseBillingPeriod,
    pub license_type: LicenseType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,
    pub expiration_policy: LicenseExpirationPolicy,
    pub warning_days: i32,
    pub status: LicensePoolStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,
}

impl From<GovLicensePool> for LicensePoolResponse {
    fn from(pool: GovLicensePool) -> Self {
        Self {
            id: pool.id,
            name: pool.name.clone(),
            vendor: pool.vendor.clone(),
            description: pool.description.clone(),
            total_capacity: pool.total_capacity,
            allocated_count: pool.allocated_count,
            available_count: pool.available_count(),
            utilization_percent: pool.utilization_percent(),
            cost_per_license: pool.cost_per_license,
            currency: pool.currency.clone(),
            billing_period: pool.billing_period,
            license_type: pool.license_type,
            expiration_date: pool.expiration_date,
            expiration_policy: pool.expiration_policy,
            warning_days: pool.warning_days,
            status: pool.status,
            created_at: pool.created_at,
            updated_at: pool.updated_at,
            created_by: pool.created_by,
        }
    }
}

/// Query parameters for listing license pools.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct ListLicensePoolsParams {
    /// Filter by vendor name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    /// Filter by license type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_type: Option<LicenseType>,

    /// Filter by status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<LicensePoolStatus>,

    /// Maximum number of results (default: 20, max: 100).
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

// ============================================================================
// License Assignment Models
// ============================================================================

/// Request to assign a license to a user.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct AssignLicenseRequest {
    /// The license pool to assign from.
    pub license_pool_id: Uuid,

    /// The user to assign the license to.
    pub user_id: Uuid,

    /// How the license is being assigned.
    #[serde(default = "default_assignment_source")]
    pub source: LicenseAssignmentSource,

    /// Optional notes about the assignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

fn default_assignment_source() -> LicenseAssignmentSource {
    LicenseAssignmentSource::Manual
}

/// Request for bulk license assignment.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct BulkAssignLicenseRequest {
    /// The license pool to assign from.
    pub license_pool_id: Uuid,

    /// List of user IDs to assign licenses to.
    #[validate(length(min = 1, max = 1000, message = "Must include 1-1000 user IDs"))]
    pub user_ids: Vec<Uuid>,

    /// How the licenses are being assigned.
    #[serde(default = "default_assignment_source")]
    pub source: LicenseAssignmentSource,
}

/// Request for bulk license reclamation.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct BulkReclaimLicenseRequest {
    /// The license pool to reclaim from.
    pub license_pool_id: Uuid,

    /// List of assignment IDs to reclaim.
    #[validate(length(min = 1, max = 1000, message = "Must include 1-1000 assignment IDs"))]
    pub assignment_ids: Vec<Uuid>,

    /// Reason for reclamation.
    pub reason: String,
}

/// License assignment response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseAssignmentResponse {
    pub id: Uuid,
    pub license_pool_id: Uuid,
    pub pool_name: Option<String>,
    pub user_id: Uuid,
    pub user_email: Option<String>,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Uuid,
    pub source: LicenseAssignmentSource,
    pub status: LicenseAssignmentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reclaimed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reclaim_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<GovLicenseAssignment> for LicenseAssignmentResponse {
    fn from(a: GovLicenseAssignment) -> Self {
        Self {
            id: a.id,
            license_pool_id: a.license_pool_id,
            pool_name: None, // Enriched separately
            user_id: a.user_id,
            user_email: None, // Enriched separately
            assigned_at: a.assigned_at,
            assigned_by: a.assigned_by,
            source: a.source,
            status: a.status,
            reclaimed_at: a.reclaimed_at,
            reclaim_reason: a.reclaim_reason.map(|r| format!("{:?}", r).to_lowercase()),
            notes: a.notes,
            created_at: a.created_at,
        }
    }
}

/// Query parameters for listing license assignments.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct ListLicenseAssignmentsParams {
    /// Filter by license pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_pool_id: Option<Uuid>,

    /// Filter by user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,

    /// Filter by status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<LicenseAssignmentStatus>,

    /// Filter by source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<LicenseAssignmentSource>,

    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

/// Result of a bulk operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkOperationResult {
    pub success_count: i32,
    pub failure_count: i32,
    pub failures: Vec<BulkOperationFailure>,
}

/// A single failure in a bulk operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkOperationFailure {
    pub item_id: Uuid,
    pub error: String,
}

// ============================================================================
// License Entitlement Link Models
// ============================================================================

/// Request to create a license-entitlement link.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateLicenseEntitlementLinkRequest {
    /// The license pool to link.
    pub license_pool_id: Uuid,

    /// The entitlement to link.
    pub entitlement_id: Uuid,

    /// Priority when multiple pools could satisfy the entitlement (lower = higher priority).
    #[validate(range(min = 0, message = "Priority must be non-negative"))]
    #[serde(default)]
    pub priority: i32,
}

/// License entitlement link response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseEntitlementLinkResponse {
    pub id: Uuid,
    pub license_pool_id: Uuid,
    pub pool_name: Option<String>,
    pub pool_vendor: Option<String>,
    pub entitlement_id: Uuid,
    pub entitlement_name: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
}

impl From<GovLicenseEntitlementLink> for LicenseEntitlementLinkResponse {
    fn from(l: GovLicenseEntitlementLink) -> Self {
        Self {
            id: l.id,
            license_pool_id: l.license_pool_id,
            pool_name: None,
            pool_vendor: None,
            entitlement_id: l.entitlement_id,
            entitlement_name: None,
            priority: l.priority,
            enabled: l.enabled,
            created_at: l.created_at,
            created_by: l.created_by,
        }
    }
}

/// Query parameters for listing entitlement links.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct ListEntitlementLinksParams {
    /// Filter by license pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_pool_id: Option<Uuid>,

    /// Filter by entitlement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_id: Option<Uuid>,

    /// Filter by enabled status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

// ============================================================================
// License Incompatibility Models
// ============================================================================

/// Request to create a license incompatibility rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateLicenseIncompatibilityRequest {
    /// First pool in the incompatible pair.
    pub pool_a_id: Uuid,

    /// Second pool in the incompatible pair.
    pub pool_b_id: Uuid,

    /// Reason for the incompatibility.
    #[validate(length(min = 1, message = "Reason is required"))]
    pub reason: String,
}

/// License incompatibility response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseIncompatibilityResponse {
    pub id: Uuid,
    pub pool_a_id: Uuid,
    pub pool_a_name: Option<String>,
    pub pool_a_vendor: Option<String>,
    pub pool_b_id: Uuid,
    pub pool_b_name: Option<String>,
    pub pool_b_vendor: Option<String>,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
}

impl From<GovLicenseIncompatibility> for LicenseIncompatibilityResponse {
    fn from(i: GovLicenseIncompatibility) -> Self {
        Self {
            id: i.id,
            pool_a_id: i.pool_a_id,
            pool_a_name: None,
            pool_a_vendor: None,
            pool_b_id: i.pool_b_id,
            pool_b_name: None,
            pool_b_vendor: None,
            reason: i.reason,
            created_at: i.created_at,
            created_by: i.created_by,
        }
    }
}

impl From<LicenseIncompatibilityWithDetails> for LicenseIncompatibilityResponse {
    fn from(i: LicenseIncompatibilityWithDetails) -> Self {
        Self {
            id: i.id,
            pool_a_id: i.pool_a_id,
            pool_a_name: i.pool_a_name,
            pool_a_vendor: i.pool_a_vendor,
            pool_b_id: i.pool_b_id,
            pool_b_name: i.pool_b_name,
            pool_b_vendor: i.pool_b_vendor,
            reason: i.reason,
            created_at: i.created_at,
            created_by: i.created_by,
        }
    }
}

impl LicenseIncompatibilityResponse {
    /// Create a response from a model with pool names.
    pub fn from_model_with_names(
        model: GovLicenseIncompatibility,
        pool_a_name: Option<String>,
        pool_a_vendor: Option<String>,
        pool_b_name: Option<String>,
        pool_b_vendor: Option<String>,
    ) -> Self {
        Self {
            id: model.id,
            pool_a_id: model.pool_a_id,
            pool_a_name,
            pool_a_vendor,
            pool_b_id: model.pool_b_id,
            pool_b_name,
            pool_b_vendor,
            reason: model.reason,
            created_at: model.created_at,
            created_by: model.created_by,
        }
    }
}

/// Query parameters for listing incompatibilities.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct ListIncompatibilitiesParams {
    /// Filter by pool (matches either pool_a or pool_b).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_id: Option<Uuid>,

    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

// ============================================================================
// License Reclamation Rule Models
// ============================================================================

/// Request to create a reclamation rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateReclamationRuleRequest {
    /// The license pool this rule applies to.
    pub license_pool_id: Uuid,

    /// Type of trigger.
    pub trigger_type: LicenseReclamationTrigger,

    /// Days of inactivity before reclamation (required for inactivity trigger).
    #[validate(range(min = 1, message = "Threshold days must be at least 1"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_days: Option<i32>,

    /// Lifecycle state that triggers reclamation (required for lifecycle_state trigger).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<String>,

    /// Days before reclamation to notify user (default: 7).
    #[validate(range(min = 0, max = 365, message = "Notification days must be 0-365"))]
    #[serde(default = "default_notification_days")]
    pub notification_days_before: i32,
}

fn default_notification_days() -> i32 {
    7
}

/// Request to update a reclamation rule.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateReclamationRuleRequest {
    /// Updated threshold days.
    #[validate(range(min = 1, message = "Threshold days must be at least 1"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_days: Option<i32>,

    /// Updated lifecycle state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<String>,

    /// Updated notification days.
    #[validate(range(min = 0, max = 365, message = "Notification days must be 0-365"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_days_before: Option<i32>,

    /// Whether the rule is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// Reclamation rule response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReclamationRuleResponse {
    pub id: Uuid,
    pub license_pool_id: Uuid,
    pub pool_name: Option<String>,
    pub pool_vendor: Option<String>,
    pub trigger_type: LicenseReclamationTrigger,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_days: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<String>,
    pub notification_days_before: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,
}

impl From<GovLicenseReclamationRule> for ReclamationRuleResponse {
    fn from(r: GovLicenseReclamationRule) -> Self {
        Self {
            id: r.id,
            license_pool_id: r.license_pool_id,
            pool_name: None,
            pool_vendor: None,
            trigger_type: r.trigger_type,
            threshold_days: r.threshold_days,
            lifecycle_state: r.lifecycle_state,
            notification_days_before: r.notification_days_before,
            enabled: r.enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
            created_by: r.created_by,
        }
    }
}

/// Query parameters for listing reclamation rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct ListReclamationRulesParams {
    /// Filter by license pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_pool_id: Option<Uuid>,

    /// Filter by trigger type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_type: Option<LicenseReclamationTrigger>,

    /// Filter by enabled status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

// ============================================================================
// License Analytics Models
// ============================================================================

/// License analytics dashboard response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseDashboardResponse {
    /// Summary statistics.
    pub summary: LicenseSummary,

    /// Per-pool statistics.
    pub pools: Vec<LicensePoolStats>,

    /// Cost breakdown by vendor.
    pub cost_by_vendor: Vec<VendorCost>,

    /// Recent audit events.
    pub recent_events: Vec<LicenseAuditEntry>,
}

/// Summary statistics for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseSummary {
    pub total_pools: i64,
    pub total_capacity: i64,
    pub total_allocated: i64,
    pub total_available: i64,
    pub overall_utilization: f64,
    pub total_monthly_cost: Decimal,
    pub expiring_soon_count: i64,
}

/// Statistics for a single pool.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicensePoolStats {
    pub id: Uuid,
    pub name: String,
    pub vendor: String,
    pub total_capacity: i32,
    pub allocated_count: i32,
    pub utilization_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_cost: Option<Decimal>,
    pub status: LicensePoolStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,
}

/// Cost breakdown by vendor.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VendorCost {
    pub vendor: String,
    pub pool_count: i64,
    pub total_capacity: i64,
    pub allocated_count: i64,
    pub monthly_cost: Decimal,
    pub currency: String,
}

/// License optimization recommendation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseRecommendation {
    pub recommendation_type: RecommendationType,
    pub pool_id: Uuid,
    pub pool_name: String,
    pub description: String,
    pub potential_savings: Option<Decimal>,
    pub currency: Option<String>,
}

/// Types of recommendations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationType {
    /// Pool is underutilized (< 60% for 30+ days).
    Underutilized,
    /// Pool is approaching capacity (> 90%).
    HighUtilization,
    /// Pool is expiring soon.
    ExpiringSoon,
    /// Pool has unused licenses that could be reclaimed.
    ReclaimOpportunity,
}

/// Audit event entry for API responses.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseAuditEntry {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    pub action: String,
    pub actor_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_email: Option<String>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for listing audit events.
#[derive(Debug, Clone, Serialize, Deserialize, Default, IntoParams)]
pub struct ListAuditEventsParams {
    /// Filter by pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_id: Option<Uuid>,

    /// Filter by user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,

    /// Filter by action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// Filter from date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_date: Option<DateTime<Utc>>,

    /// Filter to date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_date: Option<DateTime<Utc>>,

    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

// ============================================================================
// Paginated Responses
// ============================================================================

/// Paginated response for license pools.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicensePoolListResponse {
    pub items: Vec<LicensePoolResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Paginated response for license assignments.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LicenseAssignmentListResponse {
    pub items: Vec<LicenseAssignmentResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Paginated response for entitlement links.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EntitlementLinkListResponse {
    pub items: Vec<LicenseEntitlementLinkResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Paginated response for incompatibilities.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IncompatibilityListResponse {
    pub items: Vec<LicenseIncompatibilityResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Paginated response for reclamation rules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReclamationRuleListResponse {
    pub items: Vec<ReclamationRuleResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Paginated response for audit events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditEventListResponse {
    pub items: Vec<LicenseAuditEntry>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// ============================================================================
// Incompatibility Check Response
// ============================================================================

/// Result of checking for license incompatibility violations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IncompatibilityCheckResult {
    /// Whether the assignment would be blocked.
    pub blocked: bool,

    /// List of violations if blocked.
    pub violations: Vec<IncompatibilityViolation>,
}

/// A single incompatibility violation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IncompatibilityViolation {
    pub rule_id: Uuid,
    pub existing_pool_id: Uuid,
    pub existing_pool_name: String,
    pub requested_pool_id: Uuid,
    pub requested_pool_name: String,
    pub reason: String,
}

// ============================================================================
// Expiring Licenses Response
// ============================================================================

/// Response for expiring licenses query.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExpiringLicensesResponse {
    pub pools: Vec<ExpiringPoolInfo>,
    pub total_expiring: i64,
}

/// Information about an expiring pool.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExpiringPoolInfo {
    pub id: Uuid,
    pub name: String,
    pub vendor: String,
    pub expiration_date: DateTime<Utc>,
    pub days_until_expiration: i64,
    pub allocated_count: i32,
    pub total_capacity: i32,
    pub expiration_policy: LicenseExpirationPolicy,
}

// ============================================================================
// Type Aliases for Service Consistency
// ============================================================================

/// Alias for incompatibility list params (service consistency).
pub type ListLicenseIncompatibilitiesParams = ListIncompatibilitiesParams;

/// Alias for incompatibility list response (service consistency).
pub type LicenseIncompatibilityListResponse = IncompatibilityListResponse;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pool_request_defaults() {
        let json = r#"{
            "name": "Test Pool",
            "vendor": "Test Vendor",
            "total_capacity": 100,
            "billing_period": "monthly"
        }"#;

        let req: CreateLicensePoolRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.currency, "USD");
        assert_eq!(req.warning_days, 60);
    }

    #[test]
    fn test_list_params_defaults() {
        // Test serde defaults by deserializing empty JSON
        let params: ListLicensePoolsParams = serde_json::from_str("{}").unwrap();
        assert_eq!(params.limit, 20); // default_limit() function
        assert_eq!(params.offset, 0);
    }
}
