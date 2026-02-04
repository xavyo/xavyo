//! Request and response models for risk factor endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovRiskFactor, RiskFactorCategory};

/// Common risk factor types for static factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum StaticFactorType {
    /// Count of sensitive entitlements assigned.
    SensitiveEntitlementCount,
    /// Count of active `SoD` violations.
    SodViolationCount,
    /// Total entitlement count.
    TotalEntitlementCount,
    /// Access to high-risk applications.
    HighRiskAppAccess,
    /// Orphan account status.
    OrphanAccount,
    /// Excessive privilege indicator.
    ExcessivePrivilege,
}

/// Common risk factor types for dynamic factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DynamicFactorType {
    /// Count of failed login attempts.
    FailedLoginCount,
    /// Login at unusual time.
    UnusualLoginTime,
    /// Login from new location.
    NewLocationLogin,
    /// Excessive access attempts.
    ExcessiveAccessAttempts,
    /// Activity on dormant account.
    DormantAccountActivity,
}

/// Request to create a new risk factor.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateRiskFactorRequest {
    /// Display name for the factor.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    /// Factor category (static or dynamic).
    pub category: RiskFactorCategory,

    /// Specific factor type identifier.
    #[validate(length(min = 1, max = 50, message = "Factor type must be 1-50 characters"))]
    pub factor_type: String,

    /// Weight in score calculation (0.0-10.0).
    #[validate(range(min = 0.0, max = 10.0, message = "Weight must be between 0.0 and 10.0"))]
    pub weight: f64,

    /// Human-readable description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Whether the factor is enabled (default: true).
    pub is_enabled: Option<bool>,
}

/// Request to update an existing risk factor.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateRiskFactorRequest {
    /// Updated display name.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: Option<String>,

    /// Updated category.
    pub category: Option<RiskFactorCategory>,

    /// Updated factor type.
    #[validate(length(min = 1, max = 50, message = "Factor type must be 1-50 characters"))]
    pub factor_type: Option<String>,

    /// Updated weight (0.0-10.0).
    #[validate(range(min = 0.0, max = 10.0, message = "Weight must be between 0.0 and 10.0"))]
    pub weight: Option<f64>,

    /// Updated description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Updated enabled status.
    pub is_enabled: Option<bool>,
}

/// Query parameters for listing risk factors.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListRiskFactorsQuery {
    /// Filter by category.
    pub category: Option<RiskFactorCategory>,

    /// Filter by enabled status.
    pub is_enabled: Option<bool>,

    /// Filter by factor type.
    pub factor_type: Option<String>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListRiskFactorsQuery {
    fn default() -> Self {
        Self {
            category: None,
            is_enabled: None,
            factor_type: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Risk factor response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskFactorResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Factor category.
    pub category: RiskFactorCategory,

    /// Specific factor type.
    pub factor_type: String,

    /// Weight in calculation.
    pub weight: f64,

    /// Description.
    pub description: Option<String>,

    /// Whether enabled.
    pub is_enabled: bool,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovRiskFactor> for RiskFactorResponse {
    fn from(factor: GovRiskFactor) -> Self {
        Self {
            id: factor.id,
            name: factor.name,
            category: factor.category,
            factor_type: factor.factor_type,
            weight: factor.weight,
            description: factor.description,
            is_enabled: factor.is_enabled,
            created_at: factor.created_at,
            updated_at: factor.updated_at,
        }
    }
}

/// Paginated list of risk factors.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskFactorListResponse {
    /// List of factors.
    pub items: Vec<RiskFactorResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}
