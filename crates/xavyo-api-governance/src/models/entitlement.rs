//! Entitlement request/response models for governance API.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::models::{
    DataProtectionClassification, GdprLegalBasis, GovEntitlement, GovEntitlementStatus,
    GovRiskLevel,
};

/// Request to create a new entitlement.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateEntitlementRequest {
    /// The application this entitlement belongs to.
    pub application_id: Uuid,

    /// Entitlement display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Entitlement description.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Risk level classification.
    pub risk_level: GovRiskLevel,

    /// Entitlement owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    #[validate(length(max = 255, message = "External ID cannot exceed 255 characters"))]
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether this entitlement can be delegated. Defaults to true.
    pub is_delegable: Option<bool>,

    /// GDPR data protection classification. Defaults to none.
    pub data_protection_classification: Option<DataProtectionClassification>,

    /// GDPR legal basis for processing personal data.
    pub legal_basis: Option<GdprLegalBasis>,

    /// Data retention period in days. Must be positive if set.
    pub retention_period_days: Option<i32>,

    /// Name of the data controller organization.
    #[validate(length(max = 500, message = "Data controller cannot exceed 500 characters"))]
    pub data_controller: Option<String>,

    /// Name of the data processor organization.
    #[validate(length(max = 500, message = "Data processor cannot exceed 500 characters"))]
    pub data_processor: Option<String>,

    /// Processing purpose labels.
    pub purposes: Option<Vec<String>>,
}

/// Request to update an entitlement.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateEntitlementRequest {
    /// Entitlement display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: Option<String>,

    /// Entitlement description.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Risk level classification.
    pub risk_level: Option<GovRiskLevel>,

    /// Entitlement status.
    pub status: Option<GovEntitlementStatus>,

    /// Entitlement owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    #[validate(length(max = 255, message = "External ID cannot exceed 255 characters"))]
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether this entitlement can be delegated.
    pub is_delegable: Option<bool>,

    /// GDPR data protection classification.
    pub data_protection_classification: Option<DataProtectionClassification>,

    /// GDPR legal basis for processing personal data.
    pub legal_basis: Option<GdprLegalBasis>,

    /// Data retention period in days. Must be positive if set.
    pub retention_period_days: Option<i32>,

    /// Name of the data controller organization.
    #[validate(length(max = 500, message = "Data controller cannot exceed 500 characters"))]
    pub data_controller: Option<String>,

    /// Name of the data processor organization.
    #[validate(length(max = 500, message = "Data processor cannot exceed 500 characters"))]
    pub data_processor: Option<String>,

    /// Processing purpose labels.
    pub purposes: Option<Vec<String>>,
}

/// Query parameters for listing entitlements.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListEntitlementsQuery {
    /// Filter by application ID.
    pub application_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<GovEntitlementStatus>,

    /// Filter by risk level.
    pub risk_level: Option<GovRiskLevel>,

    /// Filter by owner ID.
    pub owner_id: Option<Uuid>,

    /// Filter by GDPR data protection classification.
    pub classification: Option<DataProtectionClassification>,

    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Number of results to skip.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Entitlement response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EntitlementResponse {
    /// Unique identifier for the entitlement.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// The application this entitlement belongs to.
    pub application_id: Uuid,

    /// Entitlement display name.
    pub name: String,

    /// Entitlement description.
    pub description: Option<String>,

    /// Risk level classification.
    pub risk_level: GovRiskLevel,

    /// Entitlement status.
    pub status: GovEntitlementStatus,

    /// Entitlement owner (user ID).
    pub owner_id: Option<Uuid>,

    /// External system reference ID.
    pub external_id: Option<String>,

    /// Extensible metadata as JSON.
    pub metadata: Option<serde_json::Value>,

    /// Whether this entitlement can be delegated.
    pub is_delegable: bool,

    /// GDPR data protection classification.
    pub data_protection_classification: DataProtectionClassification,

    /// GDPR legal basis for processing personal data.
    pub legal_basis: Option<GdprLegalBasis>,

    /// Data retention period in days.
    pub retention_period_days: Option<i32>,

    /// Name of the data controller organization.
    pub data_controller: Option<String>,

    /// Name of the data processor organization.
    pub data_processor: Option<String>,

    /// Processing purpose labels.
    pub purposes: Option<Vec<String>>,

    /// When the entitlement was created.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the entitlement was last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<GovEntitlement> for EntitlementResponse {
    fn from(ent: GovEntitlement) -> Self {
        Self {
            id: ent.id,
            tenant_id: ent.tenant_id,
            application_id: ent.application_id,
            name: ent.name,
            description: ent.description,
            risk_level: ent.risk_level,
            status: ent.status,
            owner_id: ent.owner_id,
            external_id: ent.external_id,
            metadata: ent.metadata,
            is_delegable: ent.is_delegable,
            data_protection_classification: ent.data_protection_classification,
            legal_basis: ent.legal_basis,
            retention_period_days: ent.retention_period_days,
            data_controller: ent.data_controller,
            data_processor: ent.data_processor,
            purposes: ent.purposes,
            created_at: ent.created_at,
            updated_at: ent.updated_at,
        }
    }
}

/// Paginated list of entitlements.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EntitlementListResponse {
    /// List of entitlements.
    pub items: Vec<EntitlementResponse>,

    /// Total count of matching entitlements.
    pub total: i64,

    /// Maximum number of results returned.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}

/// Request to set entitlement owner.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SetOwnerRequest {
    /// The user ID to set as owner.
    pub owner_id: Uuid,
}

/// Validate GDPR-specific business rules for create requests.
pub fn validate_gdpr_create(
    classification: Option<DataProtectionClassification>,
    legal_basis: Option<GdprLegalBasis>,
    retention_period_days: Option<i32>,
) -> Result<(), String> {
    let classification = classification.unwrap_or_default();

    // legal_basis requires classification != none
    if legal_basis.is_some() && classification == DataProtectionClassification::None {
        return Err(
            "legal_basis requires data_protection_classification to be set (not 'none')"
                .to_string(),
        );
    }

    // retention_period_days must be positive
    if let Some(days) = retention_period_days {
        if days <= 0 {
            return Err("retention_period_days must be a positive integer".to_string());
        }
    }

    Ok(())
}

/// Validate GDPR-specific business rules for update requests.
/// Uses the existing classification as fallback when not being updated.
pub fn validate_gdpr_update(
    new_classification: Option<DataProtectionClassification>,
    existing_classification: DataProtectionClassification,
    legal_basis: Option<GdprLegalBasis>,
    retention_period_days: Option<i32>,
) -> Result<(), String> {
    let effective_classification = new_classification.unwrap_or(existing_classification);

    // legal_basis requires classification != none
    if legal_basis.is_some() && effective_classification == DataProtectionClassification::None {
        return Err(
            "legal_basis requires data_protection_classification to be set (not 'none')"
                .to_string(),
        );
    }

    // retention_period_days must be positive
    if let Some(days) = retention_period_days {
        if days <= 0 {
            return Err("retention_period_days must be a positive integer".to_string());
        }
    }

    Ok(())
}

/// GDPR compliance report for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GdprReport {
    /// Tenant ID.
    pub tenant_id: Uuid,

    /// When the report was generated.
    pub generated_at: chrono::DateTime<chrono::Utc>,

    /// Total entitlements in the tenant.
    pub total_entitlements: i64,

    /// Number of entitlements with classification != none.
    pub classified_entitlements: i64,

    /// Count per classification level.
    pub classification_summary: std::collections::HashMap<String, i64>,

    /// Count per legal basis.
    pub legal_basis_summary: std::collections::HashMap<String, i64>,

    /// Classified entitlements with details.
    pub classified_entitlements_detail: Vec<ClassifiedEntitlementDetail>,

    /// Entitlements with retention periods set.
    pub entitlements_with_retention: Vec<ClassifiedEntitlementDetail>,
}

/// Detail of a classified entitlement for GDPR reporting.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClassifiedEntitlementDetail {
    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Entitlement name.
    pub entitlement_name: String,

    /// Application name.
    pub application_name: String,

    /// Data protection classification.
    pub classification: DataProtectionClassification,

    /// Legal basis for processing.
    pub legal_basis: Option<GdprLegalBasis>,

    /// Retention period in days.
    pub retention_period_days: Option<i32>,

    /// Data controller name.
    pub data_controller: Option<String>,

    /// Data processor name.
    pub data_processor: Option<String>,

    /// Processing purposes.
    pub purposes: Option<Vec<String>>,

    /// Number of active assignments for this entitlement.
    pub active_assignment_count: i64,
}

/// Per-user data protection summary.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserDataProtectionSummary {
    /// User ID.
    pub user_id: Uuid,

    /// Classified entitlements assigned to this user.
    pub entitlements: Vec<EntitlementResponse>,

    /// Total classified entitlements.
    pub total_classified: i64,

    /// Count per classification level.
    pub classifications: std::collections::HashMap<String, i64>,
}
