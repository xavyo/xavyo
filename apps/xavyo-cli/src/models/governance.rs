//! Governance data models for the CLI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --- Roles ---

/// Role response from the API
#[derive(Debug, Serialize, Deserialize)]
pub struct RoleResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub role_type: Option<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub is_requestable: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Role list response
#[derive(Debug, Serialize, Deserialize)]
pub struct RoleListResponse {
    pub roles: Vec<RoleResponse>,
    pub total: i64,
}

// --- Entitlements ---

/// Entitlement response from the API
#[derive(Debug, Serialize, Deserialize)]
pub struct EntitlementResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub entitlement_type: Option<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Entitlement list response
#[derive(Debug, Serialize, Deserialize)]
pub struct EntitlementListResponse {
    pub entitlements: Vec<EntitlementResponse>,
    pub total: i64,
}

// --- Access Requests ---

/// Access request response from the API
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessRequestResponse {
    pub id: Uuid,
    #[serde(default)]
    pub requester_id: Option<Uuid>,
    #[serde(default)]
    pub target_id: Option<Uuid>,
    #[serde(default)]
    pub request_type: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub justification: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Access request list response
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessRequestListResponse {
    pub access_requests: Vec<AccessRequestResponse>,
    pub total: i64,
}

/// Create access request
#[derive(Debug, Serialize)]
pub struct CreateAccessRequest {
    pub target_id: Uuid,
    pub request_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

// --- Archetypes ---

#[derive(Debug, Serialize, Deserialize)]
pub struct ArchetypeResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    #[serde(default)]
    pub is_abstract: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ArchetypeListResponse {
    pub archetypes: Vec<ArchetypeResponse>,
    pub total: i64,
}

// --- Lifecycle Configs ---

#[derive(Debug, Serialize, Deserialize)]
pub struct LifecycleConfigResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub object_type: Option<String>,
    #[serde(default)]
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LifecycleConfigListResponse {
    pub configs: Vec<LifecycleConfigResponse>,
    pub total: i64,
}

// --- SoD Rules ---

#[derive(Debug, Serialize, Deserialize)]
pub struct SodRuleResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub rule_type: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SodRuleListResponse {
    pub rules: Vec<SodRuleResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SodViolationResponse {
    pub id: Uuid,
    #[serde(default)]
    pub rule_id: Option<Uuid>,
    #[serde(default)]
    pub user_id: Option<Uuid>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub severity: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SodViolationListResponse {
    pub violations: Vec<SodViolationResponse>,
    pub total: i64,
}

// --- Certification Campaigns ---

#[derive(Debug, Serialize, Deserialize)]
pub struct CampaignResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub campaign_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CampaignListResponse {
    pub campaigns: Vec<CampaignResponse>,
    pub total: i64,
}

// --- Object Templates ---

#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectTemplateResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub object_type: Option<String>,
    #[serde(default)]
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectTemplateListResponse {
    pub templates: Vec<ObjectTemplateResponse>,
    pub total: i64,
}

// --- Catalog ---

#[derive(Debug, Serialize, Deserialize)]
pub struct CatalogCategoryResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CatalogCategoryListResponse {
    pub categories: Vec<CatalogCategoryResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CatalogItemResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category_id: Option<Uuid>,
    #[serde(default)]
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CatalogItemListResponse {
    pub items: Vec<CatalogItemResponse>,
    pub total: i64,
}

// --- Bulk Actions ---

#[derive(Debug, Serialize, Deserialize)]
pub struct BulkActionResponse {
    pub id: Uuid,
    #[serde(default)]
    pub action_type: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub total_items: Option<i64>,
    #[serde(default)]
    pub processed_items: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BulkActionListResponse {
    pub bulk_actions: Vec<BulkActionResponse>,
    pub total: i64,
}

// --- Delegations ---

#[derive(Debug, Serialize, Deserialize)]
pub struct DelegationResponse {
    pub id: Uuid,
    #[serde(default)]
    pub delegator_id: Option<Uuid>,
    #[serde(default)]
    pub deputy_id: Option<Uuid>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub starts_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub ends_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DelegationListResponse {
    pub delegations: Vec<DelegationResponse>,
    pub total: i64,
}

// --- GDPR ---

#[derive(Debug, Serialize, Deserialize)]
pub struct GdprReportResponse {
    #[serde(default)]
    pub user_id: Option<Uuid>,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
    pub generated_at: DateTime<Utc>,
}

// --- Risk ---

#[derive(Debug, Serialize, Deserialize)]
pub struct RiskScoreResponse {
    #[serde(default)]
    pub user_id: Option<Uuid>,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub factors: Option<serde_json::Value>,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RiskAlertResponse {
    pub id: Uuid,
    #[serde(default)]
    pub user_id: Option<Uuid>,
    #[serde(default)]
    pub alert_type: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RiskAlertListResponse {
    pub alerts: Vec<RiskAlertResponse>,
    pub total: i64,
}

// --- Reports ---

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub report_type: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub format: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportListResponse {
    pub reports: Vec<ReportResponse>,
    pub total: i64,
}

// --- Approval Workflows ---

#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalWorkflowResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalWorkflowListResponse {
    pub workflows: Vec<ApprovalWorkflowResponse>,
    pub total: i64,
}
