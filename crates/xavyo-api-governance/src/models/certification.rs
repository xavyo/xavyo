//! Request and response models for certification campaign endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    CertCampaignStatus, CertDecisionType, CertItemStatus, CertItemSummary, CertReviewerType,
    CertScopeType, GovCertificationCampaign, GovCertificationDecision, GovCertificationItem,
};
use xavyo_governance::error::{GovernanceError, Result};

// ============================================================================
// Campaign Models
// ============================================================================

/// Request to create a new certification campaign.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateCampaignRequest {
    /// Campaign display name (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Campaign description.
    pub description: Option<String>,

    /// Scope type for the campaign.
    pub scope_type: CertScopeType,

    /// Scope configuration (depends on `scope_type`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_config: Option<ScopeConfig>,

    /// How to assign reviewers.
    pub reviewer_type: CertReviewerType,

    /// Specific reviewer user IDs (required when `reviewer_type` is `specific_users`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specific_reviewers: Option<Vec<Uuid>>,

    /// Campaign deadline (must be in the future).
    pub deadline: DateTime<Utc>,
}

/// Scope configuration for campaigns.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScopeConfig {
    /// Application ID (when `scope_type` is application).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<Uuid>,

    /// Entitlement ID (when `scope_type` is entitlement).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_id: Option<Uuid>,

    /// Department name (when `scope_type` is department).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
}

/// Request to update a certification campaign (only allowed in draft status).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateCampaignRequest {
    /// Campaign display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Campaign description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Campaign deadline (must be in the future).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<DateTime<Utc>>,
}

/// Query parameters for listing campaigns.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListCampaignsQuery {
    /// Filter by status.
    pub status: Option<CertCampaignStatus>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListCampaignsQuery {
    fn default() -> Self {
        Self {
            status: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Campaign response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CampaignResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Campaign display name.
    pub name: String,

    /// Campaign description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Scope type.
    pub scope_type: CertScopeType,

    /// Scope configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_config: Option<ScopeConfig>,

    /// Reviewer assignment type.
    pub reviewer_type: CertReviewerType,

    /// Specific reviewers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub specific_reviewers: Vec<Uuid>,

    /// Campaign status.
    pub status: CertCampaignStatus,

    /// Campaign deadline.
    pub deadline: DateTime<Utc>,

    /// When the campaign was launched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launched_at: Option<DateTime<Utc>>,

    /// When the campaign was completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    /// Admin who created the campaign.
    pub created_by: Uuid,

    /// When the campaign was created.
    pub created_at: DateTime<Utc>,

    /// When the campaign was last updated.
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<GovCertificationCampaign> for CampaignResponse {
    type Error = GovernanceError;

    fn try_from(campaign: GovCertificationCampaign) -> Result<Self> {
        Ok(Self {
            id: campaign.id,
            tenant_id: campaign.tenant_id,
            name: campaign.name,
            description: campaign.description,
            scope_type: campaign.scope_type,
            scope_config: campaign_scope_config(campaign.scope_config)?,
            reviewer_type: campaign.reviewer_type,
            specific_reviewers: campaign.specific_reviewers,
            status: campaign.status,
            deadline: campaign.deadline,
            launched_at: campaign.launched_at,
            completed_at: campaign.completed_at,
            created_by: campaign.created_by,
            created_at: campaign.created_at,
            updated_at: campaign.updated_at,
        })
    }
}

/// Stored campaign scope JSON. Parse errors must not drop the scope.
pub(crate) fn campaign_scope_config(
    value: Option<serde_json::Value>,
) -> Result<Option<ScopeConfig>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v)
            .map(Some)
            .map_err(GovernanceError::from),
    }
}

/// Campaign response with progress information.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CampaignWithProgressResponse {
    /// Campaign details.
    #[serde(flatten)]
    pub campaign: CampaignResponse,

    /// Progress summary.
    pub progress: CampaignProgressResponse,
}

/// Campaign progress summary.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CampaignProgressResponse {
    /// Total number of items.
    pub total_items: i64,

    /// Number of completed items (decided).
    pub completed_items: i64,

    /// Number of pending items.
    pub pending_items: i64,

    /// Number of approved items.
    pub approved_count: i64,

    /// Advertised BFF alias of `approved_count`.
    pub approved_items: i64,

    /// Number of revoked items.
    pub revoked_count: i64,

    /// Advertised BFF alias of `revoked_count`.
    pub revoked_items: i64,

    /// Number of skipped items.
    pub skipped_count: i64,

    /// Completion percentage.
    pub completion_percentage: f64,

    /// Progress by reviewer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_reviewer: Option<Vec<ReviewerProgressResponse>>,
}

impl From<CertItemSummary> for CampaignProgressResponse {
    fn from(summary: CertItemSummary) -> Self {
        let completed = summary.approved + summary.revoked + summary.skipped;
        let percentage = if summary.total > 0 {
            (completed as f64 / summary.total as f64) * 100.0
        } else {
            0.0
        };

        Self {
            total_items: summary.total,
            completed_items: completed,
            pending_items: summary.pending,
            approved_count: summary.approved,
            approved_items: summary.approved,
            revoked_count: summary.revoked,
            revoked_items: summary.revoked,
            skipped_count: summary.skipped,
            completion_percentage: percentage,
            by_reviewer: None,
        }
    }
}

/// Progress for a specific reviewer.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReviewerProgressResponse {
    /// Reviewer user ID.
    pub reviewer_id: Uuid,

    /// Reviewer display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_name: Option<String>,

    /// Reviewer email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_email: Option<String>,

    /// Total items assigned to this reviewer.
    pub total_items: i64,

    /// Completed items.
    pub completed_items: i64,

    /// Pending items.
    pub pending_items: i64,
}

/// Paginated list of campaigns.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CampaignListResponse {
    /// List of campaigns.
    pub items: Vec<CampaignResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Page number.
    pub page: i64,

    /// Page size.
    pub page_size: i64,

    /// Advertised BFF alias of `page_size`.
    pub limit: i64,

    /// Advertised BFF query offset echoed on the list.
    pub offset: i64,
}

// ============================================================================
// Item Models
// ============================================================================

/// Query parameters for listing certification items.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListItemsQuery {
    /// Filter by status.
    pub status: Option<CertItemStatus>,

    /// Filter by reviewer.
    pub reviewer_id: Option<Uuid>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListItemsQuery {
    fn default() -> Self {
        Self {
            status: None,
            reviewer_id: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Certification item response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ItemResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Parent campaign ID.
    pub campaign_id: Uuid,

    /// Source assignment ID (NULL if deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment_id: Option<Uuid>,

    /// User whose access is being reviewed.
    pub user_id: Uuid,

    /// Entitlement being reviewed.
    pub entitlement_id: Uuid,

    /// Assigned reviewer.
    pub reviewer_id: Uuid,

    /// Item status.
    pub status: CertItemStatus,

    /// Snapshot of assignment at generation time.
    pub assignment_snapshot: serde_json::Value,

    /// When the decision was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,

    /// When the item was created.
    pub created_at: DateTime<Utc>,

    /// When the item was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<GovCertificationItem> for ItemResponse {
    fn from(item: GovCertificationItem) -> Self {
        Self {
            id: item.id,
            tenant_id: item.tenant_id,
            campaign_id: item.campaign_id,
            assignment_id: item.assignment_id,
            user_id: item.user_id,
            entitlement_id: item.entitlement_id,
            reviewer_id: item.reviewer_id,
            status: item.status,
            assignment_snapshot: item.assignment_snapshot,
            decided_at: item.decided_at,
            created_at: item.created_at,
            updated_at: item.updated_at,
        }
    }
}

/// Item response with additional details.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ItemWithDetailsResponse {
    /// Item details.
    #[serde(flatten)]
    pub item: ItemResponse,

    /// User summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserSummary>,

    /// Entitlement summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement: Option<EntitlementSummary>,

    /// Campaign summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign: Option<CampaignSummary>,

    /// Decision if made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionResponse>,

    /// Advertised BFF alias of `campaign.name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign_name: Option<String>,

    /// Advertised BFF alias of `user.email`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,

    /// Advertised BFF alias of entitlement names.
    pub entitlements: Vec<String>,

    /// Advertised BFF alias of `campaign.deadline`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<DateTime<Utc>>,
}

/// Summary of a user for display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserSummary {
    /// User ID.
    pub id: Uuid,

    /// User email.
    pub email: String,

    /// User display name.
    pub display_name: String,

    /// User department.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
}

/// Summary of an entitlement for display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EntitlementSummary {
    /// Entitlement ID.
    pub id: Uuid,

    /// Entitlement name.
    pub name: String,

    /// Entitlement description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Application ID.
    pub application_id: Uuid,

    /// Application name.
    pub application_name: String,

    /// Risk level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
}

/// Summary of a campaign for display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CampaignSummary {
    /// Campaign ID.
    pub id: Uuid,

    /// Campaign name.
    pub name: String,

    /// Campaign deadline.
    pub deadline: DateTime<Utc>,

    /// Advertised BFF alias of `deadline`.
    pub due_date: DateTime<Utc>,

    /// Campaign status.
    pub status: CertCampaignStatus,
}

/// Item response with decision.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ItemWithDecisionResponse {
    /// Item details.
    #[serde(flatten)]
    pub item: ItemResponse,

    /// Decision.
    pub decision: DecisionResponse,
}

/// Paginated list of items.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ItemListResponse {
    /// List of items.
    pub items: Vec<ItemWithDetailsResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Page number.
    pub page: i64,

    /// Page size.
    pub page_size: i64,

    /// Advertised BFF alias of `page_size`.
    pub limit: i64,

    /// Advertised BFF query offset echoed on the list.
    pub offset: i64,
}

// ============================================================================
// Decision Models
// ============================================================================

/// Request to submit a decision for a certification item.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct DecisionRequest {
    /// Decision type (approved or revoked).
    #[serde(alias = "decision")]
    pub decision_type: CertDecisionType,

    /// Justification (required when `decision_type` is revoked, minimum 20 characters).
    #[validate(length(min = 20, message = "Justification must be at least 20 characters"))]
    #[serde(default, alias = "notes", skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

/// Decision response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DecisionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Item ID.
    pub item_id: Uuid,

    /// Decision type.
    pub decision_type: CertDecisionType,

    /// Justification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,

    /// User who made the decision.
    pub decided_by: Uuid,

    /// When the decision was made.
    pub decided_at: DateTime<Utc>,

    /// When the record was created.
    pub created_at: DateTime<Utc>,
}

impl From<GovCertificationDecision> for DecisionResponse {
    fn from(decision: GovCertificationDecision) -> Self {
        Self {
            id: decision.id,
            item_id: decision.item_id,
            decision_type: decision.decision_type,
            justification: decision.justification,
            decided_by: decision.decided_by,
            decided_at: decision.decided_at,
            created_at: decision.created_at,
        }
    }
}

/// Request to reassign an item to a different reviewer.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReassignRequest {
    /// New reviewer user ID.
    pub new_reviewer_id: Uuid,
}

// ============================================================================
// Reviewer Models
// ============================================================================

/// Query parameters for my-certifications endpoint.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct MyCertificationsQuery {
    /// Filter by campaign.
    pub campaign_id: Option<Uuid>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for MyCertificationsQuery {
    fn default() -> Self {
        Self {
            campaign_id: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Reviewer's certification summary.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReviewerSummaryResponse {
    /// Total pending items across all campaigns.
    pub total_pending: i64,

    /// Summary by campaign.
    pub campaigns: Vec<ReviewerCampaignSummary>,
}

/// Summary of pending items for a campaign.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReviewerCampaignSummary {
    /// Campaign ID.
    pub campaign_id: Uuid,

    /// Campaign name.
    pub campaign_name: String,

    /// Number of pending items.
    pub pending_count: i64,

    /// Campaign deadline.
    pub deadline: DateTime<Utc>,

    /// Whether the campaign is overdue.
    pub is_overdue: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_scope_config_does_not_drop_corrupt_json() {
        assert!(campaign_scope_config(None).unwrap().is_none());
        assert!(campaign_scope_config(Some(serde_json::Value::Null))
            .unwrap()
            .is_none());
        assert!(campaign_scope_config(Some(serde_json::json!("nope"))).is_err());
        assert!(campaign_scope_config(Some(serde_json::json!([]))).is_err());

        let src = include_str!("certification.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("from_value::<ScopeConfig>(v.clone()).ok()"),
            "GET campaign must not hide corrupt scope_config as null"
        );
    }

    #[test]
    fn campaign_progress_serializes_bff_item_aliases() {
        let progress = CampaignProgressResponse {
            total_items: 10,
            completed_items: 6,
            pending_items: 4,
            approved_count: 5,
            approved_items: 5,
            revoked_count: 1,
            revoked_items: 1,
            skipped_count: 0,
            completion_percentage: 60.0,
            by_reviewer: None,
        };
        let json = serde_json::to_string(&progress).expect("serialize");
        assert!(json.contains("\"approved_items\":5"));
        assert!(json.contains("\"revoked_items\":1"));
        assert!(json.contains("\"approved_count\":5"));
    }

    #[test]
    fn decide_request_accepts_bff_decision_and_notes_aliases() {
        let req: DecisionRequest =
            serde_json::from_str(r#"{"decision":"approved","notes":"Looks good to keep access"}"#)
                .expect("decision/notes aliases");
        assert_eq!(req.decision_type, CertDecisionType::Approved);
        assert_eq!(
            req.justification.as_deref(),
            Some("Looks good to keep access")
        );
    }

    #[test]
    fn campaign_and_item_lists_serialize_limit_offset_aliases() {
        let campaigns = CampaignListResponse {
            items: vec![],
            total: 0,
            page: 1,
            page_size: 50,
            limit: 50,
            offset: 0,
        };
        let campaign_json = serde_json::to_string(&campaigns).expect("campaigns");
        assert!(campaign_json.contains("\"limit\":50"));
        assert!(campaign_json.contains("\"offset\":0"));

        let items = ItemListResponse {
            items: vec![],
            total: 0,
            page: 2,
            page_size: 25,
            limit: 25,
            offset: 25,
        };
        let item_json = serde_json::to_string(&items).expect("items");
        assert!(item_json.contains("\"limit\":25"));
        assert!(item_json.contains("\"offset\":25"));
    }
}
