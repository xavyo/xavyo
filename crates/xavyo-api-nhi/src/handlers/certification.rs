//! Handlers for unified NHI certification campaigns.
//!
//! Provides endpoints for creating, managing, and deciding on
//! certification campaigns that span both service accounts and AI agents.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::services::unified_certification_service::{
    BulkDecisionFailure, BulkDecisionResult, CampaignFilter, CampaignStatus, CampaignSummary,
    CertificationDecision, ItemCounts, ItemStatus, NhiTypeCounts, UnifiedCertificationCampaign,
    UnifiedCertificationError, UnifiedCertificationItem, UnifiedCertificationService,
};

// ============================================================================
// State
// ============================================================================

/// State for certification handlers.
#[derive(Clone)]
pub struct CertificationState {
    pub certification_service: UnifiedCertificationService,
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create a certification campaign.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub nhi_types: Vec<String>,
    pub filter: Option<CampaignFilterRequest>,
    pub reviewer_id: Uuid,
    pub due_date: DateTime<Utc>,
}

/// Filter criteria in request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CampaignFilterRequest {
    pub owner_id: Option<Uuid>,
    pub risk_min: Option<i32>,
    pub inactive_days: Option<i32>,
}

impl From<CampaignFilterRequest> for CampaignFilter {
    fn from(req: CampaignFilterRequest) -> Self {
        Self {
            owner_id: req.owner_id,
            risk_min: req.risk_min,
            inactive_days: req.inactive_days,
        }
    }
}

/// Campaign response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CampaignResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub nhi_types: Vec<String>,
    pub status: String,
    pub reviewer_id: Uuid,
    pub due_date: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub launched_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub item_counts: Option<ItemCountsResponse>,
}

impl From<UnifiedCertificationCampaign> for CampaignResponse {
    fn from(c: UnifiedCertificationCampaign) -> Self {
        Self {
            id: c.id,
            tenant_id: c.tenant_id,
            name: c.name,
            description: c.description,
            nhi_types: c.nhi_types,
            status: c.status.to_string(),
            reviewer_id: c.reviewer_id,
            due_date: c.due_date,
            created_at: c.created_at,
            launched_at: c.launched_at,
            completed_at: c.completed_at,
            item_counts: None,
        }
    }
}

impl CampaignResponse {
    fn with_counts(mut self, counts: ItemCounts) -> Self {
        self.item_counts = Some(ItemCountsResponse::from(counts));
        self
    }
}

/// Item counts response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ItemCountsResponse {
    pub total: i64,
    pub pending: i64,
    pub certified: i64,
    pub revoked: i64,
}

impl From<ItemCounts> for ItemCountsResponse {
    fn from(c: ItemCounts) -> Self {
        Self {
            total: c.total,
            pending: c.pending,
            certified: c.certified,
            revoked: c.revoked,
        }
    }
}

/// Campaign list response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CampaignListResponse {
    pub items: Vec<CampaignResponse>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

/// Query parameters for listing campaigns.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListCampaignsQuery {
    /// Filter by status: draft, active, completed, cancelled
    pub status: Option<String>,
    /// Page number (1-indexed)
    pub page: Option<i64>,
    /// Items per page (max 100)
    pub per_page: Option<i64>,
}

/// Certification item response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CertificationItemResponse {
    pub id: Uuid,
    pub campaign_id: Uuid,
    pub nhi_id: Uuid,
    pub nhi_type: String,
    pub nhi_name: String,
    pub reviewer_id: Uuid,
    pub status: String,
    pub decision: Option<String>,
    pub decided_by: Option<Uuid>,
    pub decided_at: Option<DateTime<Utc>>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<UnifiedCertificationItem> for CertificationItemResponse {
    fn from(i: UnifiedCertificationItem) -> Self {
        Self {
            id: i.id,
            campaign_id: i.campaign_id,
            nhi_id: i.nhi_id,
            nhi_type: i.nhi_type,
            nhi_name: i.nhi_name,
            reviewer_id: i.reviewer_id,
            status: i.status.to_string(),
            decision: i.decision.map(|d| match d {
                CertificationDecision::Certify => "certify".to_string(),
                CertificationDecision::Revoke => "revoke".to_string(),
            }),
            decided_by: i.decided_by,
            decided_at: i.decided_at,
            comment: i.comment,
            created_at: i.created_at,
        }
    }
}

/// Item list response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ItemListResponse {
    pub items: Vec<CertificationItemResponse>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

/// Query parameters for listing items.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListItemsQuery {
    /// Filter by NHI type: service_account, ai_agent
    pub nhi_type: Option<String>,
    /// Filter by status: pending, certified, revoked
    pub status: Option<String>,
    /// Page number (1-indexed)
    pub page: Option<i64>,
    /// Items per page (max 100)
    pub per_page: Option<i64>,
}

/// Request to make a certification decision.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DecisionRequest {
    pub decision: String,
    pub comment: Option<String>,
}

/// Request for bulk certification decisions.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BulkDecisionRequest {
    pub item_ids: Vec<Uuid>,
    pub decision: String,
    pub comment: Option<String>,
}

/// Campaign summary response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CampaignSummaryResponse {
    pub campaign_id: Uuid,
    pub campaign_name: String,
    pub status: String,
    pub due_date: DateTime<Utc>,
    pub item_counts: ItemCountsResponse,
    pub by_type: Vec<NhiTypeCountsResponse>,
    pub progress_percent: i32,
}

/// Counts per NHI type response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiTypeCountsResponse {
    pub nhi_type: String,
    pub pending: i64,
    pub certified: i64,
    pub revoked: i64,
}

impl From<NhiTypeCounts> for NhiTypeCountsResponse {
    fn from(c: NhiTypeCounts) -> Self {
        Self {
            nhi_type: c.nhi_type,
            pending: c.pending,
            certified: c.certified,
            revoked: c.revoked,
        }
    }
}

impl From<CampaignSummary> for CampaignSummaryResponse {
    fn from(s: CampaignSummary) -> Self {
        Self {
            campaign_id: s.campaign_id,
            campaign_name: s.campaign_name,
            status: s.status.to_string(),
            due_date: s.due_date,
            item_counts: ItemCountsResponse::from(s.item_counts),
            by_type: s.by_type.into_iter().map(Into::into).collect(),
            progress_percent: s.progress_percent,
        }
    }
}

/// Bulk decision response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BulkDecisionResponse {
    pub succeeded: Vec<CertificationItemResponse>,
    pub failed: Vec<BulkFailureResponse>,
    pub total_succeeded: usize,
    pub total_failed: usize,
}

/// Bulk decision failure response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BulkFailureResponse {
    pub item_id: Uuid,
    pub error: String,
}

impl From<BulkDecisionFailure> for BulkFailureResponse {
    fn from(f: BulkDecisionFailure) -> Self {
        Self {
            item_id: f.item_id,
            error: f.error,
        }
    }
}

impl From<BulkDecisionResult> for BulkDecisionResponse {
    fn from(r: BulkDecisionResult) -> Self {
        Self {
            total_succeeded: r.succeeded.len(),
            total_failed: r.failed.len(),
            succeeded: r.succeeded.into_iter().map(Into::into).collect(),
            failed: r.failed.into_iter().map(Into::into).collect(),
        }
    }
}

/// My pending items response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MyPendingItemsResponse {
    pub items: Vec<CertificationItemResponse>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

/// Query parameters for my-pending endpoint.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct MyPendingQuery {
    /// Page number (1-indexed)
    pub page: Option<i64>,
    /// Items per page (max 100)
    pub per_page: Option<i64>,
}

/// Error response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Creates a new certification campaign.
///
/// POST /nhi/certifications/campaigns
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/certifications/campaigns",
    tag = "Unified NHI Certification",
    request_body = CreateCampaignRequest,
    responses(
        (status = 201, description = "Campaign created", body = CampaignResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_campaign(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Json(req): Json<CreateCampaignRequest>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_user".to_string(),
                    message: "Invalid user ID in token".to_string(),
                }),
            )
                .into_response()
        }
    };
    let filter = req.filter.map(Into::into);

    match state
        .certification_service
        .create_campaign(
            tenant_id,
            req.name,
            req.description,
            req.nhi_types,
            filter,
            req.reviewer_id,
            req.due_date,
            user_id,
        )
        .await
    {
        Ok(campaign) => {
            (StatusCode::CREATED, Json(CampaignResponse::from(campaign))).into_response()
        }
        Err(e) => error_response(e),
    }
}

/// Lists certification campaigns.
///
/// GET /nhi/certifications/campaigns
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/certifications/campaigns",
    tag = "Unified NHI Certification",
    params(ListCampaignsQuery),
    responses(
        (status = 200, description = "List of campaigns", body = CampaignListResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_campaigns(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCampaignsQuery>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    let status = query.status.and_then(|s| match s.as_str() {
        "draft" => Some(CampaignStatus::Draft),
        "active" => Some(CampaignStatus::Active),
        "completed" => Some(CampaignStatus::Completed),
        "cancelled" => Some(CampaignStatus::Cancelled),
        _ => None,
    });

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let campaigns = match state
        .certification_service
        .list_campaigns(tenant_id, status, per_page, offset)
        .await
    {
        Ok(c) => c,
        Err(e) => return error_response(e),
    };

    let total = match state
        .certification_service
        .count_campaigns(tenant_id, status)
        .await
    {
        Ok(t) => t,
        Err(e) => return error_response(e),
    };

    let items: Vec<CampaignResponse> = campaigns.into_iter().map(Into::into).collect();

    Json(CampaignListResponse {
        items,
        total,
        page,
        per_page,
    })
    .into_response()
}

/// Gets a specific campaign with item counts.
///
/// GET /nhi/certifications/campaigns/:campaign_id
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/certifications/campaigns/{campaign_id}",
    tag = "Unified NHI Certification",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign UUID")
    ),
    responses(
        (status = 200, description = "Campaign details", body = CampaignResponse),
        (status = 404, description = "Campaign not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_campaign(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    let campaign = match state
        .certification_service
        .get_campaign(tenant_id, campaign_id)
        .await
    {
        Ok(c) => c,
        Err(e) => return error_response(e),
    };

    let counts = match state
        .certification_service
        .get_item_counts(tenant_id, campaign_id)
        .await
    {
        Ok(c) => c,
        Err(e) => return error_response(e),
    };

    Json(CampaignResponse::from(campaign).with_counts(counts)).into_response()
}

/// Launches a campaign.
///
/// POST /nhi/certifications/campaigns/:campaign_id/launch
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/certifications/campaigns/{campaign_id}/launch",
    tag = "Unified NHI Certification",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign UUID")
    ),
    responses(
        (status = 200, description = "Campaign launched", body = CampaignResponse),
        (status = 400, description = "Campaign not in draft status", body = ErrorResponse),
        (status = 404, description = "Campaign not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn launch_campaign(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    match state
        .certification_service
        .launch_campaign(tenant_id, campaign_id)
        .await
    {
        Ok(campaign) => {
            let counts = state
                .certification_service
                .get_item_counts(tenant_id, campaign_id)
                .await
                .unwrap_or_default();
            Json(CampaignResponse::from(campaign).with_counts(counts)).into_response()
        }
        Err(e) => error_response(e),
    }
}

/// Cancels a campaign.
///
/// POST /nhi/certifications/campaigns/:campaign_id/cancel
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/certifications/campaigns/{campaign_id}/cancel",
    tag = "Unified NHI Certification",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign UUID")
    ),
    responses(
        (status = 200, description = "Campaign cancelled", body = CampaignResponse),
        (status = 400, description = "Campaign cannot be cancelled", body = ErrorResponse),
        (status = 404, description = "Campaign not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn cancel_campaign(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    match state
        .certification_service
        .cancel_campaign(tenant_id, campaign_id)
        .await
    {
        Ok(campaign) => Json(CampaignResponse::from(campaign)).into_response(),
        Err(e) => error_response(e),
    }
}

/// Lists items for a campaign.
///
/// GET /nhi/certifications/campaigns/:campaign_id/items
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/certifications/campaigns/{campaign_id}/items",
    tag = "Unified NHI Certification",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign UUID"),
        ListItemsQuery
    ),
    responses(
        (status = 200, description = "List of certification items", body = ItemListResponse),
        (status = 404, description = "Campaign not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_campaign_items(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
    Query(query): Query<ListItemsQuery>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    let status = query.status.and_then(|s| match s.as_str() {
        "pending" => Some(ItemStatus::Pending),
        "certified" => Some(ItemStatus::Certified),
        "revoked" => Some(ItemStatus::Revoked),
        _ => None,
    });

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let items = match state
        .certification_service
        .list_items(
            tenant_id,
            campaign_id,
            query.nhi_type.clone(),
            status,
            per_page,
            offset,
        )
        .await
    {
        Ok(i) => i,
        Err(e) => return error_response(e),
    };

    let total = match state
        .certification_service
        .count_items(tenant_id, campaign_id, query.nhi_type, status)
        .await
    {
        Ok(t) => t,
        Err(e) => return error_response(e),
    };

    let items: Vec<CertificationItemResponse> = items.into_iter().map(Into::into).collect();

    Json(ItemListResponse {
        items,
        total,
        page,
        per_page,
    })
    .into_response()
}

/// Makes a decision on a certification item.
///
/// POST /nhi/certifications/items/:item_id/decide
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/certifications/items/{item_id}/decide",
    tag = "Unified NHI Certification",
    params(
        ("item_id" = Uuid, Path, description = "Certification item UUID")
    ),
    request_body = DecisionRequest,
    responses(
        (status = 200, description = "Decision recorded", body = CertificationItemResponse),
        (status = 400, description = "Invalid decision or item already decided", body = ErrorResponse),
        (status = 404, description = "Item not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn decide_item(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(item_id): Path<Uuid>,
    Json(req): Json<DecisionRequest>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_user".to_string(),
                    message: "Invalid user ID in token".to_string(),
                }),
            )
                .into_response()
        }
    };

    let decision = match req.decision.as_str() {
        "certify" => CertificationDecision::Certify,
        "revoke" => CertificationDecision::Revoke,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_decision".to_string(),
                    message: "Decision must be 'certify' or 'revoke'".to_string(),
                }),
            )
                .into_response()
        }
    };

    match state
        .certification_service
        .decide_item(tenant_id, item_id, decision, req.comment, user_id)
        .await
    {
        Ok(item) => Json(CertificationItemResponse::from(item)).into_response(),
        Err(e) => error_response(e),
    }
}

/// Gets campaign summary statistics.
///
/// GET /nhi/certifications/campaigns/:campaign_id/summary
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/certifications/campaigns/{campaign_id}/summary",
    tag = "Unified NHI Certification",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign UUID")
    ),
    responses(
        (status = 200, description = "Campaign summary", body = CampaignSummaryResponse),
        (status = 404, description = "Campaign not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_campaign_summary(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    match state
        .certification_service
        .get_campaign_summary(tenant_id, campaign_id)
        .await
    {
        Ok(summary) => Json(CampaignSummaryResponse::from(summary)).into_response(),
        Err(e) => error_response(e),
    }
}

/// Makes bulk certification decisions.
///
/// POST /nhi/certifications/items/bulk-decide
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/certifications/items/bulk-decide",
    tag = "Unified NHI Certification",
    request_body = BulkDecisionRequest,
    responses(
        (status = 200, description = "Bulk decision results", body = BulkDecisionResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn bulk_decide(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Json(req): Json<BulkDecisionRequest>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_user".to_string(),
                    message: "Invalid user ID in token".to_string(),
                }),
            )
                .into_response()
        }
    };

    let decision = match req.decision.as_str() {
        "certify" => CertificationDecision::Certify,
        "revoke" => CertificationDecision::Revoke,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_decision".to_string(),
                    message: "Decision must be 'certify' or 'revoke'".to_string(),
                }),
            )
                .into_response()
        }
    };

    match state
        .certification_service
        .bulk_decide(tenant_id, req.item_ids, decision, req.comment, user_id)
        .await
    {
        Ok(result) => Json(BulkDecisionResponse::from(result)).into_response(),
        Err(e) => error_response(e),
    }
}

/// Gets pending certification items for the current user.
///
/// GET /nhi/certifications/my-pending
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/certifications/my-pending",
    tag = "Unified NHI Certification",
    params(MyPendingQuery),
    responses(
        (status = 200, description = "User's pending certification items", body = MyPendingItemsResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_my_pending(
    State(state): State<CertificationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<MyPendingQuery>,
) -> impl IntoResponse {
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing_tenant".to_string(),
                    message: "Tenant ID is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_user".to_string(),
                    message: "Invalid user ID in token".to_string(),
                }),
            )
                .into_response()
        }
    };

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let items = match state
        .certification_service
        .get_my_pending_items(tenant_id, user_id, per_page, offset)
        .await
    {
        Ok(i) => i,
        Err(e) => return error_response(e),
    };

    let total = match state
        .certification_service
        .count_my_pending_items(tenant_id, user_id)
        .await
    {
        Ok(t) => t,
        Err(e) => return error_response(e),
    };

    let items: Vec<CertificationItemResponse> = items.into_iter().map(Into::into).collect();

    Json(MyPendingItemsResponse {
        items,
        total,
        page,
        per_page,
    })
    .into_response()
}

// ============================================================================
// Error Handling
// ============================================================================

fn error_response(e: UnifiedCertificationError) -> axum::response::Response {
    let (status, error_code, message) = match &e {
        UnifiedCertificationError::Database(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            e.to_string(),
        ),
        UnifiedCertificationError::CampaignNotFound(_) => {
            (StatusCode::NOT_FOUND, "campaign_not_found", e.to_string())
        }
        UnifiedCertificationError::ItemNotFound(_) => {
            (StatusCode::NOT_FOUND, "item_not_found", e.to_string())
        }
        UnifiedCertificationError::CampaignNotDraft => {
            (StatusCode::BAD_REQUEST, "campaign_not_draft", e.to_string())
        }
        UnifiedCertificationError::CampaignNotActive => (
            StatusCode::BAD_REQUEST,
            "campaign_not_active",
            e.to_string(),
        ),
        UnifiedCertificationError::NoMatchingNhis => {
            (StatusCode::BAD_REQUEST, "no_matching_nhis", e.to_string())
        }
        UnifiedCertificationError::DueDateInPast => {
            (StatusCode::BAD_REQUEST, "due_date_in_past", e.to_string())
        }
        UnifiedCertificationError::NoNhiTypesSelected => (
            StatusCode::BAD_REQUEST,
            "no_nhi_types_selected",
            e.to_string(),
        ),
        UnifiedCertificationError::ItemAlreadyDecided => (
            StatusCode::BAD_REQUEST,
            "item_already_decided",
            e.to_string(),
        ),
    };

    (
        status,
        Json(ErrorResponse {
            error: error_code.to_string(),
            message,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_campaign_filter_request_conversion() {
        let req = CampaignFilterRequest {
            owner_id: Some(Uuid::new_v4()),
            risk_min: Some(50),
            inactive_days: Some(30),
        };

        let filter: CampaignFilter = req.into();
        assert!(filter.owner_id.is_some());
        assert_eq!(filter.risk_min, Some(50));
        assert_eq!(filter.inactive_days, Some(30));
    }

    #[test]
    fn test_item_counts_response_from() {
        let counts = ItemCounts {
            total: 100,
            pending: 50,
            certified: 40,
            revoked: 10,
        };

        let response = ItemCountsResponse::from(counts);
        assert_eq!(response.total, 100);
        assert_eq!(response.pending, 50);
        assert_eq!(response.certified, 40);
        assert_eq!(response.revoked, 10);
    }

    #[test]
    fn test_certification_item_response_serialization() {
        let item = UnifiedCertificationItem {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            campaign_id: Uuid::new_v4(),
            nhi_id: Uuid::new_v4(),
            nhi_type: "service_account".to_string(),
            nhi_name: "Test SA".to_string(),
            reviewer_id: Uuid::new_v4(),
            status: ItemStatus::Pending,
            decision: None,
            decided_by: None,
            decided_at: None,
            comment: None,
            created_at: Utc::now(),
        };

        let response = CertificationItemResponse::from(item);
        assert_eq!(response.status, "pending");
        assert!(response.decision.is_none());
    }

    #[test]
    fn test_campaign_response_with_counts() {
        let campaign = UnifiedCertificationCampaign {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Campaign".to_string(),
            description: None,
            nhi_types: vec!["service_account".to_string()],
            status: CampaignStatus::Active,
            reviewer_id: Uuid::new_v4(),
            filter: None,
            due_date: Utc::now(),
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            launched_at: Some(Utc::now()),
            completed_at: None,
        };

        let counts = ItemCounts {
            total: 10,
            pending: 5,
            certified: 3,
            revoked: 2,
        };

        let response = CampaignResponse::from(campaign).with_counts(counts);
        assert!(response.item_counts.is_some());
        let ic = response.item_counts.unwrap();
        assert_eq!(ic.total, 10);
    }

    // T065: Test get_campaign_summary handler types
    #[test]
    fn test_campaign_summary_response_structure() {
        let summary_response = CampaignSummaryResponse {
            campaign_id: Uuid::new_v4(),
            campaign_name: "Test Campaign".to_string(),
            status: "active".to_string(),
            due_date: Utc::now(),
            item_counts: ItemCountsResponse {
                total: 100,
                pending: 60,
                certified: 30,
                revoked: 10,
            },
            by_type: vec![
                NhiTypeCountsResponse {
                    nhi_type: "service_account".to_string(),
                    pending: 40,
                    certified: 20,
                    revoked: 5,
                },
                NhiTypeCountsResponse {
                    nhi_type: "ai_agent".to_string(),
                    pending: 20,
                    certified: 10,
                    revoked: 5,
                },
            ],
            progress_percent: 40,
        };

        assert_eq!(summary_response.progress_percent, 40);
        assert_eq!(summary_response.by_type.len(), 2);
        assert_eq!(summary_response.item_counts.total, 100);
    }

    // T066: Test bulk_decide handler types
    #[test]
    fn test_bulk_decision_request_types() {
        let request = BulkDecisionRequest {
            item_ids: vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
            decision: "certify".to_string(),
            comment: Some("Bulk approval".to_string()),
        };

        assert_eq!(request.item_ids.len(), 3);
        assert_eq!(request.decision, "certify");
        assert!(request.comment.is_some());
    }

    #[test]
    fn test_bulk_decision_response_structure() {
        let response = BulkDecisionResponse {
            succeeded: vec![],
            failed: vec![BulkFailureResponse {
                item_id: Uuid::new_v4(),
                error: "Item already decided".to_string(),
            }],
            total_succeeded: 5,
            total_failed: 1,
        };

        assert_eq!(response.total_succeeded, 5);
        assert_eq!(response.total_failed, 1);
        assert_eq!(response.failed.len(), 1);
    }

    #[test]
    fn test_my_pending_items_response() {
        let response = MyPendingItemsResponse {
            items: vec![],
            total: 15,
            page: 1,
            per_page: 20,
        };

        assert_eq!(response.total, 15);
        assert_eq!(response.page, 1);
        assert!(response.items.is_empty());
    }

    #[test]
    fn test_my_pending_query_defaults() {
        let query = MyPendingQuery {
            page: None,
            per_page: None,
        };
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());

        let query_with_pagination = MyPendingQuery {
            page: Some(2),
            per_page: Some(50),
        };
        assert_eq!(query_with_pagination.page, Some(2));
        assert_eq!(query_with_pagination.per_page, Some(50));
    }
}
