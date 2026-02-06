//! Certification item handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::CertDecisionType;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    DecisionRequest, ItemListResponse, ItemResponse, ItemWithDecisionResponse,
    ItemWithDetailsResponse, ListItemsQuery, MyCertificationsQuery, ReassignRequest,
    ReviewerCampaignSummary, ReviewerSummaryResponse,
};
use crate::router::GovernanceState;

/// List certification items for a campaign.
#[utoipa::path(
    get,
    path = "/governance/certification-campaigns/{campaign_id}/items",
    tag = "Governance - Certification Items",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign ID"),
        ListItemsQuery
    ),
    responses(
        (status = 200, description = "List of items", body = ItemListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_campaign_items(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
    Query(query): Query<ListItemsQuery>,
) -> ApiResult<Json<ItemListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);
    let page = (offset / limit) + 1;

    // Verify campaign exists
    let _ = state
        .certification_campaign_service
        .get(tenant_id, campaign_id)
        .await?;

    let (items, total) = state
        .certification_item_service
        .list_for_campaign(
            tenant_id,
            campaign_id,
            query.status,
            query.reviewer_id,
            limit,
            offset,
        )
        .await?;

    // Convert to response with empty details for now
    let item_responses: Vec<ItemWithDetailsResponse> = items
        .into_iter()
        .map(|item| ItemWithDetailsResponse {
            item: item.into(),
            user: None,
            entitlement: None,
            campaign: None,
            decision: None,
        })
        .collect();

    Ok(Json(ItemListResponse {
        items: item_responses,
        total,
        page,
        page_size: limit,
    }))
}

/// Get a certification item by ID.
#[utoipa::path(
    get,
    path = "/governance/certification-items/{id}",
    tag = "Governance - Certification Items",
    params(
        ("id" = Uuid, Path, description = "Item ID")
    ),
    responses(
        (status = 200, description = "Item details", body = ItemWithDetailsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ItemWithDetailsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let item = state.certification_item_service.get(tenant_id, id).await?;

    let decision = state.certification_item_service.get_decision(id).await?;

    Ok(Json(ItemWithDetailsResponse {
        item: item.into(),
        user: None,
        entitlement: None,
        campaign: None,
        decision: decision.map(Into::into),
    }))
}

/// Submit a decision for a certification item.
#[utoipa::path(
    post,
    path = "/governance/certification-items/{id}/decide",
    tag = "Governance - Certification Items",
    params(
        ("id" = Uuid, Path, description = "Item ID")
    ),
    request_body = DecisionRequest,
    responses(
        (status = 200, description = "Decision recorded", body = ItemWithDecisionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not authorized to decide on this item"),
        (status = 404, description = "Item not found"),
        (status = 409, description = "Item already decided or campaign not active"),
        (status = 422, description = "Validation error"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn decide_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<DecisionRequest>,
) -> ApiResult<Json<ItemWithDecisionResponse>> {
    // Validate justification for revocations
    if request.decision_type == CertDecisionType::Revoked {
        if let Some(ref just) = request.justification {
            if just.trim().len() < 20 {
                return Err(ApiGovernanceError::from(
                    xavyo_governance::error::GovernanceError::RevocationJustificationRequired,
                ));
            }
        } else {
            return Err(ApiGovernanceError::from(
                xavyo_governance::error::GovernanceError::RevocationJustificationRequired,
            ));
        }
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Get the item first to check campaign status
    let item = state.certification_item_service.get(tenant_id, id).await?;

    // Verify campaign is active
    let campaign = state
        .certification_campaign_service
        .get(tenant_id, item.campaign_id)
        .await?;

    if !campaign.can_decide() {
        return Err(ApiGovernanceError::from(
            xavyo_governance::error::GovernanceError::CampaignNotActive(campaign.id),
        ));
    }

    let (updated_item, decision) = state
        .certification_item_service
        .decide(
            tenant_id,
            id,
            user_id,
            request.decision_type,
            request.justification,
        )
        .await?;

    // Check if campaign should be marked as completed
    let _ = state
        .certification_campaign_service
        .check_and_complete_campaign(tenant_id, item.campaign_id)
        .await;

    Ok(Json(ItemWithDecisionResponse {
        item: updated_item.into(),
        decision: decision.into(),
    }))
}

/// Reassign a certification item to a different reviewer.
#[utoipa::path(
    post,
    path = "/governance/certification-items/{id}/reassign",
    tag = "Governance - Certification Items",
    params(
        ("id" = Uuid, Path, description = "Item ID")
    ),
    request_body = ReassignRequest,
    responses(
        (status = 200, description = "Item reassigned", body = ItemResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Item not found"),
        (status = 409, description = "Item not in pending status"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reassign_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ReassignRequest>,
) -> ApiResult<Json<ItemResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let item = state
        .certification_item_service
        .reassign(tenant_id, id, request.new_reviewer_id)
        .await?;

    Ok(Json(item.into()))
}

/// Get pending certification items for the current user.
#[utoipa::path(
    get,
    path = "/governance/my-certifications",
    tag = "Governance - Certification Items",
    params(MyCertificationsQuery),
    responses(
        (status = 200, description = "List of pending items", body = ItemListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_my_certifications(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<MyCertificationsQuery>,
) -> ApiResult<Json<ItemListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);
    let page = (offset / limit) + 1;

    let (items, total) = state
        .certification_item_service
        .list_for_reviewer(tenant_id, user_id, query.campaign_id, limit, offset)
        .await?;

    // Convert to response with empty details for now
    let item_responses: Vec<ItemWithDetailsResponse> = items
        .into_iter()
        .map(|item| ItemWithDetailsResponse {
            item: item.into(),
            user: None,
            entitlement: None,
            campaign: None,
            decision: None,
        })
        .collect();

    Ok(Json(ItemListResponse {
        items: item_responses,
        total,
        page,
        page_size: limit,
    }))
}

/// Get certification summary for the current user.
#[utoipa::path(
    get,
    path = "/governance/my-certifications/summary",
    tag = "Governance - Certification Items",
    responses(
        (status = 200, description = "Certification summary", body = ReviewerSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_my_certifications_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<ReviewerSummaryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let total_pending = state
        .certification_item_service
        .get_reviewer_pending_count(tenant_id, user_id)
        .await?;

    // Get pending items grouped by campaign
    // For now, return a simple summary - could be enhanced to group by campaign
    let campaigns: Vec<ReviewerCampaignSummary> = vec![];

    Ok(Json(ReviewerSummaryResponse {
        total_pending,
        campaigns,
    }))
}
