//! Certification item handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use std::collections::HashMap;
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::{
    CertDecisionType, GovApplication, GovCertificationCampaign, GovCertificationItem,
    GovEntitlement, GovRiskLevel, User,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CampaignSummary, DecisionRequest, EntitlementSummary, ItemListResponse, ItemResponse,
    ItemWithDecisionResponse, ItemWithDetailsResponse, ListItemsQuery, MyCertificationsQuery,
    ReassignRequest, ReviewerCampaignSummary, ReviewerSummaryResponse, UserSummary,
};
use crate::router::GovernanceState;

struct ItemDetailCache {
    users: HashMap<Uuid, UserSummary>,
    entitlements: HashMap<Uuid, EntitlementSummary>,
    campaigns: HashMap<Uuid, CampaignSummary>,
}

impl ItemDetailCache {
    fn new() -> Self {
        Self {
            users: HashMap::new(),
            entitlements: HashMap::new(),
            campaigns: HashMap::new(),
        }
    }
}

fn entitlement_risk_level(level: GovRiskLevel) -> String {
    match level {
        GovRiskLevel::Low => "low",
        GovRiskLevel::Medium => "medium",
        GovRiskLevel::High => "high",
        GovRiskLevel::Critical => "critical",
    }
    .to_string()
}

async fn user_summary(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
    cache: &mut ItemDetailCache,
) -> Result<Option<UserSummary>, sqlx::Error> {
    if let Some(existing) = cache.users.get(&user_id) {
        return Ok(Some(existing.clone()));
    }
    let Some(user) = User::find_by_id_in_tenant(pool, tenant_id, user_id).await? else {
        return Ok(None);
    };
    let summary = UserSummary {
        id: user.id,
        email: user.email.clone(),
        display_name: user.display_name.unwrap_or_else(|| user.email.clone()),
        department: None,
    };
    cache.users.insert(user_id, summary.clone());
    Ok(Some(summary))
}

async fn entitlement_summary(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    entitlement_id: Uuid,
    cache: &mut ItemDetailCache,
) -> Result<Option<EntitlementSummary>, sqlx::Error> {
    if let Some(existing) = cache.entitlements.get(&entitlement_id) {
        return Ok(Some(existing.clone()));
    }
    let Some(entitlement) = GovEntitlement::find_by_id(pool, tenant_id, entitlement_id).await?
    else {
        return Ok(None);
    };
    let Some(application) =
        GovApplication::find_by_id(pool, tenant_id, entitlement.application_id).await?
    else {
        return Ok(None);
    };
    let application_name = application.name;
    let summary = EntitlementSummary {
        id: entitlement.id,
        name: entitlement.name,
        description: entitlement.description,
        application_id: entitlement.application_id,
        application_name,
        risk_level: Some(entitlement_risk_level(entitlement.risk_level)),
    };
    cache.entitlements.insert(entitlement_id, summary.clone());
    Ok(Some(summary))
}

async fn campaign_summary(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    campaign_id: Uuid,
    cache: &mut ItemDetailCache,
) -> Result<Option<CampaignSummary>, sqlx::Error> {
    if let Some(existing) = cache.campaigns.get(&campaign_id) {
        return Ok(Some(existing.clone()));
    }
    let Some(campaign) = GovCertificationCampaign::find_by_id(pool, tenant_id, campaign_id).await?
    else {
        return Ok(None);
    };
    let summary = CampaignSummary {
        id: campaign.id,
        name: campaign.name,
        deadline: campaign.deadline,
        status: campaign.status,
    };
    cache.campaigns.insert(campaign_id, summary.clone());
    Ok(Some(summary))
}

async fn item_with_details(
    state: &GovernanceState,
    tenant_id: Uuid,
    item: GovCertificationItem,
    cache: &mut ItemDetailCache,
    include_decision: bool,
) -> ApiResult<ItemWithDetailsResponse> {
    let pool = state.pool();
    let user = user_summary(pool, tenant_id, item.user_id, cache)
        .await
        .map_err(ApiGovernanceError::Database)?;
    let entitlement = entitlement_summary(pool, tenant_id, item.entitlement_id, cache)
        .await
        .map_err(ApiGovernanceError::Database)?;
    let campaign = campaign_summary(pool, tenant_id, item.campaign_id, cache)
        .await
        .map_err(ApiGovernanceError::Database)?;
    let decision = if include_decision {
        state
            .certification_item_service
            .get_decision(tenant_id, item.id)
            .await?
            .map(Into::into)
    } else {
        None
    };
    Ok(ItemWithDetailsResponse {
        item: item.into(),
        user,
        entitlement,
        campaign,
        decision,
    })
}

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

    let mut cache = ItemDetailCache::new();
    let mut item_responses = Vec::with_capacity(items.len());
    for item in items {
        let include_decision = item.decided_at.is_some();
        item_responses
            .push(item_with_details(&state, tenant_id, item, &mut cache, include_decision).await?);
    }

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

    let mut cache = ItemDetailCache::new();
    Ok(Json(
        item_with_details(&state, tenant_id, item, &mut cache, true).await?,
    ))
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
    state
        .certification_campaign_service
        .check_and_complete_campaign(tenant_id, item.campaign_id)
        .await?;

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

    let mut cache = ItemDetailCache::new();
    let mut item_responses = Vec::with_capacity(items.len());
    for item in items {
        let include_decision = item.decided_at.is_some();
        item_responses
            .push(item_with_details(&state, tenant_id, item, &mut cache, include_decision).await?);
    }

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

    let campaigns = state
        .certification_item_service
        .list_reviewer_pending_by_campaign(tenant_id, user_id)
        .await?
        .into_iter()
        .map(
            |(campaign_id, campaign_name, deadline, is_overdue, pending_count)| {
                ReviewerCampaignSummary {
                    campaign_id,
                    campaign_name,
                    pending_count,
                    deadline,
                    is_overdue,
                }
            },
        )
        .collect();

    Ok(Json(ReviewerSummaryResponse {
        total_pending,
        campaigns,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_item_passes_tenant_to_decision_lookup() {
        let src = include_str!("certification_items.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("get_decision(tenant_id, item.id)"),
            "certification item GET must look up decisions with JWT tenant_id"
        );
        assert!(
            !production.contains("get_decision(id)"),
            "must not look up certification decisions without tenant_id"
        );
    }

    #[test]
    fn certification_item_lists_include_related_details() {
        let src = include_str!("certification_items.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("item_with_details(")
                && production.contains("user_summary(")
                && production.contains("entitlement_summary(")
                && production.contains("campaign_summary("),
            "certification item responses must load user, entitlement, and campaign details"
        );
        assert!(
            !production.contains(
                "user: None,\n            entitlement: None,\n            campaign: None"
            ),
            "must not return certification items with empty related details"
        );
    }

    #[test]
    fn my_certifications_summary_groups_pending_by_campaign() {
        let src = include_str!("certification_items.rs");
        let production = src.split("mod tests").next().expect("production source");
        let summary = production
            .split("pub async fn get_my_certifications_summary")
            .nth(1)
            .and_then(|s| s.split("#[cfg(test)]").next())
            .expect("get_my_certifications_summary");
        assert!(
            summary.contains("list_reviewer_pending_by_campaign(")
                && !summary.contains("campaigns: Vec::new()")
                && !summary.contains("let campaigns: Vec<ReviewerCampaignSummary> = vec![]"),
            "my-certifications summary must group pending items by campaign"
        );
    }

    #[test]
    fn decide_does_not_swallow_campaign_complete() {
        let src = include_str!("certification_items.rs");
        let production = src.split("mod tests").next().expect("production source");
        let decide = production
            .split("check_and_complete_campaign")
            .nth(1)
            .expect("check_and_complete_campaign");
        assert!(
            !production.contains("let _ = state\n        .certification_campaign_service\n        .check_and_complete_campaign"),
            "certification decide must not swallow campaign completion"
        );
        assert!(
            decide.contains(".await?;"),
            "certification decide must fail when campaign completion cannot be written"
        );
    }
}
