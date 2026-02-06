//! Certification campaign handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CampaignListResponse, CampaignProgressResponse, CampaignResponse, CampaignWithProgressResponse,
    CreateCampaignRequest, ListCampaignsQuery, UpdateCampaignRequest,
};
use crate::router::GovernanceState;

/// List certification campaigns.
#[utoipa::path(
    get,
    path = "/governance/certification-campaigns",
    tag = "Governance - Certification Campaigns",
    params(ListCampaignsQuery),
    responses(
        (status = 200, description = "List of campaigns", body = CampaignListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_campaigns(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCampaignsQuery>,
) -> ApiResult<Json<CampaignListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);
    let page = (offset / limit) + 1;

    let (campaigns, total) = state
        .certification_campaign_service
        .list(tenant_id, query.status, limit, offset)
        .await?;

    Ok(Json(CampaignListResponse {
        items: campaigns.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Create a new certification campaign.
#[utoipa::path(
    post,
    path = "/governance/certification-campaigns",
    tag = "Governance - Certification Campaigns",
    request_body = CreateCampaignRequest,
    responses(
        (status = 201, description = "Campaign created", body = CampaignResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Campaign name already exists"),
        (status = 422, description = "Validation error"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateCampaignRequest>,
) -> ApiResult<(StatusCode, Json<CampaignResponse>)> {
    request.validate().map_err(ApiGovernanceError::from)?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let campaign = state
        .certification_campaign_service
        .create(
            tenant_id,
            request.name,
            request.description,
            request.scope_type,
            request.scope_config,
            request.reviewer_type,
            request.specific_reviewers,
            request.deadline,
            user_id,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(campaign.into())))
}

/// Get a certification campaign by ID.
#[utoipa::path(
    get,
    path = "/governance/certification-campaigns/{id}",
    tag = "Governance - Certification Campaigns",
    params(
        ("id" = Uuid, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign details with progress", body = CampaignWithProgressResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CampaignWithProgressResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let campaign = state
        .certification_campaign_service
        .get(tenant_id, id)
        .await?;

    let progress = state
        .certification_campaign_service
        .get_progress(tenant_id, id)
        .await?;

    Ok(Json(CampaignWithProgressResponse {
        campaign: campaign.into(),
        progress: progress.into(),
    }))
}

/// Update a certification campaign (only allowed in draft status).
#[utoipa::path(
    put,
    path = "/governance/certification-campaigns/{id}",
    tag = "Governance - Certification Campaigns",
    params(
        ("id" = Uuid, Path, description = "Campaign ID")
    ),
    request_body = UpdateCampaignRequest,
    responses(
        (status = 200, description = "Campaign updated", body = CampaignResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 409, description = "Campaign not in draft status"),
        (status = 422, description = "Validation error"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateCampaignRequest>,
) -> ApiResult<Json<CampaignResponse>> {
    request.validate().map_err(ApiGovernanceError::from)?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let campaign = state
        .certification_campaign_service
        .update(
            tenant_id,
            id,
            request.name,
            request.description,
            request.deadline,
        )
        .await?;

    Ok(Json(campaign.into()))
}

/// Delete a certification campaign (only allowed in draft status).
#[utoipa::path(
    delete,
    path = "/governance/certification-campaigns/{id}",
    tag = "Governance - Certification Campaigns",
    params(
        ("id" = Uuid, Path, description = "Campaign ID")
    ),
    responses(
        (status = 204, description = "Campaign deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 409, description = "Cannot delete non-draft campaign"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .certification_campaign_service
        .delete(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Launch a certification campaign.
#[utoipa::path(
    post,
    path = "/governance/certification-campaigns/{id}/launch",
    tag = "Governance - Certification Campaigns",
    params(
        ("id" = Uuid, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign launched", body = CampaignWithProgressResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 409, description = "Campaign not in draft status or no items to generate"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn launch_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CampaignWithProgressResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let campaign = state
        .certification_campaign_service
        .launch(tenant_id, id)
        .await?;

    let progress = state
        .certification_campaign_service
        .get_progress(tenant_id, id)
        .await?;

    Ok(Json(CampaignWithProgressResponse {
        campaign: campaign.into(),
        progress: progress.into(),
    }))
}

/// Cancel a certification campaign.
#[utoipa::path(
    post,
    path = "/governance/certification-campaigns/{id}/cancel",
    tag = "Governance - Certification Campaigns",
    params(
        ("id" = Uuid, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign cancelled", body = CampaignResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 409, description = "Campaign cannot be cancelled in current status"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CampaignResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let campaign = state
        .certification_campaign_service
        .cancel(tenant_id, id)
        .await?;

    Ok(Json(campaign.into()))
}

/// Get campaign progress.
#[utoipa::path(
    get,
    path = "/governance/certification-campaigns/{id}/progress",
    tag = "Governance - Certification Campaigns",
    params(
        ("id" = Uuid, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign progress", body = CampaignProgressResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_campaign_progress(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CampaignProgressResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let progress = state
        .certification_campaign_service
        .get_progress(tenant_id, id)
        .await?;

    Ok(Json(progress.into()))
}
