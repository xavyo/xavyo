//! NHI (Non-Human Identity) handlers for managing machine-to-machine accounts.
//!
//! F061 - NHI Lifecycle Management

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use utoipa::IntoParams;
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ApproveNhiRequestRequest, CertifyNhiResponse, CreateNhiRequest, ListNhiRequestsQuery,
    ListNhisQuery, NhiListResponse, NhiRequestListResponse, NhiRequestResponse, NhiResponse,
    NhiRiskScoreResponse, NhiSummary, ReactivateNhiRequest, RejectNhiRequestRequest,
    RiskLevelSummary, SubmitNhiRequestRequest, SuspendNhiRequest, TransferOwnershipRequest,
    UpdateNhiRequest,
};
use crate::router::GovernanceState;

/// List NHIs with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/nhis",
    tag = "Governance - NHIs",
    params(ListNhisQuery),
    responses(
        (status = 200, description = "List of NHIs", body = NhiListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_nhis(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListNhisQuery>,
) -> ApiResult<Json<NhiListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state.nhi_service.list(tenant_id, &query).await?;

    Ok(Json(result))
}

/// Get NHI summary statistics.
#[utoipa::path(
    get,
    path = "/governance/nhis/summary",
    tag = "Governance - NHIs",
    responses(
        (status = 200, description = "NHI summary statistics", body = NhiSummary),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<NhiSummary>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state.nhi_service.get_summary(tenant_id).await?;

    Ok(Json(summary))
}

/// Get an NHI by ID.
#[utoipa::path(
    get,
    path = "/governance/nhis/{id}",
    tag = "Governance - NHIs",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    responses(
        (status = 200, description = "NHI details", body = NhiResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<NhiResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let nhi = state.nhi_service.get(tenant_id, id).await?;

    Ok(Json(nhi))
}

/// Create a new NHI.
#[utoipa::path(
    post,
    path = "/governance/nhis",
    tag = "Governance - NHIs",
    request_body = CreateNhiRequest,
    responses(
        (status = 201, description = "NHI created", body = NhiResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "NHI name already exists or user already registered"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_nhi(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateNhiRequest>,
) -> ApiResult<(StatusCode, Json<NhiResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let nhi = state
        .nhi_service
        .create(tenant_id, actor_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(nhi)))
}

/// Update an NHI.
#[utoipa::path(
    put,
    path = "/governance/nhis/{id}",
    tag = "Governance - NHIs",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    request_body = UpdateNhiRequest,
    responses(
        (status = 200, description = "NHI updated", body = NhiResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 409, description = "NHI name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_nhi(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateNhiRequest>,
) -> ApiResult<Json<NhiResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let nhi = state
        .nhi_service
        .update(tenant_id, id, actor_id, request)
        .await?;

    Ok(Json(nhi))
}

/// Delete an NHI.
#[utoipa::path(
    delete,
    path = "/governance/nhis/{id}",
    tag = "Governance - NHIs",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    responses(
        (status = 204, description = "NHI deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_nhi(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state.nhi_service.delete(tenant_id, id, actor_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Suspend an NHI.
#[utoipa::path(
    post,
    path = "/governance/nhis/{id}/suspend",
    tag = "Governance - NHIs",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    request_body = SuspendNhiRequest,
    responses(
        (status = 200, description = "NHI suspended", body = NhiResponse),
        (status = 400, description = "Invalid request or NHI already suspended"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn suspend_nhi(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<SuspendNhiRequest>,
) -> ApiResult<Json<NhiResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let nhi = state
        .nhi_service
        .suspend(tenant_id, id, actor_id, request.reason, request.details)
        .await?;

    Ok(Json(nhi))
}

/// Reactivate a suspended NHI.
#[utoipa::path(
    post,
    path = "/governance/nhis/{id}/reactivate",
    tag = "Governance - NHIs",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    request_body = ReactivateNhiRequest,
    responses(
        (status = 200, description = "NHI reactivated", body = NhiResponse),
        (status = 400, description = "Invalid request or NHI not suspended"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reactivate_nhi(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ReactivateNhiRequest>,
) -> ApiResult<Json<NhiResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let nhi = state
        .nhi_service
        .reactivate(tenant_id, id, actor_id, Some(request.reason))
        .await?;

    Ok(Json(nhi))
}

/// Transfer ownership of an NHI.
#[utoipa::path(
    post,
    path = "/governance/nhis/{id}/transfer-ownership",
    tag = "Governance - NHIs",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    request_body = TransferOwnershipRequest,
    responses(
        (status = 200, description = "Ownership transferred", body = NhiResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn transfer_nhi_ownership(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<TransferOwnershipRequest>,
) -> ApiResult<Json<NhiResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let nhi = state
        .nhi_service
        .transfer_ownership(
            tenant_id,
            id,
            actor_id,
            request.new_owner_id,
            Some(request.reason),
        )
        .await?;

    Ok(Json(nhi))
}

/// Certify an NHI (confirm ownership and purpose are still valid).
#[utoipa::path(
    post,
    path = "/governance/nhis/{id}/certify",
    tag = "Governance - NHIs",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    responses(
        (status = 200, description = "NHI certified", body = CertifyNhiResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn certify_nhi(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CertifyNhiResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let nhi = state
        .nhi_service
        .certify(tenant_id, id, actor_id, None)
        .await?;

    Ok(Json(CertifyNhiResponse {
        nhi,
        message: "NHI ownership and purpose confirmed".to_string(),
    }))
}

// =============================================================================
// Usage Tracking Handlers
// =============================================================================

use crate::models::{
    ListNhiUsageQuery, NhiUsageListResponse, NhiUsageSummaryExtendedResponse, RecordUsageRequest,
    StalenessReportResponse,
};

/// Query parameters for staleness report.
#[derive(Debug, Clone, serde::Deserialize, IntoParams)]
pub struct StalenessReportParams {
    /// Minimum days inactive to include in report.
    #[param(minimum = 1)]
    pub min_inactive_days: Option<i32>,
}

/// Record a usage event for an NHI.
#[utoipa::path(
    post,
    path = "/governance/nhis/{id}/usage",
    tag = "Governance - NHI Usage",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    request_body = RecordUsageRequest,
    responses(
        (status = 201, description = "Usage event recorded"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn record_nhi_usage(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<RecordUsageRequest>,
) -> ApiResult<StatusCode> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .nhi_usage_service
        .record_usage(tenant_id, id, request)
        .await?;

    Ok(StatusCode::CREATED)
}

/// List usage events for an NHI.
#[utoipa::path(
    get,
    path = "/governance/nhis/{id}/usage",
    tag = "Governance - NHI Usage",
    params(
        ("id" = Uuid, Path, description = "NHI ID"),
        ListNhiUsageQuery
    ),
    responses(
        (status = 200, description = "List of usage events", body = NhiUsageListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_nhi_usage(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListNhiUsageQuery>,
) -> ApiResult<Json<NhiUsageListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .nhi_usage_service
        .list_usage(tenant_id, id, query)
        .await?;

    Ok(Json(result))
}

/// Get usage summary for an NHI.
#[utoipa::path(
    get,
    path = "/governance/nhis/{id}/usage/summary",
    tag = "Governance - NHI Usage",
    params(
        ("id" = Uuid, Path, description = "NHI ID"),
        ("period_days" = Option<i32>, Query, description = "Period in days (default: 30)")
    ),
    responses(
        (status = 200, description = "Usage summary", body = NhiUsageSummaryExtendedResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_usage_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(params): Query<UsageSummaryParams>,
) -> ApiResult<Json<NhiUsageSummaryExtendedResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state
        .nhi_usage_service
        .get_summary(tenant_id, id, params.period_days)
        .await?;

    Ok(Json(summary))
}

/// Query parameters for usage summary.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UsageSummaryParams {
    pub period_days: Option<i32>,
}

/// Get staleness report for all NHIs.
#[utoipa::path(
    get,
    path = "/governance/nhis/staleness-report",
    tag = "Governance - NHI Usage",
    params(StalenessReportParams),
    responses(
        (status = 200, description = "Staleness report", body = StalenessReportResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_staleness_report(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<StalenessReportParams>,
) -> ApiResult<Json<StalenessReportResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let report = state
        .nhi_usage_service
        .get_staleness_report(tenant_id, params.min_inactive_days)
        .await?;

    Ok(Json(report))
}

// =============================================================================
// Risk Score Handlers
// =============================================================================

/// Get NHI risk score.
#[utoipa::path(
    get,
    path = "/governance/nhis/{id}/risk",
    tag = "Governance - NHI Risk",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    responses(
        (status = 200, description = "Risk score retrieved", body = NhiRiskScoreResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI or score not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_risk_score(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<NhiRiskScoreResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let score = state
        .nhi_risk_service
        .get_or_calculate_score(tenant_id, id)
        .await?;

    Ok(Json(score))
}

/// Calculate/recalculate NHI risk score.
#[utoipa::path(
    post,
    path = "/governance/nhis/{id}/risk/calculate",
    tag = "Governance - NHI Risk",
    params(
        ("id" = Uuid, Path, description = "NHI ID")
    ),
    responses(
        (status = 200, description = "Risk score calculated", body = NhiRiskScoreResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn calculate_nhi_risk_score(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<NhiRiskScoreResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let score = state
        .nhi_risk_service
        .calculate_score(tenant_id, id)
        .await?;

    Ok(Json(score))
}

/// Get risk score summary by level.
#[utoipa::path(
    get,
    path = "/governance/nhis/risk/summary",
    tag = "Governance - NHI Risk",
    responses(
        (status = 200, description = "Risk summary retrieved", body = RiskLevelSummary),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_risk_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<RiskLevelSummary>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state.nhi_risk_service.get_risk_summary(tenant_id).await?;

    Ok(Json(summary))
}

/// Batch calculate risk scores for multiple NHIs.
#[utoipa::path(
    post,
    path = "/governance/nhis/risk/batch-calculate",
    tag = "Governance - NHI Risk",
    request_body = Vec<Uuid>,
    responses(
        (status = 200, description = "Risk scores calculated", body = Vec<NhiRiskScoreResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn batch_calculate_nhi_risk(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(nhi_ids): Json<Vec<Uuid>>,
) -> ApiResult<Json<Vec<NhiRiskScoreResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    if nhi_ids.is_empty() {
        return Ok(Json(vec![]));
    }

    // Limit batch size
    if nhi_ids.len() > 100 {
        return Err(ApiGovernanceError::Validation(
            "Batch size cannot exceed 100 NHIs".to_string(),
        ));
    }

    let scores = state
        .nhi_risk_service
        .batch_calculate(tenant_id, nhi_ids)
        .await?;

    Ok(Json(scores))
}

// ============================================================================
// NHI Certification Handlers
// ============================================================================

use crate::models::{
    BulkNhiCertificationDecisionRequest, BulkNhiCertificationResult,
    CreateNhiCertificationCampaignRequest, ListNhiCertificationCampaignsQuery,
    ListNhiCertificationItemsQuery, NhiCertificationCampaignListResponse,
    NhiCertificationCampaignResponse, NhiCertificationDecisionRequest,
    NhiCertificationItemListResponse, NhiCertificationItemResponse, NhiCertificationSummary,
};

/// Create an NHI certification campaign.
#[utoipa::path(
    post,
    path = "/governance/nhis/certification/campaigns",
    tag = "Governance - NHI Certification",
    request_body = CreateNhiCertificationCampaignRequest,
    responses(
        (status = 201, description = "Campaign created", body = NhiCertificationCampaignResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_nhi_certification_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateNhiCertificationCampaignRequest>,
) -> ApiResult<(StatusCode, Json<NhiCertificationCampaignResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let campaign = state
        .nhi_certification_service
        .create_campaign(
            tenant_id,
            request.name,
            request.description,
            request.owner_filter,
            request.needs_certification_only,
            request.reviewer_type,
            request.specific_reviewers,
            request.deadline,
            user_id,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(campaign)))
}

/// Launch an NHI certification campaign.
#[utoipa::path(
    post,
    path = "/governance/nhis/certification/campaigns/{campaign_id}/launch",
    tag = "Governance - NHI Certification",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign launched", body = NhiCertificationCampaignResponse),
        (status = 400, description = "Cannot launch campaign"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn launch_nhi_certification_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
) -> ApiResult<Json<NhiCertificationCampaignResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let campaign = state
        .nhi_certification_service
        .launch_campaign(tenant_id, campaign_id, None, true)
        .await?;

    Ok(Json(campaign))
}

/// Get an NHI certification campaign.
#[utoipa::path(
    get,
    path = "/governance/nhis/certification/campaigns/{campaign_id}",
    tag = "Governance - NHI Certification",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign details", body = NhiCertificationCampaignResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_certification_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
) -> ApiResult<Json<NhiCertificationCampaignResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let campaign = state
        .nhi_certification_service
        .get_campaign(tenant_id, campaign_id)
        .await?;

    Ok(Json(campaign))
}

/// List NHI certification campaigns.
#[utoipa::path(
    get,
    path = "/governance/nhis/certification/campaigns",
    tag = "Governance - NHI Certification",
    params(ListNhiCertificationCampaignsQuery),
    responses(
        (status = 200, description = "List of campaigns", body = NhiCertificationCampaignListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_nhi_certification_campaigns(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListNhiCertificationCampaignsQuery>,
) -> ApiResult<Json<NhiCertificationCampaignListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0).max(0);

    let (items, total) = state
        .nhi_certification_service
        .list_campaigns(tenant_id, query.status, query.created_by, limit, offset)
        .await?;

    Ok(Json(NhiCertificationCampaignListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Cancel an NHI certification campaign.
#[utoipa::path(
    post,
    path = "/governance/nhis/certification/campaigns/{campaign_id}/cancel",
    tag = "Governance - NHI Certification",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign cancelled", body = NhiCertificationCampaignResponse),
        (status = 400, description = "Cannot cancel campaign"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_nhi_certification_campaign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
) -> ApiResult<Json<NhiCertificationCampaignResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let campaign = state
        .nhi_certification_service
        .cancel_campaign(tenant_id, campaign_id)
        .await?;

    Ok(Json(campaign))
}

/// Get campaign summary.
#[utoipa::path(
    get,
    path = "/governance/nhis/certification/campaigns/{campaign_id}/summary",
    tag = "Governance - NHI Certification",
    params(
        ("campaign_id" = Uuid, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign summary", body = NhiCertificationSummary),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_certification_campaign_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(campaign_id): Path<Uuid>,
) -> ApiResult<Json<NhiCertificationSummary>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state
        .nhi_certification_service
        .get_campaign_summary(tenant_id, campaign_id)
        .await?;

    Ok(Json(summary))
}

/// List certification items.
#[utoipa::path(
    get,
    path = "/governance/nhis/certification/items",
    tag = "Governance - NHI Certification",
    params(ListNhiCertificationItemsQuery),
    responses(
        (status = 200, description = "List of certification items", body = NhiCertificationItemListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_nhi_certification_items(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListNhiCertificationItemsQuery>,
) -> ApiResult<Json<NhiCertificationItemListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0).max(0);

    let reviewer_id = if query.my_pending == Some(true) {
        Some(Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?)
    } else {
        query.reviewer_id
    };

    let (items, total) = state
        .nhi_certification_service
        .list_items(
            tenant_id,
            query.campaign_id,
            query.status,
            reviewer_id,
            query.owner_id,
            limit,
            offset,
        )
        .await?;

    Ok(Json(NhiCertificationItemListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get a certification item.
#[utoipa::path(
    get,
    path = "/governance/nhis/certification/items/{item_id}",
    tag = "Governance - NHI Certification",
    params(
        ("item_id" = Uuid, Path, description = "Certification item ID")
    ),
    responses(
        (status = 200, description = "Certification item details", body = NhiCertificationItemResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_certification_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(item_id): Path<Uuid>,
) -> ApiResult<Json<NhiCertificationItemResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let item = state
        .nhi_certification_service
        .get_item(tenant_id, item_id)
        .await?;

    Ok(Json(item))
}

/// Make a decision on a certification item.
#[utoipa::path(
    post,
    path = "/governance/nhis/certification/items/{item_id}/decide",
    tag = "Governance - NHI Certification",
    params(
        ("item_id" = Uuid, Path, description = "Certification item ID")
    ),
    request_body = NhiCertificationDecisionRequest,
    responses(
        (status = 200, description = "Decision recorded", body = NhiCertificationItemResponse),
        (status = 400, description = "Invalid decision or already decided"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not authorized to decide"),
        (status = 404, description = "Item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn decide_nhi_certification(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(item_id): Path<Uuid>,
    Json(request): Json<NhiCertificationDecisionRequest>,
) -> ApiResult<Json<NhiCertificationItemResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let item = state
        .nhi_certification_service
        .decide(
            tenant_id,
            item_id,
            user_id,
            request.decision,
            request.comment,
            request.delegate_to,
        )
        .await?;

    Ok(Json(item))
}

/// Make the same decision on multiple certification items.
#[utoipa::path(
    post,
    path = "/governance/nhis/certification/items/bulk-decide",
    tag = "Governance - NHI Certification",
    request_body = BulkNhiCertificationDecisionRequest,
    responses(
        (status = 200, description = "Bulk decision results", body = BulkNhiCertificationResult),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn bulk_decide_nhi_certification(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BulkNhiCertificationDecisionRequest>,
) -> ApiResult<Json<BulkNhiCertificationResult>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .nhi_certification_service
        .bulk_decide(
            tenant_id,
            &request.item_ids,
            user_id,
            request.decision,
            request.comment,
        )
        .await?;

    Ok(Json(result))
}

/// Get my pending certification items.
#[utoipa::path(
    get,
    path = "/governance/nhis/certification/my-pending",
    tag = "Governance - NHI Certification",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of results"),
        ("offset" = Option<i64>, Query, description = "Number of results to skip")
    ),
    responses(
        (status = 200, description = "My pending items", body = NhiCertificationItemListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_my_pending_nhi_certifications(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<PaginationParams>,
) -> ApiResult<Json<NhiCertificationItemListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;
    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);

    let (items, total) = state
        .nhi_certification_service
        .get_my_pending_items(tenant_id, user_id, limit, offset)
        .await?;

    Ok(Json(NhiCertificationItemListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Pagination parameters for my-pending endpoint.
#[derive(Debug, Clone, serde::Deserialize, IntoParams)]
pub struct PaginationParams {
    /// Maximum number of results.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

// ============================================================================
// NHI Request Handlers (Self-Service Workflow - US6)
// ============================================================================

/// Submit a new NHI request.
#[utoipa::path(
    post,
    path = "/governance/nhis/requests",
    tag = "Governance - NHI Requests",
    request_body = SubmitNhiRequestRequest,
    responses(
        (status = 201, description = "Request submitted successfully", body = NhiRequestResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Duplicate pending request exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn submit_nhi_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(body): Json<SubmitNhiRequestRequest>,
) -> ApiResult<(StatusCode, Json<NhiRequestResponse>)> {
    body.validate()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .nhi_request_service
        .submit_request(
            tenant_id,
            user_id,
            body.name,
            body.purpose,
            body.requested_permissions,
            body.requested_expiration,
            body.requested_rotation_days,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// List NHI requests with filtering.
#[utoipa::path(
    get,
    path = "/governance/nhis/requests",
    tag = "Governance - NHI Requests",
    params(ListNhiRequestsQuery),
    responses(
        (status = 200, description = "List of NHI requests", body = NhiRequestListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_nhi_requests(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListNhiRequestsQuery>,
) -> ApiResult<Json<NhiRequestListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let filter = xavyo_db::NhiRequestFilter {
        requester_id: query.requester_id,
        status: query.status,
        pending_only: query.pending_only,
    };

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0).max(0);

    let result = state
        .nhi_request_service
        .list_requests(tenant_id, filter, limit, offset)
        .await?;

    Ok(Json(result))
}

/// Get my pending NHI requests (submitted by me).
#[utoipa::path(
    get,
    path = "/governance/nhis/requests/my-pending",
    tag = "Governance - NHI Requests",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of results"),
        ("offset" = Option<i64>, Query, description = "Number of results to skip")
    ),
    responses(
        (status = 200, description = "My pending requests", body = NhiRequestListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_my_pending_nhi_requests(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<PaginationParams>,
) -> ApiResult<Json<NhiRequestListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;
    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);

    let result = state
        .nhi_request_service
        .get_my_pending_requests(tenant_id, user_id, limit, offset)
        .await?;

    Ok(Json(result))
}

/// Get an NHI request by ID.
#[utoipa::path(
    get,
    path = "/governance/nhis/requests/{request_id}",
    tag = "Governance - NHI Requests",
    params(
        ("request_id" = Uuid, Path, description = "NHI request ID")
    ),
    responses(
        (status = 200, description = "NHI request details", body = NhiRequestResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(request_id): Path<Uuid>,
) -> ApiResult<Json<NhiRequestResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .nhi_request_service
        .get_request(tenant_id, request_id)
        .await?;

    Ok(Json(result))
}

/// Approve an NHI request (creates the NHI).
#[utoipa::path(
    post,
    path = "/governance/nhis/requests/{request_id}/approve",
    tag = "Governance - NHI Requests",
    params(
        ("request_id" = Uuid, Path, description = "NHI request ID")
    ),
    request_body = ApproveNhiRequestRequest,
    responses(
        (status = 200, description = "Request approved, NHI created", body = NhiRequestApprovalResponse),
        (status = 400, description = "Invalid request or already decided"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn approve_nhi_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(request_id): Path<Uuid>,
    Json(body): Json<ApproveNhiRequestRequest>,
) -> ApiResult<Json<NhiRequestApprovalResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let approver_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let request = state
        .nhi_request_service
        .approve_request(tenant_id, request_id, approver_id, body.comments)
        .await?;

    Ok(Json(NhiRequestApprovalResponse { request }))
}

/// Reject an NHI request.
#[utoipa::path(
    post,
    path = "/governance/nhis/requests/{request_id}/reject",
    tag = "Governance - NHI Requests",
    params(
        ("request_id" = Uuid, Path, description = "NHI request ID")
    ),
    request_body = RejectNhiRequestRequest,
    responses(
        (status = 200, description = "Request rejected", body = NhiRequestResponse),
        (status = 400, description = "Invalid request or already decided"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_nhi_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(request_id): Path<Uuid>,
    Json(body): Json<RejectNhiRequestRequest>,
) -> ApiResult<Json<NhiRequestResponse>> {
    body.validate()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let approver_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .nhi_request_service
        .reject_request(tenant_id, request_id, approver_id, body.reason)
        .await?;

    Ok(Json(result))
}

/// Cancel an NHI request (requester only).
#[utoipa::path(
    post,
    path = "/governance/nhis/requests/{request_id}/cancel",
    tag = "Governance - NHI Requests",
    params(
        ("request_id" = Uuid, Path, description = "NHI request ID")
    ),
    responses(
        (status = 200, description = "Request cancelled", body = NhiRequestResponse),
        (status = 400, description = "Invalid request or already decided"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Only requester can cancel"),
        (status = 404, description = "Request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_nhi_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(request_id): Path<Uuid>,
) -> ApiResult<Json<NhiRequestResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .nhi_request_service
        .cancel_request(tenant_id, request_id, user_id)
        .await?;

    Ok(Json(result))
}

/// Get NHI request summary statistics.
#[utoipa::path(
    get,
    path = "/governance/nhis/requests/summary",
    tag = "Governance - NHI Requests",
    responses(
        (status = 200, description = "Request summary statistics", body = NhiRequestSummary),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_nhi_request_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<crate::services::NhiRequestSummary>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .nhi_request_service
        .get_request_summary(tenant_id)
        .await?;

    Ok(Json(result))
}

/// Response when approving an NHI request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct NhiRequestApprovalResponse {
    /// The updated request.
    pub request: NhiRequestResponse,
}
