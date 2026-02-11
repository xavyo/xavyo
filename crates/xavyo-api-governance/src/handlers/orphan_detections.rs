//! Orphan detection handlers for viewing and managing detected orphans.

use axum::{
    extract::{Path, Query, State},
    http::header,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    BulkRemediateRequest, BulkRemediateResponse, DeleteOrphanRequest, DeleteOrphanResponse,
    DisableOrphanRequest, DismissOrphanRequest, ListOrphanDetectionsQuery, OrphanAgeAnalysis,
    OrphanDetectionListResponse, OrphanDetectionResponse, OrphanRiskReport, OrphanSummaryResponse,
    ReassignOrphanRequest,
};
use crate::router::GovernanceState;

/// List orphan detections with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/orphan-detections",
    tag = "Governance - Orphan Detection",
    params(ListOrphanDetectionsQuery),
    responses(
        (status = 200, description = "List of orphan detections", body = OrphanDetectionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_orphan_detections(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListOrphanDetectionsQuery>,
) -> ApiResult<Json<OrphanDetectionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .orphan_detection_service
        .list(tenant_id, &query)
        .await?;

    Ok(Json(result))
}

/// Get orphan detection summary statistics.
#[utoipa::path(
    get,
    path = "/governance/orphan-detections/summary",
    tag = "Governance - Orphan Detection",
    responses(
        (status = 200, description = "Orphan detection summary", body = OrphanSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_orphan_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<OrphanSummaryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state
        .orphan_detection_service
        .get_summary(tenant_id)
        .await?;

    Ok(Json(summary))
}

/// Get a single orphan detection by ID.
#[utoipa::path(
    get,
    path = "/governance/orphan-detections/{id}",
    tag = "Governance - Orphan Detection",
    params(
        ("id" = Uuid, Path, description = "Orphan detection ID")
    ),
    responses(
        (status = 200, description = "Orphan detection details", body = OrphanDetectionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Detection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_orphan_detection(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<OrphanDetectionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let detection = state.orphan_detection_service.get(tenant_id, id).await?;

    Ok(Json(detection))
}

/// Start review of an orphan detection.
#[utoipa::path(
    post,
    path = "/governance/orphan-detections/{id}/review",
    tag = "Governance - Orphan Detection",
    params(
        ("id" = Uuid, Path, description = "Orphan detection ID")
    ),
    responses(
        (status = 200, description = "Review started", body = OrphanDetectionResponse),
        (status = 400, description = "Invalid state for review"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Detection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn start_review(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<OrphanDetectionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let detection = state
        .orphan_detection_service
        .start_review(tenant_id, id)
        .await?;

    Ok(Json(detection))
}

/// Reassign an orphan to a new owner.
#[utoipa::path(
    post,
    path = "/governance/orphan-detections/{id}/reassign",
    tag = "Governance - Orphan Detection",
    params(
        ("id" = Uuid, Path, description = "Orphan detection ID")
    ),
    request_body = ReassignOrphanRequest,
    responses(
        (status = 200, description = "Orphan reassigned", body = OrphanDetectionResponse),
        (status = 400, description = "Invalid request or state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Detection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reassign_orphan(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ReassignOrphanRequest>,
) -> ApiResult<Json<OrphanDetectionResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let detection = state
        .orphan_detection_service
        .reassign(tenant_id, id, request.new_owner_id, user_id, request.notes)
        .await?;

    Ok(Json(detection))
}

/// Disable an orphan account.
#[utoipa::path(
    post,
    path = "/governance/orphan-detections/{id}/disable",
    tag = "Governance - Orphan Detection",
    params(
        ("id" = Uuid, Path, description = "Orphan detection ID")
    ),
    request_body = DisableOrphanRequest,
    responses(
        (status = 200, description = "Account disabled", body = OrphanDetectionResponse),
        (status = 400, description = "Invalid state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Detection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_orphan(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<DisableOrphanRequest>,
) -> ApiResult<Json<OrphanDetectionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let detection = state
        .orphan_detection_service
        .disable(tenant_id, id, user_id, request.notes)
        .await?;

    Ok(Json(detection))
}

/// Request deletion of an orphan account.
#[utoipa::path(
    post,
    path = "/governance/orphan-detections/{id}/delete",
    tag = "Governance - Orphan Detection",
    params(
        ("id" = Uuid, Path, description = "Orphan detection ID")
    ),
    request_body = DeleteOrphanRequest,
    responses(
        (status = 200, description = "Deletion requested", body = DeleteOrphanResponse),
        (status = 400, description = "Invalid request or state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Detection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_orphan(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<DeleteOrphanRequest>,
) -> ApiResult<Json<DeleteOrphanResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let (detection, requires_approval, access_request_id) = state
        .orphan_detection_service
        .request_delete(tenant_id, id, user_id, request.justification)
        .await?;

    Ok(Json(DeleteOrphanResponse {
        detection,
        requires_approval,
        access_request_id,
    }))
}

/// Dismiss an orphan detection as false positive.
#[utoipa::path(
    post,
    path = "/governance/orphan-detections/{id}/dismiss",
    tag = "Governance - Orphan Detection",
    params(
        ("id" = Uuid, Path, description = "Orphan detection ID")
    ),
    request_body = DismissOrphanRequest,
    responses(
        (status = 200, description = "Detection dismissed", body = OrphanDetectionResponse),
        (status = 400, description = "Invalid request or state"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Detection not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn dismiss_orphan(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<DismissOrphanRequest>,
) -> ApiResult<Json<OrphanDetectionResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let detection = state
        .orphan_detection_service
        .dismiss(tenant_id, id, user_id, request.justification)
        .await?;

    Ok(Json(detection))
}

/// Bulk remediate multiple orphan detections.
#[utoipa::path(
    post,
    path = "/governance/orphan-detections/bulk-remediate",
    tag = "Governance - Orphan Detection",
    request_body = BulkRemediateRequest,
    responses(
        (status = 200, description = "Bulk remediation results", body = BulkRemediateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn bulk_remediate(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BulkRemediateRequest>,
) -> ApiResult<Json<BulkRemediateResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .orphan_detection_service
        .bulk_remediate(
            tenant_id,
            request.detection_ids,
            request.action,
            user_id,
            request.justification,
            request.new_owner_id,
        )
        .await?;

    Ok(Json(result))
}

/// Get age analysis for orphan detections.
#[utoipa::path(
    get,
    path = "/governance/orphan-detections/age-analysis",
    tag = "Governance - Orphan Detection",
    responses(
        (status = 200, description = "Orphan age analysis", body = OrphanAgeAnalysis),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_age_analysis(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<OrphanAgeAnalysis>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let analysis = state
        .orphan_detection_service
        .get_age_analysis(tenant_id)
        .await?;

    Ok(Json(analysis))
}

/// Get risk report for orphan accounts.
#[utoipa::path(
    get,
    path = "/governance/orphan-detections/risk-report",
    tag = "Governance - Orphan Detection",
    responses(
        (status = 200, description = "Orphan risk report", body = OrphanRiskReport),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_risk_report(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<OrphanRiskReport>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let report = state
        .orphan_detection_service
        .get_risk_report(tenant_id)
        .await?;

    Ok(Json(report))
}

/// Export orphan detections to CSV.
#[utoipa::path(
    get,
    path = "/governance/orphan-detections/export",
    tag = "Governance - Orphan Detection",
    responses(
        (status = 200, description = "CSV export of orphan detections", content_type = "text/csv"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn export_orphans_csv(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<impl IntoResponse, ApiGovernanceError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let csv = state.orphan_detection_service.export_csv(tenant_id).await?;

    Ok((
        [
            (header::CONTENT_TYPE, "text/csv"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"orphan-detections.csv\"",
            ),
        ],
        csv,
    ))
}
