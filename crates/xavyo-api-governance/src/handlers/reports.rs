//! Report handlers for compliance reporting.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    GenerateReportRequest, GeneratedReportListResponse, GeneratedReportResponse, ListReportsQuery,
};
use crate::router::GovernanceState;

/// List generated reports with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/reports",
    tag = "Governance - Compliance Reporting",
    params(ListReportsQuery),
    responses(
        (status = 200, description = "List of generated reports", body = GeneratedReportListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_reports(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListReportsQuery>,
) -> ApiResult<Json<GeneratedReportListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (reports, total) = state
        .report_service
        .list(
            tenant_id,
            query.template_id,
            query.status,
            query.from_date,
            query.to_date,
            limit,
            offset,
        )
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(GeneratedReportListResponse {
        items: reports.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get a generated report by ID.
#[utoipa::path(
    get,
    path = "/governance/reports/{id}",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Report ID")
    ),
    responses(
        (status = 200, description = "Report details", body = GeneratedReportResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Report not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_report(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<GeneratedReportResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let report = state.report_service.get(tenant_id, id).await?;

    Ok(Json(report.into()))
}

/// Generate a new report.
///
/// This endpoint creates a report record in "pending" status, then immediately
/// executes the report generation process. The response includes the completed
/// (or failed) report with generated data.
#[utoipa::path(
    post,
    path = "/governance/reports/generate",
    tag = "Governance - Compliance Reporting",
    request_body = GenerateReportRequest,
    responses(
        (status = 201, description = "Report generated successfully", body = GeneratedReportResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn generate_report(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<GenerateReportRequest>,
) -> ApiResult<(StatusCode, Json<GeneratedReportResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Create the report record in pending status
    let report = state
        .report_service
        .generate(
            tenant_id,
            request.template_id,
            request.name,
            request.parameters,
            request.output_format,
            user_id,
            None, // Not scheduled
        )
        .await?;

    // Execute the report generation (synchronous for now)
    // This collects data, formats it, and updates the report status
    let completed_report = state
        .report_generator_service
        .execute_generation(tenant_id, report.id)
        .await?;

    Ok((StatusCode::CREATED, Json(completed_report.into())))
}

/// Get report output data (for completed reports).
#[utoipa::path(
    get,
    path = "/governance/reports/{id}/data",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Report ID")
    ),
    responses(
        (status = 200, description = "Report data", body = serde_json::Value),
        (status = 400, description = "Report not completed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Report not found or no inline data"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_report_data(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let data = state
        .report_service
        .get_output_data(tenant_id, id)
        .await?
        .ok_or_else(|| ApiGovernanceError::NotFound("Report has no inline data".to_string()))?;

    Ok(Json(data))
}

/// Delete a report (only pending/failed reports).
#[utoipa::path(
    delete,
    path = "/governance/reports/{id}",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Report ID")
    ),
    responses(
        (status = 204, description = "Report deleted"),
        (status = 400, description = "Cannot delete completed/generating report"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Report not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_report(
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

    state.report_service.delete(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Delete expired reports.
#[utoipa::path(
    post,
    path = "/governance/reports/cleanup",
    tag = "Governance - Compliance Reporting",
    responses(
        (status = 200, description = "Expired reports deleted", body = CleanupResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cleanup_expired_reports(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<CleanupResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let deleted_count = state.report_service.delete_expired(tenant_id).await?;

    Ok(Json(CleanupResponse { deleted_count }))
}

/// Response for cleanup operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct CleanupResponse {
    pub deleted_count: i64,
}
