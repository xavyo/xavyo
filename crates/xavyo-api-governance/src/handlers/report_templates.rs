//! Report template handlers for compliance reporting.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CloneReportTemplateRequest, CreateReportTemplateRequest, ListTemplatesQuery,
    ReportTemplateListResponse, ReportTemplateResponse, UpdateReportTemplateRequest,
};
use crate::router::GovernanceState;

/// List report templates with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/reports/templates",
    tag = "Governance - Compliance Reporting",
    params(ListTemplatesQuery),
    responses(
        (status = 200, description = "List of report templates", body = ReportTemplateListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_templates(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListTemplatesQuery>,
) -> ApiResult<Json<ReportTemplateListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (templates, total) = state
        .report_template_service
        .list(
            tenant_id,
            query.template_type,
            query.compliance_standard,
            query.include_system,
            limit,
            offset,
        )
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(ReportTemplateListResponse {
        items: templates.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get a report template by ID.
#[utoipa::path(
    get,
    path = "/governance/reports/templates/{id}",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "Template details", body = ReportTemplateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ReportTemplateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let template = state.report_template_service.get(tenant_id, id).await?;

    Ok(Json(template.into()))
}

/// Create a new custom report template.
#[utoipa::path(
    post,
    path = "/governance/reports/templates",
    tag = "Governance - Compliance Reporting",
    request_body = CreateReportTemplateRequest,
    responses(
        (status = 201, description = "Template created", body = ReportTemplateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Template name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateReportTemplateRequest>,
) -> ApiResult<(StatusCode, Json<ReportTemplateResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let template = state
        .report_template_service
        .create(
            tenant_id,
            request.name,
            request.description,
            request.template_type,
            request.compliance_standard,
            request.definition,
            user_id,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(template.into())))
}

/// Clone a report template.
#[utoipa::path(
    post,
    path = "/governance/reports/templates/{id}/clone",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Source template ID")
    ),
    request_body = CloneReportTemplateRequest,
    responses(
        (status = 201, description = "Template cloned", body = ReportTemplateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Source template not found"),
        (status = 409, description = "Template name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn clone_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<CloneReportTemplateRequest>,
) -> ApiResult<(StatusCode, Json<ReportTemplateResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let template = state
        .report_template_service
        .clone_template(tenant_id, id, request.name, request.description, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(template.into())))
}

/// Update a custom report template.
#[utoipa::path(
    put,
    path = "/governance/reports/templates/{id}",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Template ID")
    ),
    request_body = UpdateReportTemplateRequest,
    responses(
        (status = 200, description = "Template updated", body = ReportTemplateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot modify system template"),
        (status = 404, description = "Template not found"),
        (status = 409, description = "Template name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateReportTemplateRequest>,
) -> ApiResult<Json<ReportTemplateResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let template = state
        .report_template_service
        .update(
            tenant_id,
            id,
            request.name,
            request.description,
            request.definition,
        )
        .await?;

    Ok(Json(template.into()))
}

/// Archive (soft-delete) a custom report template.
#[utoipa::path(
    delete,
    path = "/governance/reports/templates/{id}",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "Template archived", body = ReportTemplateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot archive system template"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn archive_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ReportTemplateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let template = state.report_template_service.archive(tenant_id, id).await?;

    Ok(Json(template.into()))
}
