//! Report schedule handlers for compliance reporting.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateReportScheduleRequest, ListSchedulesQuery, ReportScheduleListResponse,
    ReportScheduleResponse, UpdateReportScheduleRequest,
};
use crate::router::GovernanceState;

/// List report schedules with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/reports/schedules",
    tag = "Governance - Compliance Reporting",
    params(ListSchedulesQuery),
    responses(
        (status = 200, description = "List of report schedules", body = ReportScheduleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_schedules(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSchedulesQuery>,
) -> ApiResult<Json<ReportScheduleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let (schedules, total) = state
        .report_schedule_service
        .list(tenant_id, query.template_id, query.status, limit, offset)
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(ReportScheduleListResponse {
        items: schedules.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get a report schedule by ID.
#[utoipa::path(
    get,
    path = "/governance/reports/schedules/{id}",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Schedule ID")
    ),
    responses(
        (status = 200, description = "Schedule details", body = ReportScheduleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schedule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_schedule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ReportScheduleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let schedule = state.report_schedule_service.get(tenant_id, id).await?;

    Ok(Json(schedule.into()))
}

/// Create a new report schedule.
#[utoipa::path(
    post,
    path = "/governance/reports/schedules",
    tag = "Governance - Compliance Reporting",
    request_body = CreateReportScheduleRequest,
    responses(
        (status = 201, description = "Schedule created", body = ReportScheduleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 409, description = "Schedule name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_schedule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateReportScheduleRequest>,
) -> ApiResult<(StatusCode, Json<ReportScheduleResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let schedule = state
        .report_schedule_service
        .create(
            tenant_id,
            request.template_id,
            request.name,
            request.frequency,
            request.schedule_hour,
            request.schedule_day_of_week,
            request.schedule_day_of_month,
            request.parameters,
            request.recipients,
            request.output_format,
            user_id,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(schedule.into())))
}

/// Update a report schedule.
#[utoipa::path(
    put,
    path = "/governance/reports/schedules/{id}",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Schedule ID")
    ),
    request_body = UpdateReportScheduleRequest,
    responses(
        (status = 200, description = "Schedule updated", body = ReportScheduleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schedule not found"),
        (status = 409, description = "Schedule name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_schedule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateReportScheduleRequest>,
) -> ApiResult<Json<ReportScheduleResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let schedule = state
        .report_schedule_service
        .update(
            tenant_id,
            id,
            request.name,
            request.frequency,
            request.schedule_hour,
            request.schedule_day_of_week,
            request.schedule_day_of_month,
            request.parameters,
            request.recipients,
            request.output_format,
        )
        .await?;

    Ok(Json(schedule.into()))
}

/// Delete a report schedule.
#[utoipa::path(
    delete,
    path = "/governance/reports/schedules/{id}",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Schedule ID")
    ),
    responses(
        (status = 204, description = "Schedule deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schedule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_schedule(
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

    state.report_schedule_service.delete(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Pause a report schedule.
#[utoipa::path(
    post,
    path = "/governance/reports/schedules/{id}/pause",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Schedule ID")
    ),
    responses(
        (status = 200, description = "Schedule paused", body = ReportScheduleResponse),
        (status = 400, description = "Schedule already paused"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schedule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn pause_schedule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ReportScheduleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let schedule = state.report_schedule_service.pause(tenant_id, id).await?;

    Ok(Json(schedule.into()))
}

/// Resume a paused report schedule.
#[utoipa::path(
    post,
    path = "/governance/reports/schedules/{id}/resume",
    tag = "Governance - Compliance Reporting",
    params(
        ("id" = Uuid, Path, description = "Schedule ID")
    ),
    responses(
        (status = 200, description = "Schedule resumed", body = ReportScheduleResponse),
        (status = 400, description = "Schedule already active"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schedule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn resume_schedule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ReportScheduleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let schedule = state.report_schedule_service.resume(tenant_id, id).await?;

    Ok(Json(schedule.into()))
}

/// Trigger due schedules (for scheduler jobs).
///
/// This endpoint finds all schedules that are due to run and executes them.
/// Each scheduled report is created and then fully generated (data collection + export).
#[utoipa::path(
    post,
    path = "/governance/reports/schedules/trigger-due",
    tag = "Governance - Compliance Reporting",
    responses(
        (status = 200, description = "Due schedules triggered", body = TriggerDueResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_due_schedules(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<TriggerDueResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Get due schedules
    let due_schedules = state.report_schedule_service.list_due(tenant_id).await?;

    let mut triggered_count = 0;
    let mut errors = Vec::new();

    // Trigger each due schedule
    for schedule in due_schedules {
        // Step 1: Create the report record in pending status
        let report_result = state
            .report_service
            .generate(
                tenant_id,
                schedule.template_id,
                Some(format!("{} - Scheduled", schedule.name)),
                Some(schedule.parameters.clone()),
                schedule.output_format,
                user_id,
                Some(schedule.id),
            )
            .await;

        match report_result {
            Ok(report) => {
                // Step 2: Execute the report generation
                match state
                    .report_generator_service
                    .execute_generation(tenant_id, report.id)
                    .await
                {
                    Ok(_) => {
                        triggered_count += 1;
                        // Record success in schedule
                        let _ = state
                            .report_schedule_service
                            .record_success(tenant_id, schedule.id)
                            .await;
                    }
                    Err(e) => {
                        errors.push(format!("Schedule {} generation: {}", schedule.id, e));
                        // Record failure in schedule
                        let _ = state
                            .report_schedule_service
                            .record_failure(tenant_id, schedule.id, e.to_string())
                            .await;
                    }
                }
            }
            Err(e) => {
                errors.push(format!("Schedule {} creation: {}", schedule.id, e));
                // Record failure
                let _ = state
                    .report_schedule_service
                    .record_failure(tenant_id, schedule.id, e.to_string())
                    .await;
            }
        }
    }

    Ok(Json(TriggerDueResponse {
        triggered_count,
        errors,
    }))
}

/// Response for trigger due operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TriggerDueResponse {
    pub triggered_count: i64,
    pub errors: Vec<String>,
}
