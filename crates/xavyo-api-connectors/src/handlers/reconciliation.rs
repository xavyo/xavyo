//! Reconciliation API handlers for F049 Reconciliation Engine.
//!
//! Provides endpoints for triggering, monitoring, and managing reconciliation runs.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

use crate::error::{ApiError, ConnectorApiError};
use crate::router::ReconciliationState;
use crate::services::ReconciliationServiceError;

// ============================================================================
// Request/Response Types for Runs
// ============================================================================

/// Request to trigger a reconciliation run.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TriggerReconciliationRequest {
    /// Mode: "full" or "delta".
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Whether this is a dry run.
    #[serde(default)]
    pub dry_run: bool,
}

fn default_mode() -> String {
    "full".to_string()
}

/// Response for a reconciliation run.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReconciliationRunResponse {
    pub id: Uuid,
    pub connector_id: Uuid,
    pub mode: String,
    pub status: String,
    pub triggered_by: Option<Uuid>,
    pub statistics: ReconciliationStatistics,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Statistics for a reconciliation run.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct ReconciliationStatistics {
    #[serde(default)]
    pub accounts_total: u32,
    #[serde(default)]
    pub accounts_processed: u32,
    #[serde(default)]
    pub discrepancies_found: u32,
    #[serde(default)]
    pub discrepancies_by_type: HashMap<String, u32>,
    #[serde(default)]
    pub actions_taken: u32,
    #[serde(default)]
    pub duration_seconds: u64,
}

/// Query parameters for listing runs.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListRunsQuery {
    pub mode: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for listing runs.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListRunsResponse {
    pub runs: Vec<ReconciliationRunResponse>,
    pub total: i64,
}

// ============================================================================
// Request/Response Types for Discrepancies
// ============================================================================

/// Query parameters for listing discrepancies.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListDiscrepanciesQuery {
    pub run_id: Option<Uuid>,
    pub discrepancy_type: Option<String>,
    pub resolution_status: Option<String>,
    pub identity_id: Option<Uuid>,
    pub external_uid: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for a discrepancy.
#[derive(Debug, Serialize, ToSchema)]
pub struct DiscrepancyResponse {
    pub id: Uuid,
    pub run_id: Uuid,
    pub discrepancy_type: String,
    pub identity_id: Option<Uuid>,
    pub external_uid: String,
    pub mismatched_attributes: Option<serde_json::Value>,
    pub resolution_status: String,
    pub resolved_action: Option<String>,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub detected_at: DateTime<Utc>,
    pub suggested_actions: Vec<String>,
}

/// Response for listing discrepancies.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListDiscrepanciesResponse {
    pub discrepancies: Vec<DiscrepancyResponse>,
    pub total: i64,
}

/// Request to remediate a discrepancy.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RemediateRequest {
    /// Action: create, update, delete, link, unlink, `inactivate_identity`.
    pub action: String,
    /// Direction for update: `xavyo_to_target` or `target_to_xavyo`.
    #[serde(default = "default_direction")]
    pub direction: String,
    /// Identity ID for link action.
    pub identity_id: Option<Uuid>,
    /// Whether this is a dry run.
    #[serde(default)]
    pub dry_run: bool,
}

fn default_direction() -> String {
    "xavyo_to_target".to_string()
}

/// Response for a remediation action.
#[derive(Debug, Serialize, ToSchema)]
pub struct RemediationResponse {
    pub discrepancy_id: Uuid,
    pub action: String,
    pub result: String,
    pub error_message: Option<String>,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub dry_run: bool,
}

/// Request for bulk remediation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkRemediateRequest {
    pub items: Vec<BulkRemediateItem>,
    #[serde(default)]
    pub dry_run: bool,
}

/// Single item in bulk remediation request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkRemediateItem {
    pub discrepancy_id: Uuid,
    pub action: String,
    pub direction: Option<String>,
    pub identity_id: Option<Uuid>,
}

/// Response for bulk remediation.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkRemediationResponse {
    pub results: Vec<RemediationResponse>,
    pub summary: BulkRemediationSummary,
}

/// Summary of bulk remediation.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkRemediationSummary {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
}

// ============================================================================
// Request/Response Types for Preview
// ============================================================================

/// Request for previewing changes.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PreviewRequest {
    pub discrepancy_ids: Vec<Uuid>,
}

/// Response for preview.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewResponse {
    pub items: Vec<PreviewItem>,
    pub summary: PreviewSummary,
}

/// Single item in preview.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PreviewItem {
    pub discrepancy_id: Uuid,
    pub discrepancy_type: String,
    pub suggested_action: String,
    pub would_change: serde_json::Value,
}

/// Summary of preview.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewSummary {
    pub total_actions: usize,
    pub by_action: HashMap<String, usize>,
}

// ============================================================================
// Request/Response Types for Schedules
// ============================================================================

/// Request to create/update a schedule.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ScheduleRequest {
    /// Mode: full or delta.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Frequency: hourly, daily, weekly, monthly, `cron`, or a cron expression.
    pub frequency: String,
    /// Cron expression. Required when `frequency` is `cron`; stored in `frequency`.
    #[serde(default)]
    pub cron_expression: Option<String>,
    /// Day of week (0-6) for weekly schedule.
    pub day_of_week: Option<i32>,
    /// Day of month (1-28) for monthly schedule.
    pub day_of_month: Option<i32>,
    /// Hour of day (0-23 UTC).
    #[serde(default = "default_hour")]
    pub hour_of_day: i32,
    /// Whether enabled. Omitted on update preserves the existing flag.
    #[serde(default)]
    pub enabled: Option<bool>,
}

fn default_hour() -> i32 {
    2
}

/// Resolve the stored frequency. `frequency=cron` requires `cron_expression`.
pub fn resolve_schedule_frequency(
    frequency: &str,
    cron_expression: Option<&str>,
) -> Result<String, String> {
    if frequency.eq_ignore_ascii_case("cron") {
        let expr = cron_expression
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "cron_expression is required when frequency is cron".to_string())?;
        if !expr.contains(' ') {
            return Err("cron_expression must be a cron expression".to_string());
        }
        return Ok(expr.to_string());
    }
    Ok(frequency.to_string())
}

/// Cron expressions are stored in `frequency`; echo them as `cron_expression`.
pub fn advertised_cron_expression(frequency: &str) -> Option<String> {
    frequency.contains(' ').then(|| frequency.to_string())
}

/// Response for a schedule.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScheduleResponse {
    pub id: Uuid,
    pub connector_id: Uuid,
    pub connector_name: Option<String>,
    pub mode: String,
    pub frequency: String,
    pub cron_expression: Option<String>,
    pub day_of_week: Option<i32>,
    pub day_of_month: Option<i32>,
    pub hour_of_day: i32,
    pub enabled: bool,
    pub last_run_id: Option<Uuid>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Build the advertised schedule payload.
pub fn schedule_response(
    schedule: xavyo_db::models::ReconciliationSchedule,
    connector_name: Option<String>,
    last_run_at: Option<DateTime<Utc>>,
) -> ScheduleResponse {
    let cron_expression = advertised_cron_expression(&schedule.frequency);
    ScheduleResponse {
        id: schedule.id,
        connector_id: schedule.connector_id,
        connector_name,
        mode: schedule.mode,
        frequency: schedule.frequency,
        cron_expression,
        day_of_week: schedule.day_of_week,
        day_of_month: schedule.day_of_month,
        hour_of_day: schedule.hour_of_day,
        enabled: schedule.enabled,
        last_run_id: schedule.last_run_id,
        last_run_at,
        next_run_at: schedule.next_run_at,
        created_at: schedule.created_at,
        updated_at: schedule.updated_at,
    }
}

/// Response for listing schedules.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListSchedulesResponse {
    pub schedules: Vec<ScheduleResponse>,
}

// ============================================================================
// Request/Response Types for Reports
// ============================================================================

/// Response for a reconciliation report.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReportResponse {
    pub run: RunInfo,
    pub discrepancy_summary: DiscrepancySummary,
    pub action_summary: ActionSummary,
    pub top_mismatched_attributes: Vec<AttributeMismatchCount>,
    pub performance: PerformanceMetrics,
}

/// Run info for report.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunInfo {
    pub id: Uuid,
    pub connector_id: Uuid,
    pub connector_name: Option<String>,
    pub mode: String,
    pub status: String,
    pub triggered_by: Option<Uuid>,
    pub triggered_by_name: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub statistics: ReconciliationStatistics,
}

/// Discrepancy summary for report.
#[derive(Debug, Serialize, ToSchema)]
pub struct DiscrepancySummary {
    pub total: u32,
    pub by_type: HashMap<String, u32>,
    pub by_resolution: HashMap<String, u32>,
}

/// Action summary for report.
#[derive(Debug, Serialize, ToSchema)]
pub struct ActionSummary {
    pub total: u32,
    pub by_type: HashMap<String, u32>,
    pub by_result: HashMap<String, u32>,
}

/// Attribute mismatch count.
#[derive(Debug, Serialize, ToSchema)]
pub struct AttributeMismatchCount {
    pub attribute: String,
    pub count: u32,
}

/// Performance metrics.
#[derive(Debug, Serialize, ToSchema)]
pub struct PerformanceMetrics {
    pub accounts_per_second: f64,
    pub total_duration_seconds: u64,
}

/// Query parameters for trend data.
#[derive(Debug, Deserialize, IntoParams)]
pub struct TrendQuery {
    pub connector_id: Option<Uuid>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

/// Response for trend data.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrendResponse {
    pub data_points: Vec<TrendDataPoint>,
    pub connector_id: Option<Uuid>,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

/// Single data point in trend.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrendDataPoint {
    pub date: String,
    pub total: u32,
    pub by_type: HashMap<String, u32>,
}

// ============================================================================
// Request/Response Types for Actions (Audit Log)
// ============================================================================

/// Query parameters for listing actions.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListActionsQuery {
    pub discrepancy_id: Option<Uuid>,
    pub action_type: Option<String>,
    pub result: Option<String>,
    pub dry_run: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for an action.
#[derive(Debug, Serialize, ToSchema)]
pub struct ActionResponse {
    pub id: Uuid,
    pub discrepancy_id: Uuid,
    pub action_type: String,
    pub executed_by: Uuid,
    pub result: String,
    pub error_message: Option<String>,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub dry_run: bool,
    pub executed_at: DateTime<Utc>,
}

/// Response for listing actions.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListActionsResponse {
    pub actions: Vec<ActionResponse>,
    pub total: i64,
}

// ============================================================================
// Handler Implementations - Runs
// ============================================================================

/// Trigger a reconciliation run.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/reconciliation/trigger",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = TriggerReconciliationRequest,
    responses(
        (status = 202, description = "Reconciliation run triggered", body = ReconciliationRunResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn trigger_reconciliation(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    publisher: Option<Extension<EventPublisher>>,
    Path(connector_id): Path<Uuid>,
    Json(request): Json<TriggerReconciliationRequest>,
) -> Result<(StatusCode, Json<ReconciliationRunResponse>), ApiError> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = Some(extract_user_id(&claims)?);

    let run = state
        .reconciliation_service
        .trigger_run(
            tenant_id,
            actor_id,
            connector_id,
            &request.mode,
            request.dry_run,
        )
        .await
        .map_err(map_reconciliation_error)?;

    let stats = parse_run_statistics(run.statistics.clone())?;

    // A newly persisted run is queued, not finished. Do not advertise
    // reconciliation.completed until the worker actually completes it.
    if run.status == "completed" {
        if let Some(Extension(publisher)) = publisher {
            publisher.publish(WebhookEvent {
                event_id: Uuid::new_v4(),
                event_type: "reconciliation.completed".to_string(),
                tenant_id,
                actor_id,
                timestamp: chrono::Utc::now(),
                data: serde_json::json!({
                    "run_id": run.id,
                    "connector_id": connector_id,
                    "mode": run.mode,
                    "status": run.status,
                }),
            });
        }
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(ReconciliationRunResponse {
            id: run.id,
            connector_id: run.connector_id,
            mode: run.mode,
            status: run.status,
            triggered_by: run.triggered_by,
            statistics: stats,
            error_message: run.error_message,
            started_at: run.started_at,
            completed_at: run.completed_at,
            created_at: run.created_at,
        }),
    ))
}

/// Get a reconciliation run by ID.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/reconciliation/runs/{run_id}",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("run_id" = Uuid, Path, description = "Reconciliation run ID")
    ),
    responses(
        (status = 200, description = "Reconciliation run details", body = ReconciliationRunResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Run not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_reconciliation_run(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ReconciliationRunResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let run = state
        .reconciliation_service
        .get_run(tenant_id, connector_id, run_id)
        .await
        .map_err(map_reconciliation_error)?
        .ok_or_else(|| ApiError::not_found("Reconciliation run not found"))?;

    let stats = parse_run_statistics(run.statistics.clone())?;

    Ok(Json(ReconciliationRunResponse {
        id: run.id,
        connector_id: run.connector_id,
        mode: run.mode,
        status: run.status,
        triggered_by: run.triggered_by,
        statistics: stats,
        error_message: run.error_message,
        started_at: run.started_at,
        completed_at: run.completed_at,
        created_at: run.created_at,
    }))
}

/// List reconciliation runs.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/reconciliation/runs",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ListRunsQuery
    ),
    responses(
        (status = 200, description = "List of reconciliation runs", body = ListRunsResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_reconciliation_runs(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Query(query): Query<ListRunsQuery>,
) -> Result<Json<ListRunsResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let mode = parse_optional_recon_mode(query.mode.as_deref())?;
    let status = parse_optional_recon_status(query.status.as_deref())?;
    let (runs, total) = state
        .reconciliation_service
        .list_runs(
            tenant_id,
            connector_id,
            mode,
            status,
            query.limit.unwrap_or(50).min(100),
            query.offset.unwrap_or(0).max(0),
        )
        .await
        .map_err(map_reconciliation_error)?;

    let runs: Vec<ReconciliationRunResponse> = runs
        .into_iter()
        .map(|run| {
            let stats = parse_run_statistics(run.statistics.clone())?;
            Ok(ReconciliationRunResponse {
                id: run.id,
                connector_id: run.connector_id,
                mode: run.mode,
                status: run.status,
                triggered_by: run.triggered_by,
                statistics: stats,
                error_message: run.error_message,
                started_at: run.started_at,
                completed_at: run.completed_at,
                created_at: run.created_at,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    Ok(Json(ListRunsResponse { runs, total }))
}

/// Cancel a reconciliation run.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/reconciliation/runs/{run_id}/cancel",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("run_id" = Uuid, Path, description = "Reconciliation run ID")
    ),
    responses(
        (status = 204, description = "Run cancelled"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Run not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn cancel_reconciliation_run(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .reconciliation_service
        .cancel_run(tenant_id, connector_id, run_id)
        .await
        .map_err(map_reconciliation_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Resume a failed/cancelled reconciliation run.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/reconciliation/runs/{run_id}/resume",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("run_id" = Uuid, Path, description = "Reconciliation run ID")
    ),
    responses(
        (status = 200, description = "Run resumed", body = ReconciliationRunResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Run not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn resume_reconciliation_run(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ReconciliationRunResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let run = state
        .reconciliation_service
        .resume_run(tenant_id, connector_id, run_id)
        .await
        .map_err(map_reconciliation_error)?;

    let stats = parse_run_statistics(run.statistics.clone())?;

    Ok(Json(ReconciliationRunResponse {
        id: run.id,
        connector_id: run.connector_id,
        mode: run.mode,
        status: run.status,
        triggered_by: run.triggered_by,
        statistics: stats,
        error_message: run.error_message,
        started_at: run.started_at,
        completed_at: run.completed_at,
        created_at: run.created_at,
    }))
}

// ============================================================================
// Handler Implementations - Discrepancies
// ============================================================================

/// List discrepancies.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/reconciliation/discrepancies",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ListDiscrepanciesQuery
    ),
    responses(
        (status = 200, description = "List of discrepancies", body = ListDiscrepanciesResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_discrepancies(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Query(query): Query<ListDiscrepanciesQuery>,
) -> Result<Json<ListDiscrepanciesResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let discrepancy_type = parse_optional_discrepancy_type(query.discrepancy_type.as_deref())?;
    let resolution_status = parse_optional_resolution_status(query.resolution_status.as_deref())?;
    let (discrepancies, total) = state
        .reconciliation_service
        .list_discrepancies(
            tenant_id,
            connector_id,
            query.run_id,
            discrepancy_type,
            resolution_status,
            query.identity_id,
            query.external_uid.as_deref(),
            query.limit.unwrap_or(50).min(100),
            query.offset.unwrap_or(0).max(0),
        )
        .await
        .map_err(map_reconciliation_error)?;

    let discrepancies: Vec<DiscrepancyResponse> = discrepancies
        .into_iter()
        .map(|d| {
            Ok(DiscrepancyResponse {
                id: d.id,
                run_id: d.run_id,
                discrepancy_type: d.discrepancy_type.clone(),
                identity_id: d.identity_id,
                external_uid: d.external_uid,
                mismatched_attributes: d.mismatched_attributes,
                resolution_status: d.resolution_status,
                resolved_action: d.resolved_action,
                resolved_by: d.resolved_by,
                resolved_at: d.resolved_at,
                detected_at: d.detected_at,
                suggested_actions: get_suggested_actions(&d.discrepancy_type)?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    Ok(Json(ListDiscrepanciesResponse {
        discrepancies,
        total,
    }))
}

/// Get a discrepancy by ID.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/reconciliation/discrepancies/{discrepancy_id}",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("discrepancy_id" = Uuid, Path, description = "Discrepancy ID")
    ),
    responses(
        (status = 200, description = "Discrepancy details", body = DiscrepancyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Discrepancy not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_discrepancy(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, discrepancy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DiscrepancyResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let d = state
        .reconciliation_service
        .get_discrepancy(tenant_id, connector_id, discrepancy_id)
        .await
        .map_err(map_reconciliation_error)?
        .ok_or_else(|| ApiError::not_found("Discrepancy not found"))?;

    Ok(Json(DiscrepancyResponse {
        id: d.id,
        run_id: d.run_id,
        discrepancy_type: d.discrepancy_type.clone(),
        identity_id: d.identity_id,
        external_uid: d.external_uid,
        mismatched_attributes: d.mismatched_attributes,
        resolution_status: d.resolution_status,
        resolved_action: d.resolved_action,
        resolved_by: d.resolved_by,
        resolved_at: d.resolved_at,
        detected_at: d.detected_at,
        suggested_actions: get_suggested_actions(&d.discrepancy_type)?,
    }))
}

/// Remediate a discrepancy.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/reconciliation/discrepancies/{discrepancy_id}/remediate",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("discrepancy_id" = Uuid, Path, description = "Discrepancy ID")
    ),
    request_body = RemediateRequest,
    responses(
        (status = 501, description = "Connector-side remediation is not implemented"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Discrepancy not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn remediate_discrepancy(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, discrepancy_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RemediateRequest>,
) -> Result<Json<RemediationResponse>, ApiError> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = Some(extract_user_id(&claims)?);

    let result = state
        .reconciliation_service
        .remediate(
            tenant_id,
            user_id,
            connector_id,
            discrepancy_id,
            &request.action,
            &request.direction,
            request.identity_id,
            request.dry_run,
        )
        .await
        .map_err(map_reconciliation_error)?;

    Ok(Json(result))
}

/// Bulk remediate discrepancies.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/reconciliation/discrepancies/bulk-remediate",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = BulkRemediateRequest,
    responses(
        (status = 501, description = "Connector-side remediation is not implemented"),
        (status = 400, description = "Invalid request (e.g., too many items)"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn bulk_remediate_discrepancies(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Json(request): Json<BulkRemediateRequest>,
) -> Result<Json<BulkRemediationResponse>, ApiError> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = Some(extract_user_id(&claims)?);

    // Limit to 100 items
    if request.items.len() > 100 {
        return Err(ApiError::bad_request(
            "Maximum 100 items allowed in bulk remediation",
        ));
    }

    let result = state
        .reconciliation_service
        .bulk_remediate(
            tenant_id,
            user_id,
            connector_id,
            request.items,
            request.dry_run,
        )
        .await
        .map_err(map_reconciliation_error)?;

    Ok(Json(result))
}

/// Ignore a discrepancy.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/reconciliation/discrepancies/{discrepancy_id}/ignore",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("discrepancy_id" = Uuid, Path, description = "Discrepancy ID")
    ),
    responses(
        (status = 204, description = "Discrepancy ignored"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Discrepancy not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn ignore_discrepancy(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, discrepancy_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = Some(extract_user_id(&claims)?);

    state
        .reconciliation_service
        .ignore_discrepancy(tenant_id, user_id, connector_id, discrepancy_id)
        .await
        .map_err(map_reconciliation_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Preview remediation changes.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/reconciliation/discrepancies/preview",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = PreviewRequest,
    responses(
        (status = 200, description = "Preview of remediation changes", body = PreviewResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn preview_remediation(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Json(request): Json<PreviewRequest>,
) -> Result<Json<PreviewResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let result = state
        .reconciliation_service
        .preview(tenant_id, connector_id, request.discrepancy_ids)
        .await
        .map_err(map_reconciliation_error)?;

    Ok(Json(result))
}

// ============================================================================
// Handler Implementations - Schedules
// ============================================================================

/// Get schedule for a connector.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/reconciliation/schedule",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Schedule configuration", body = ScheduleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schedule not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_schedule(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<Json<ScheduleResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let schedule = state
        .reconciliation_service
        .get_schedule(tenant_id, connector_id)
        .await
        .map_err(map_reconciliation_error)?
        .ok_or_else(|| ApiError::not_found("Schedule not found"))?;

    Ok(Json(
        state
            .reconciliation_service
            .to_schedule_response(tenant_id, schedule)
            .await
            .map_err(map_reconciliation_error)?,
    ))
}

/// Update schedule for a connector.
#[utoipa::path(
    put,
    path = "/connectors/{connector_id}/reconciliation/schedule",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = ScheduleRequest,
    responses(
        (status = 200, description = "Schedule updated", body = ScheduleResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn update_schedule(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Json(request): Json<ScheduleRequest>,
) -> Result<Json<ScheduleResponse>, ApiError> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let frequency =
        resolve_schedule_frequency(&request.frequency, request.cron_expression.as_deref())
            .map_err(ApiError::bad_request)?;

    let schedule = state
        .reconciliation_service
        .upsert_schedule(
            tenant_id,
            connector_id,
            &request.mode,
            &frequency,
            request.day_of_week,
            request.day_of_month,
            request.hour_of_day,
            request.enabled,
        )
        .await
        .map_err(map_reconciliation_error)?;

    Ok(Json(
        state
            .reconciliation_service
            .to_schedule_response(tenant_id, schedule)
            .await
            .map_err(map_reconciliation_error)?,
    ))
}

/// Delete schedule for a connector.
#[utoipa::path(
    delete,
    path = "/connectors/{connector_id}/reconciliation/schedule",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Schedule deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schedule not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn delete_schedule(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .reconciliation_service
        .delete_schedule(tenant_id, connector_id)
        .await
        .map_err(map_reconciliation_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable schedule.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/reconciliation/schedule/enable",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Schedule enabled"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schedule not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn enable_schedule(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .reconciliation_service
        .enable_schedule(tenant_id, connector_id)
        .await
        .map_err(map_reconciliation_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Disable schedule.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/reconciliation/schedule/disable",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Schedule disabled"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schedule not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn disable_schedule(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .reconciliation_service
        .disable_schedule(tenant_id, connector_id)
        .await
        .map_err(map_reconciliation_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// List all schedules.
#[utoipa::path(
    get,
    path = "/reconciliation/schedules",
    tag = "Connector Reconciliation",
    responses(
        (status = 200, description = "List of all schedules", body = ListSchedulesResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_schedules(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<ListSchedulesResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let schedules = state
        .reconciliation_service
        .list_schedules(tenant_id)
        .await
        .map_err(map_reconciliation_error)?;

    let mut responses = Vec::with_capacity(schedules.len());
    for schedule in schedules {
        responses.push(
            state
                .reconciliation_service
                .to_schedule_response(tenant_id, schedule)
                .await
                .map_err(map_reconciliation_error)?,
        );
    }

    Ok(Json(ListSchedulesResponse {
        schedules: responses,
    }))
}

// ============================================================================
// Handler Implementations - Reports
// ============================================================================

/// Get report for a reconciliation run.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/reconciliation/runs/{run_id}/report",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("run_id" = Uuid, Path, description = "Reconciliation run ID")
    ),
    responses(
        (status = 200, description = "Reconciliation report", body = ReportResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Run not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_report(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ReportResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let report = state
        .reconciliation_service
        .get_report(tenant_id, connector_id, run_id)
        .await
        .map_err(map_reconciliation_error)?;

    Ok(Json(report))
}

/// Get discrepancy trend data.
#[utoipa::path(
    get,
    path = "/reconciliation/trend",
    tag = "Connector Reconciliation",
    params(TrendQuery),
    responses(
        (status = 200, description = "Trend data", body = TrendResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_trend(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<TrendQuery>,
) -> Result<Json<TrendResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let trend = state
        .reconciliation_service
        .get_trend(tenant_id, query.connector_id, query.from, query.to)
        .await
        .map_err(map_reconciliation_error)?;

    Ok(Json(trend))
}

// ============================================================================
// Handler Implementations - Actions (Audit Log)
// ============================================================================

/// List actions.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/reconciliation/actions",
    tag = "Connector Reconciliation",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ListActionsQuery
    ),
    responses(
        (status = 200, description = "List of remediation actions", body = ListActionsResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_actions(
    State(state): State<ReconciliationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Query(query): Query<ListActionsQuery>,
) -> Result<Json<ListActionsResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let action_type = parse_optional_action_type(query.action_type.as_deref())?;
    let result = parse_optional_action_result(query.result.as_deref())?;
    let (actions, total) = state
        .reconciliation_service
        .list_actions(
            tenant_id,
            connector_id,
            query.discrepancy_id,
            action_type,
            result,
            query.dry_run,
            query.limit.unwrap_or(50).min(100),
            query.offset.unwrap_or(0).max(0),
        )
        .await
        .map_err(map_reconciliation_error)?;

    let actions: Vec<ActionResponse> = actions
        .into_iter()
        .map(|a| ActionResponse {
            id: a.id,
            discrepancy_id: a.discrepancy_id,
            action_type: a.action_type,
            executed_by: a.executed_by,
            result: a.result,
            error_message: a.error_message,
            before_state: a.before_state,
            after_state: a.after_state,
            dry_run: a.dry_run,
            executed_at: a.executed_at,
        })
        .collect();

    Ok(Json(ListActionsResponse { actions, total }))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract tenant ID from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiError> {
    claims
        .tenant_id()
        .map(|tid| *tid.as_uuid())
        .ok_or(ConnectorApiError::Unauthorized {
            message: "Missing tenant ID in token".to_string(),
        })
}

fn extract_user_id(claims: &JwtClaims) -> Result<Uuid, ApiError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ConnectorApiError::Unauthorized {
        message: "Invalid user ID in claims".to_string(),
    })
}

/// Invalid reconciliation status filters must not silently list every run.
fn parse_optional_recon_status(status: Option<&str>) -> Result<Option<&str>, ApiError> {
    match status {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "pending" | "running" | "completed" | "failed" | "cancelled") => {
            Ok(Some(s))
        }
        Some(s) => Err(ApiError::bad_request(format!(
            "Invalid reconciliation status '{s}'. Must be one of: pending, running, completed, failed, cancelled"
        ))),
    }
}

/// Invalid reconciliation mode filters must not silently list every run.
fn parse_optional_recon_mode(mode: Option<&str>) -> Result<Option<&str>, ApiError> {
    match mode {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "full" | "delta") => Ok(Some(s)),
        Some(s) => Err(ApiError::bad_request(format!(
            "Invalid reconciliation mode '{s}'. Must be one of: full, delta"
        ))),
    }
}

fn parse_optional_discrepancy_type(value: Option<&str>) -> Result<Option<&str>, ApiError> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s)
            if matches!(
                s,
                "missing" | "orphan" | "mismatch" | "collision" | "unlinked" | "deleted"
            ) =>
        {
            Ok(Some(s))
        }
        Some(s) => Err(ApiError::bad_request(format!(
            "Invalid discrepancy type '{s}'. Must be one of: missing, orphan, mismatch, collision, unlinked, deleted"
        ))),
    }
}

fn parse_optional_resolution_status(value: Option<&str>) -> Result<Option<&str>, ApiError> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "pending" | "resolved" | "ignored") => Ok(Some(s)),
        Some(s) => Err(ApiError::bad_request(format!(
            "Invalid resolution status '{s}'. Must be one of: pending, resolved, ignored"
        ))),
    }
}

fn parse_optional_action_type(value: Option<&str>) -> Result<Option<&str>, ApiError> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s)
            if matches!(
                s,
                "create"
                    | "update"
                    | "delete"
                    | "link"
                    | "unlink"
                    | "inactivate_identity"
                    | "create_identity"
                    | "delete_identity"
            ) =>
        {
            Ok(Some(s))
        }
        Some(s) => Err(ApiError::bad_request(format!(
            "Invalid action type '{s}'. Must be one of: create, update, delete, link, unlink, inactivate_identity, create_identity, delete_identity"
        ))),
    }
}

fn parse_optional_action_result(value: Option<&str>) -> Result<Option<&str>, ApiError> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "success" | "failure") => Ok(Some(s)),
        Some(s) => Err(ApiError::bad_request(format!(
            "Invalid action result '{s}'. Must be one of: success, failure"
        ))),
    }
}

/// Map reconciliation service errors to API errors with proper status codes.
fn parse_run_statistics(value: serde_json::Value) -> Result<ReconciliationStatistics, ApiError> {
    serde_json::from_value(value)
        .map_err(|e| ApiError::bad_request(format!("Invalid reconciliation statistics JSON: {e}")))
}

fn map_reconciliation_error(err: ReconciliationServiceError) -> ApiError {
    match err {
        ReconciliationServiceError::NotFound(msg) => ApiError::not_found(msg),
        ReconciliationServiceError::InvalidParameter(msg) => ApiError::bad_request(msg),
        ReconciliationServiceError::Conflict(msg) => ApiError::conflict(msg),
        ReconciliationServiceError::Database(e) => {
            tracing::error!("Reconciliation database error: {e}");
            ApiError::internal("Database error")
        }
        ReconciliationServiceError::Reconciliation(msg) => ApiError::internal(msg),
        ReconciliationServiceError::NotImplemented(msg) => ApiError::not_implemented(msg),
    }
}

/// Get suggested actions for a discrepancy type.
fn get_suggested_actions(discrepancy_type: &str) -> Result<Vec<String>, ApiError> {
    match discrepancy_type {
        "missing" => Ok(vec!["create".to_string()]),
        "orphan" => Ok(vec!["link".to_string(), "delete".to_string()]),
        "mismatch" => Ok(vec!["update".to_string()]),
        "collision" => Ok(vec!["link".to_string()]),
        "unlinked" => Ok(vec!["link".to_string()]),
        "deleted" => Ok(vec![
            "create".to_string(),
            "unlink".to_string(),
            "inactivate_identity".to_string(),
        ]),
        other => Err(ApiError::bad_request(format!(
            "Unknown discrepancy type '{other}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_discrepancy_type_does_not_suggest_empty() {
        assert_eq!(
            get_suggested_actions("orphan").unwrap(),
            vec!["link".to_string(), "delete".to_string()]
        );
        assert!(get_suggested_actions("bogus").is_err());
        let src = include_str!("reconciliation.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("_ => vec![]") && production.contains("Unknown discrepancy type"),
            "unknown discrepancy types must not advertise empty suggested actions"
        );
    }

    #[test]
    fn omitted_enabled_deserializes_to_none() {
        let request: ScheduleRequest = serde_json::from_str(r#"{"frequency":"daily"}"#).unwrap();
        assert_eq!(request.enabled, None);
        assert_eq!(request.hour_of_day, 2);
        assert_eq!(request.mode, "full");
        assert!(request.cron_expression.is_none());
    }

    #[test]
    fn frequency_cron_requires_cron_expression() {
        assert!(resolve_schedule_frequency("cron", None).is_err());
        assert!(resolve_schedule_frequency("cron", Some("   ")).is_err());
        assert!(resolve_schedule_frequency("cron", Some("nightly")).is_err());
        assert_eq!(
            resolve_schedule_frequency("cron", Some("0 2 * * *")).unwrap(),
            "0 2 * * *"
        );
        assert_eq!(
            resolve_schedule_frequency("daily", Some("0 2 * * *")).unwrap(),
            "daily"
        );
    }

    #[test]
    fn advertised_cron_expression_comes_from_stored_frequency() {
        assert_eq!(
            advertised_cron_expression("0 2 * * *").as_deref(),
            Some("0 2 * * *")
        );
        assert!(advertised_cron_expression("daily").is_none());
        assert!(advertised_cron_expression("cron").is_none());
    }

    #[test]
    fn explicit_enabled_false_is_preserved() {
        let request: ScheduleRequest =
            serde_json::from_str(r#"{"frequency":"weekly","enabled":false}"#).unwrap();
        assert_eq!(request.enabled, Some(false));
    }

    #[test]
    fn parse_run_statistics_does_not_default_on_invalid_json() {
        assert!(parse_run_statistics(serde_json::json!("not-stats")).is_err());
        assert!(parse_run_statistics(serde_json::json!({})).is_ok());
        let src = include_str!("reconciliation.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("from_value(run.statistics.clone()).unwrap_or_default()"),
            "reconciliation statistics GET must fail closed on JSON parse"
        );
    }

    #[test]
    fn trigger_does_not_publish_completed_for_queued_runs() {
        let src = include_str!("reconciliation.rs");
        let production = src.split("mod tests").next().expect("production source");
        let trigger = production
            .split("pub async fn trigger_reconciliation")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("trigger_reconciliation");
        assert!(
            trigger.contains("run.status == \"completed\"")
                && trigger.contains("reconciliation.completed"),
            "POST trigger must not emit reconciliation.completed for a queued run"
        );
    }

    #[test]
    fn recon_mutations_require_actor_uuid() {
        let src = include_str!("reconciliation.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("extract_user_id(")
                && !production.contains("Uuid::parse_str(&claims.sub).ok()"),
            "reconciliation mutations must not drop a malformed JWT sub"
        );
    }

    #[test]
    fn invalid_recon_filters_do_not_list_all_runs() {
        assert_eq!(parse_optional_recon_status(None).unwrap(), None);
        assert_eq!(
            parse_optional_recon_status(Some("pending")).unwrap(),
            Some("pending")
        );
        assert!(parse_optional_recon_status(Some("bogus")).is_err());
        assert_eq!(parse_optional_recon_mode(None).unwrap(), None);
        assert_eq!(
            parse_optional_recon_mode(Some("full")).unwrap(),
            Some("full")
        );
        assert!(parse_optional_recon_mode(Some("bogus")).is_err());
        let src = include_str!("reconciliation.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_optional_recon_status(")
                && production.contains("parse_optional_recon_mode(")
                && !production.contains("query.status.as_deref(),"),
            "invalid reconciliation filters must be 400, not an unfiltered list"
        );
    }

    #[test]
    fn invalid_discrepancy_and_action_filters_do_not_list_all() {
        assert!(parse_optional_discrepancy_type(Some("bogus")).is_err());
        assert_eq!(
            parse_optional_discrepancy_type(Some("orphan")).unwrap(),
            Some("orphan")
        );
        assert!(parse_optional_resolution_status(Some("bogus")).is_err());
        assert_eq!(
            parse_optional_resolution_status(Some("pending")).unwrap(),
            Some("pending")
        );
        assert!(parse_optional_action_type(Some("bogus")).is_err());
        assert_eq!(
            parse_optional_action_type(Some("link")).unwrap(),
            Some("link")
        );
        assert!(parse_optional_action_result(Some("bogus")).is_err());
        assert_eq!(
            parse_optional_action_result(Some("success")).unwrap(),
            Some("success")
        );
        let src = include_str!("reconciliation.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_optional_discrepancy_type(")
                && production.contains("parse_optional_resolution_status(")
                && production.contains("parse_optional_action_type(")
                && production.contains("parse_optional_action_result("),
            "invalid discrepancy/action filters must be 400, not an unfiltered list"
        );
    }
}
