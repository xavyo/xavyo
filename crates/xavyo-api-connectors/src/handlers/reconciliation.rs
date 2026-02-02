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
    pub accounts_total: u32,
    pub accounts_processed: u32,
    pub discrepancies_found: u32,
    #[serde(default)]
    pub discrepancies_by_type: HashMap<String, u32>,
    pub actions_taken: u32,
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
    /// Action: create, update, delete, link, unlink, inactivate_identity.
    pub action: String,
    /// Direction for update: xavyo_to_target or target_to_xavyo.
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
    /// Frequency: hourly, daily, weekly, monthly, or cron expression.
    pub frequency: String,
    /// Day of week (0-6) for weekly schedule.
    pub day_of_week: Option<i32>,
    /// Day of month (1-28) for monthly schedule.
    pub day_of_month: Option<i32>,
    /// Hour of day (0-23 UTC).
    #[serde(default = "default_hour")]
    pub hour_of_day: i32,
    /// Whether enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_hour() -> i32 {
    2
}

fn default_enabled() -> bool {
    true
}

/// Response for a schedule.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScheduleResponse {
    pub id: Uuid,
    pub connector_id: Uuid,
    pub mode: String,
    pub frequency: String,
    pub day_of_week: Option<i32>,
    pub day_of_month: Option<i32>,
    pub hour_of_day: i32,
    pub enabled: bool,
    pub last_run_id: Option<Uuid>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
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
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = Uuid::parse_str(&claims.sub).ok();

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let stats: ReconciliationStatistics = run
        .statistics
        .as_object()
        .map(|_| serde_json::from_value(run.statistics.clone()).unwrap_or_default())
        .unwrap_or_default();

    // F085: Publish reconciliation.completed webhook event (triggered run)
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
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Reconciliation run not found"))?;

    let stats: ReconciliationStatistics =
        serde_json::from_value(run.statistics.clone()).unwrap_or_default();

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

    let (runs, total) = state
        .reconciliation_service
        .list_runs(
            tenant_id,
            connector_id,
            query.mode.as_deref(),
            query.status.as_deref(),
            query.limit.unwrap_or(50),
            query.offset.unwrap_or(0),
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let runs: Vec<ReconciliationRunResponse> = runs
        .into_iter()
        .map(|run| {
            let stats: ReconciliationStatistics =
                serde_json::from_value(run.statistics.clone()).unwrap_or_default();
            ReconciliationRunResponse {
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
            }
        })
        .collect();

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let stats: ReconciliationStatistics =
        serde_json::from_value(run.statistics.clone()).unwrap_or_default();

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

    let (discrepancies, total) = state
        .reconciliation_service
        .list_discrepancies(
            tenant_id,
            connector_id,
            query.run_id,
            query.discrepancy_type.as_deref(),
            query.resolution_status.as_deref(),
            query.identity_id,
            query.external_uid.as_deref(),
            query.limit.unwrap_or(50),
            query.offset.unwrap_or(0),
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let discrepancies: Vec<DiscrepancyResponse> = discrepancies
        .into_iter()
        .map(|d| DiscrepancyResponse {
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
            suggested_actions: get_suggested_actions(&d.discrepancy_type),
        })
        .collect();

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
        .map_err(|e| ApiError::internal(e.to_string()))?
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
        suggested_actions: get_suggested_actions(&d.discrepancy_type),
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
        (status = 200, description = "Remediation result", body = RemediationResponse),
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
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = Uuid::parse_str(&claims.sub).ok();

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
        (status = 200, description = "Bulk remediation results", body = BulkRemediationResponse),
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
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = Uuid::parse_str(&claims.sub).ok();

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = Uuid::parse_str(&claims.sub).ok();

    state
        .reconciliation_service
        .ignore_discrepancy(tenant_id, user_id, connector_id, discrepancy_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Schedule not found"))?;

    Ok(Json(ScheduleResponse {
        id: schedule.id,
        connector_id: schedule.connector_id,
        mode: schedule.mode,
        frequency: schedule.frequency,
        day_of_week: schedule.day_of_week,
        day_of_month: schedule.day_of_month,
        hour_of_day: schedule.hour_of_day,
        enabled: schedule.enabled,
        last_run_id: schedule.last_run_id,
        next_run_at: schedule.next_run_at,
        created_at: schedule.created_at,
    }))
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
    let tenant_id = extract_tenant_id(&claims)?;

    let schedule = state
        .reconciliation_service
        .upsert_schedule(
            tenant_id,
            connector_id,
            &request.mode,
            &request.frequency,
            request.day_of_week,
            request.day_of_month,
            request.hour_of_day,
            request.enabled,
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(ScheduleResponse {
        id: schedule.id,
        connector_id: schedule.connector_id,
        mode: schedule.mode,
        frequency: schedule.frequency,
        day_of_week: schedule.day_of_week,
        day_of_month: schedule.day_of_month,
        hour_of_day: schedule.hour_of_day,
        enabled: schedule.enabled,
        last_run_id: schedule.last_run_id,
        next_run_at: schedule.next_run_at,
        created_at: schedule.created_at,
    }))
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
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .reconciliation_service
        .delete_schedule(tenant_id, connector_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let schedules: Vec<ScheduleResponse> = schedules
        .into_iter()
        .map(|s| ScheduleResponse {
            id: s.id,
            connector_id: s.connector_id,
            mode: s.mode,
            frequency: s.frequency,
            day_of_week: s.day_of_week,
            day_of_month: s.day_of_month,
            hour_of_day: s.hour_of_day,
            enabled: s.enabled,
            last_run_id: s.last_run_id,
            next_run_at: s.next_run_at,
            created_at: s.created_at,
        })
        .collect();

    Ok(Json(ListSchedulesResponse { schedules }))
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
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
        .map_err(|e| ApiError::internal(e.to_string()))?;

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

    let (actions, total) = state
        .reconciliation_service
        .list_actions(
            tenant_id,
            connector_id,
            query.discrepancy_id,
            query.action_type.as_deref(),
            query.result.as_deref(),
            query.dry_run,
            query.limit.unwrap_or(50),
            query.offset.unwrap_or(0),
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

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

/// Get suggested actions for a discrepancy type.
fn get_suggested_actions(discrepancy_type: &str) -> Vec<String> {
    match discrepancy_type {
        "missing" => vec!["create".to_string()],
        "orphan" => vec!["link".to_string(), "delete".to_string()],
        "mismatch" => vec!["update".to_string()],
        "collision" => vec!["link".to_string()],
        "unlinked" => vec!["link".to_string()],
        "deleted" => vec![
            "create".to_string(),
            "unlink".to_string(),
            "inactivate_identity".to_string(),
        ],
        _ => vec![],
    }
}
