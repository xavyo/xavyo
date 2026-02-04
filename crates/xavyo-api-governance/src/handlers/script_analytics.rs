//! HTTP handlers for script analytics and execution log operations (F066).
//!
//! Provides endpoints for the provisioning script dashboard, per-script
//! analytics, execution log browsing, and script audit event queries.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::script::{
        DashboardResponse, ExecutionLogListResponse, ExecutionLogParams, ExecutionLogResponse,
        ScriptAnalyticsResponse,
    },
    router::GovernanceState,
    services::ListScriptAuditParams,
};

// ============================================================================
// Dashboard & Analytics
// ============================================================================

/// Get the provisioning script analytics dashboard.
///
/// Returns aggregate statistics including total/active script counts,
/// overall success rate, average duration, and per-script summaries.
#[utoipa::path(
    get,
    path = "/governance/script-analytics/dashboard",
    tag = "Governance - Provisioning Scripts",
    responses(
        (status = 200, description = "Dashboard analytics data", body = DashboardResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_dashboard(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<DashboardResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let data = state
        .script_analytics_service
        .get_dashboard(tenant_id, None)
        .await?;

    Ok(Json(DashboardResponse {
        total_scripts: data.total_scripts,
        active_scripts: data.active_scripts,
        total_executions: data.total_executions,
        success_rate: data.success_rate,
        avg_duration_ms: data.avg_duration_ms,
        scripts: data
            .scripts
            .into_iter()
            .map(|s| crate::models::script::ScriptSummary {
                script_id: s.script_id,
                name: s.name,
                total_executions: s.total_executions,
                success_count: s.success_count,
                failure_count: s.failure_count,
                avg_duration_ms: s.avg_duration_ms,
            })
            .collect(),
    }))
}

/// Get detailed analytics for a specific provisioning script.
///
/// Returns per-script statistics including success rate, average and p95
/// durations, daily execution trends, and top error messages.
#[utoipa::path(
    get,
    path = "/governance/script-analytics/scripts/{script_id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("script_id" = Uuid, Path, description = "Script ID")
    ),
    responses(
        (status = 200, description = "Script analytics data", body = ScriptAnalyticsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_script_analytics(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(script_id): Path<Uuid>,
) -> ApiResult<Json<ScriptAnalyticsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let data = state
        .script_analytics_service
        .get_script_analytics(tenant_id, script_id, None)
        .await?;

    Ok(Json(ScriptAnalyticsResponse {
        script_id: data.script_id,
        name: data.name,
        total_executions: data.total_executions,
        success_rate: data.success_rate,
        avg_duration_ms: data.avg_duration_ms,
        p95_duration_ms: 0.0, // p95 not yet computed by the analytics service
        daily_trends: data
            .daily_trends
            .into_iter()
            .map(|t| crate::models::script::DailyTrend {
                date: t.date,
                executions: t.executions,
                successes: t.successes,
                failures: t.failures,
                avg_duration_ms: t.avg_duration_ms,
            })
            .collect(),
        top_errors: data
            .top_errors
            .into_iter()
            .map(|e| crate::models::script::ErrorSummary {
                error_message: e.error_message,
                count: e.count,
                last_occurred: e.last_occurred,
            })
            .collect(),
    }))
}

// ============================================================================
// Execution Logs
// ============================================================================

/// List script execution logs with optional filtering.
///
/// Supports filtering by script, connector, binding, status, dry-run flag,
/// and date range. Results are paginated.
#[utoipa::path(
    get,
    path = "/governance/script-execution-logs",
    tag = "Governance - Provisioning Scripts",
    params(ExecutionLogParams),
    responses(
        (status = 200, description = "Execution log list", body = ExecutionLogListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_execution_logs(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ExecutionLogParams>,
) -> ApiResult<Json<ExecutionLogListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = params.page_size.unwrap_or(50).min(100);
    let offset = params.page.map_or(0, |p| (p.max(1) - 1) * limit);

    // Parse date strings into DateTime<Utc> if provided.
    let from_date = params
        .from_date
        .as_deref()
        .and_then(|s| s.parse::<chrono::DateTime<chrono::Utc>>().ok());
    let to_date = params
        .to_date
        .as_deref()
        .and_then(|s| s.parse::<chrono::DateTime<chrono::Utc>>().ok());

    // Parse status string into ExecutionStatus enum if provided.
    let execution_status = params
        .status
        .as_deref()
        .and_then(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok());

    use xavyo_db::models::gov_script_execution_log::ExecutionLogFilter;

    let filter = ExecutionLogFilter {
        script_id: params.script_id,
        connector_id: params.connector_id,
        binding_id: params.binding_id,
        execution_status,
        dry_run: params.dry_run,
        from_date,
        to_date,
    };

    let (logs, total) = state
        .script_analytics_service
        .list_execution_logs(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<ExecutionLogResponse> = logs.into_iter().map(map_execution_log).collect();

    Ok(Json(ExecutionLogListResponse { logs: items, total }))
}

/// Get a single execution log entry by ID.
#[utoipa::path(
    get,
    path = "/governance/script-execution-logs/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Execution log entry ID")
    ),
    responses(
        (status = 200, description = "Execution log entry", body = ExecutionLogResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Execution log not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_execution_log(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ExecutionLogResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let log = state
        .script_analytics_service
        .get_execution_log(tenant_id, id)
        .await?
        .ok_or_else(|| ApiGovernanceError::NotFound(format!("Execution log not found: {id}")))?;

    Ok(Json(map_execution_log(log)))
}

// ============================================================================
// Audit Events
// ============================================================================

/// Query parameters for listing script audit events.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct AuditEventParams {
    /// Filter by script ID.
    pub script_id: Option<Uuid>,
    /// Filter by audit action (e.g., created, activated, deleted).
    pub action: Option<String>,
    /// Maximum number of events to return (default: 50, max: 100).
    pub limit: Option<i64>,
    /// Number of events to skip for pagination.
    pub offset: Option<i64>,
}

/// List script audit events with optional filtering.
///
/// Returns an audit trail of script lifecycle actions such as creation,
/// activation, rollback, binding, and deletion.
#[utoipa::path(
    get,
    path = "/governance/script-audit-events",
    tag = "Governance - Provisioning Scripts",
    params(AuditEventParams),
    responses(
        (status = 200, description = "Script audit events", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_script_audit_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<AuditEventParams>,
) -> ApiResult<Json<serde_json::Value>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    // Parse the action string into ScriptAuditAction if provided.
    let action = params
        .action
        .as_deref()
        .and_then(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok());

    let list_params = ListScriptAuditParams {
        script_id: params.script_id,
        action,
        actor_id: None,
        from_date: None,
        to_date: None,
        limit,
        offset,
    };

    let (events, total) = state
        .script_audit_service
        .list_events(tenant_id, &list_params)
        .await?;

    Ok(Json(serde_json::json!({
        "events": events,
        "total": total,
    })))
}

// ============================================================================
// Helpers
// ============================================================================

/// Map a database execution log row to the API response model.
fn map_execution_log(
    log: xavyo_db::models::gov_script_execution_log::GovScriptExecutionLog,
) -> ExecutionLogResponse {
    ExecutionLogResponse {
        id: log.id,
        tenant_id: log.tenant_id,
        script_id: log.script_id.unwrap_or(Uuid::nil()),
        binding_id: log.binding_id,
        connector_id: Some(log.connector_id),
        script_version: log.script_version,
        status: serde_json::to_value(log.execution_status)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", log.execution_status)),
        dry_run: log.dry_run,
        input_context: log.input_context,
        output: log.output_result,
        error: log.error_message,
        duration_ms: log.duration_ms,
        executed_by: Uuid::nil(), // execution logs do not track actor; placeholder
        executed_at: log.executed_at,
    }
}
