//! Outlier detection handlers for governance API (F059).

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::UpsertOutlierConfiguration;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    AlertResponse, AlertSummaryResponse, CreateDispositionRequest, DispositionResponse,
    DispositionSummaryResponse, GenerateOutlierReportRequest, ListAlertsQuery, ListAnalysesQuery,
    ListDispositionsQuery, ListResultsQuery, OutlierAnalysisResponse, OutlierConfigResponse,
    OutlierReportResponse, OutlierResultResponse, OutlierSummaryResponse, PaginatedResponse,
    TriggerAnalysisRequest, UpdateOutlierConfigRequest, UserOutlierHistoryResponse,
};
use crate::router::GovernanceState;

// ============================================================================
// Configuration Endpoints
// ============================================================================

/// Get outlier detection configuration for the tenant.
#[utoipa::path(
    get,
    path = "/governance/outliers/config",
    tag = "Governance - Outlier Detection",
    responses(
        (status = 200, description = "Configuration retrieved", body = OutlierConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_config(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<OutlierConfigResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let config = state
        .outlier_config_service
        .get_or_create(tenant_id)
        .await?;

    Ok(Json(OutlierConfigResponse {
        id: config.id,
        tenant_id: config.tenant_id,
        confidence_threshold: config.confidence_threshold,
        frequency_threshold: config.frequency_threshold,
        min_peer_group_size: config.min_peer_group_size,
        scoring_weights: config.scoring_weights.0,
        schedule_cron: config.schedule_cron,
        retention_days: config.retention_days,
        is_enabled: config.is_enabled,
        created_at: config.created_at,
        updated_at: config.updated_at,
    }))
}

/// Update outlier detection configuration.
#[utoipa::path(
    put,
    path = "/governance/outliers/config",
    tag = "Governance - Outlier Detection",
    request_body = UpdateOutlierConfigRequest,
    responses(
        (status = 200, description = "Configuration updated", body = OutlierConfigResponse),
        (status = 400, description = "Invalid configuration"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_config(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<UpdateOutlierConfigRequest>,
) -> ApiResult<Json<OutlierConfigResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = UpsertOutlierConfiguration {
        confidence_threshold: request.confidence_threshold,
        frequency_threshold: request.frequency_threshold,
        min_peer_group_size: request.min_peer_group_size,
        scoring_weights: request.scoring_weights,
        schedule_cron: request.schedule_cron,
        retention_days: request.retention_days,
        is_enabled: request.is_enabled,
    };

    let config = state
        .outlier_config_service
        .update(tenant_id, input)
        .await?;

    Ok(Json(OutlierConfigResponse {
        id: config.id,
        tenant_id: config.tenant_id,
        confidence_threshold: config.confidence_threshold,
        frequency_threshold: config.frequency_threshold,
        min_peer_group_size: config.min_peer_group_size,
        scoring_weights: config.scoring_weights.0,
        schedule_cron: config.schedule_cron,
        retention_days: config.retention_days,
        is_enabled: config.is_enabled,
        created_at: config.created_at,
        updated_at: config.updated_at,
    }))
}

/// Enable outlier detection for the tenant.
#[utoipa::path(
    post,
    path = "/governance/outliers/config/enable",
    tag = "Governance - Outlier Detection",
    responses(
        (status = 200, description = "Outlier detection enabled", body = OutlierConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_detection(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<OutlierConfigResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let config = state.outlier_config_service.enable(tenant_id).await?;

    Ok(Json(OutlierConfigResponse {
        id: config.id,
        tenant_id: config.tenant_id,
        confidence_threshold: config.confidence_threshold,
        frequency_threshold: config.frequency_threshold,
        min_peer_group_size: config.min_peer_group_size,
        scoring_weights: config.scoring_weights.0,
        schedule_cron: config.schedule_cron,
        retention_days: config.retention_days,
        is_enabled: config.is_enabled,
        created_at: config.created_at,
        updated_at: config.updated_at,
    }))
}

/// Disable outlier detection for the tenant.
#[utoipa::path(
    post,
    path = "/governance/outliers/config/disable",
    tag = "Governance - Outlier Detection",
    responses(
        (status = 200, description = "Outlier detection disabled", body = OutlierConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_detection(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<OutlierConfigResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let config = state.outlier_config_service.disable(tenant_id).await?;

    Ok(Json(OutlierConfigResponse {
        id: config.id,
        tenant_id: config.tenant_id,
        confidence_threshold: config.confidence_threshold,
        frequency_threshold: config.frequency_threshold,
        min_peer_group_size: config.min_peer_group_size,
        scoring_weights: config.scoring_weights.0,
        schedule_cron: config.schedule_cron,
        retention_days: config.retention_days,
        is_enabled: config.is_enabled,
        created_at: config.created_at,
        updated_at: config.updated_at,
    }))
}

// ============================================================================
// Analysis Endpoints
// ============================================================================

/// List outlier analysis runs.
#[utoipa::path(
    get,
    path = "/governance/outliers/analyses",
    tag = "Governance - Outlier Detection",
    params(ListAnalysesQuery),
    responses(
        (status = 200, description = "Analysis list retrieved", body = PaginatedOutlierAnalysisResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_analyses(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListAnalysesQuery>,
) -> ApiResult<Json<PaginatedResponse<OutlierAnalysisResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (analyses, total) = state
        .outlier_scoring_service
        .list_analyses(tenant_id, query.status, query.triggered_by, limit, offset)
        .await?;

    let items: Vec<OutlierAnalysisResponse> = analyses
        .into_iter()
        .map(|a| OutlierAnalysisResponse {
            id: a.id,
            tenant_id: a.tenant_id,
            status: a.status,
            triggered_by: a.triggered_by,
            started_at: a.started_at,
            completed_at: a.completed_at,
            users_analyzed: a.users_analyzed,
            outliers_detected: a.outliers_detected,
            progress_percent: a.progress_percent,
            error_message: a.error_message,
            created_at: a.created_at,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(items, total, limit, offset)))
}

/// Trigger a new outlier analysis.
#[utoipa::path(
    post,
    path = "/governance/outliers/analyses",
    tag = "Governance - Outlier Detection",
    request_body = TriggerAnalysisRequest,
    responses(
        (status = 201, description = "Analysis started", body = OutlierAnalysisResponse),
        (status = 400, description = "Outlier detection is disabled"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Analysis already running"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_analysis(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<TriggerAnalysisRequest>,
) -> ApiResult<Json<OutlierAnalysisResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let analysis = state
        .outlier_scoring_service
        .trigger_analysis(tenant_id, request.triggered_by)
        .await?;

    Ok(Json(OutlierAnalysisResponse {
        id: analysis.id,
        tenant_id: analysis.tenant_id,
        status: analysis.status,
        triggered_by: analysis.triggered_by,
        started_at: analysis.started_at,
        completed_at: analysis.completed_at,
        users_analyzed: analysis.users_analyzed,
        outliers_detected: analysis.outliers_detected,
        progress_percent: analysis.progress_percent,
        error_message: analysis.error_message,
        created_at: analysis.created_at,
    }))
}

/// Get analysis details.
#[utoipa::path(
    get,
    path = "/governance/outliers/analyses/{analysis_id}",
    tag = "Governance - Outlier Detection",
    params(
        ("analysis_id" = Uuid, Path, description = "Analysis ID")
    ),
    responses(
        (status = 200, description = "Analysis retrieved", body = OutlierAnalysisResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Analysis not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_analysis(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(analysis_id): Path<Uuid>,
) -> ApiResult<Json<OutlierAnalysisResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let analysis = state
        .outlier_scoring_service
        .get_analysis(tenant_id, analysis_id)
        .await?;

    Ok(Json(OutlierAnalysisResponse {
        id: analysis.id,
        tenant_id: analysis.tenant_id,
        status: analysis.status,
        triggered_by: analysis.triggered_by,
        started_at: analysis.started_at,
        completed_at: analysis.completed_at,
        users_analyzed: analysis.users_analyzed,
        outliers_detected: analysis.outliers_detected,
        progress_percent: analysis.progress_percent,
        error_message: analysis.error_message,
        created_at: analysis.created_at,
    }))
}

/// Cancel a running analysis.
#[utoipa::path(
    post,
    path = "/governance/outliers/analyses/{analysis_id}/cancel",
    tag = "Governance - Outlier Detection",
    params(
        ("analysis_id" = Uuid, Path, description = "Analysis ID")
    ),
    responses(
        (status = 200, description = "Analysis cancelled", body = OutlierAnalysisResponse),
        (status = 400, description = "Analysis cannot be cancelled (not running)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Analysis not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_analysis(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(analysis_id): Path<Uuid>,
) -> ApiResult<Json<OutlierAnalysisResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let analysis = state
        .outlier_scoring_service
        .cancel_analysis(tenant_id, analysis_id)
        .await?;

    Ok(Json(OutlierAnalysisResponse {
        id: analysis.id,
        tenant_id: analysis.tenant_id,
        status: analysis.status,
        triggered_by: analysis.triggered_by,
        started_at: analysis.started_at,
        completed_at: analysis.completed_at,
        users_analyzed: analysis.users_analyzed,
        outliers_detected: analysis.outliers_detected,
        progress_percent: analysis.progress_percent,
        error_message: analysis.error_message,
        created_at: analysis.created_at,
    }))
}

// ============================================================================
// Results Endpoints
// ============================================================================

/// List outlier results (dashboard view).
#[utoipa::path(
    get,
    path = "/governance/outliers/results",
    tag = "Governance - Outlier Detection",
    params(ListResultsQuery),
    responses(
        (status = 200, description = "Results retrieved", body = PaginatedOutlierResultResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_results(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListResultsQuery>,
) -> ApiResult<Json<PaginatedResponse<OutlierResultResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (results, total) = state
        .outlier_scoring_service
        .list_results(
            tenant_id,
            query.analysis_id,
            query.user_id,
            query.classification,
            query.min_score,
            query.max_score,
            limit,
            offset,
        )
        .await?;

    let items: Vec<OutlierResultResponse> = results
        .into_iter()
        .map(|r| OutlierResultResponse {
            id: r.id,
            analysis_id: r.analysis_id,
            user_id: r.user_id,
            overall_score: r.overall_score,
            classification: r.classification,
            peer_scores: r.peer_scores.0,
            factor_breakdown: r.factor_breakdown.0,
            previous_score: r.previous_score,
            score_change: r.score_change,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(items, total, limit, offset)))
}

/// Get detailed result for a user.
#[utoipa::path(
    get,
    path = "/governance/outliers/results/{result_id}",
    tag = "Governance - Outlier Detection",
    params(
        ("result_id" = Uuid, Path, description = "Result ID")
    ),
    responses(
        (status = 200, description = "Result retrieved", body = OutlierResultResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Result not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_result(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(result_id): Path<Uuid>,
) -> ApiResult<Json<OutlierResultResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .outlier_scoring_service
        .get_result(tenant_id, result_id)
        .await?;

    Ok(Json(OutlierResultResponse {
        id: result.id,
        analysis_id: result.analysis_id,
        user_id: result.user_id,
        overall_score: result.overall_score,
        classification: result.classification,
        peer_scores: result.peer_scores.0,
        factor_breakdown: result.factor_breakdown.0,
        previous_score: result.previous_score,
        score_change: result.score_change,
        created_at: result.created_at,
    }))
}

/// Get outlier summary statistics.
#[utoipa::path(
    get,
    path = "/governance/outliers/summary",
    tag = "Governance - Outlier Detection",
    responses(
        (status = 200, description = "Summary retrieved", body = OutlierSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<OutlierSummaryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state.outlier_scoring_service.get_summary(tenant_id).await?;

    Ok(Json(OutlierSummaryResponse {
        total_users: summary.total_users,
        outlier_count: summary.outlier_count,
        normal_count: summary.normal_count,
        unclassifiable_count: summary.unclassifiable_count,
        avg_score: summary.avg_score,
        max_score: summary.max_score,
        analysis_id: summary.analysis_id,
        analysis_completed_at: summary.analysis_completed_at,
    }))
}

/// Get outlier history for a specific user.
#[utoipa::path(
    get,
    path = "/governance/outliers/users/{user_id}",
    tag = "Governance - Outlier Detection",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("limit" = Option<i64>, Query, description = "Maximum results")
    ),
    responses(
        (status = 200, description = "User outlier history retrieved", body = UserOutlierHistoryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_history(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<ListResultsQuery>,
) -> ApiResult<Json<UserOutlierHistoryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(10).min(50);

    let (results, disposition) = state
        .outlier_scoring_service
        .get_user_history(tenant_id, user_id, limit)
        .await?;

    let result_responses: Vec<OutlierResultResponse> = results
        .into_iter()
        .map(|r| OutlierResultResponse {
            id: r.id,
            analysis_id: r.analysis_id,
            user_id: r.user_id,
            overall_score: r.overall_score,
            classification: r.classification,
            peer_scores: r.peer_scores.0,
            factor_breakdown: r.factor_breakdown.0,
            previous_score: r.previous_score,
            score_change: r.score_change,
            created_at: r.created_at,
        })
        .collect();

    let current_disposition = disposition.map(|d| DispositionResponse {
        id: d.id,
        result_id: d.result_id,
        user_id: d.user_id,
        status: d.status,
        justification: d.justification,
        reviewed_by: d.reviewed_by,
        reviewed_at: d.reviewed_at,
        expires_at: d.expires_at,
        created_at: d.created_at,
        updated_at: d.updated_at,
    });

    Ok(Json(UserOutlierHistoryResponse {
        user_id,
        results: result_responses,
        current_disposition,
    }))
}

// ============================================================================
// Disposition Endpoints
// ============================================================================

/// Create disposition for an outlier result.
#[utoipa::path(
    post,
    path = "/governance/outliers/results/{result_id}/disposition",
    tag = "Governance - Outlier Detection",
    params(
        ("result_id" = Uuid, Path, description = "Result ID")
    ),
    request_body = CreateDispositionRequest,
    responses(
        (status = 201, description = "Disposition created", body = DispositionResponse),
        (status = 400, description = "Invalid disposition"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Result not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_disposition(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(result_id): Path<Uuid>,
    Json(request): Json<CreateDispositionRequest>,
) -> ApiResult<Json<DispositionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let reviewer_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let disposition = state
        .outlier_scoring_service
        .create_disposition(
            tenant_id,
            result_id,
            reviewer_id,
            request.status,
            request.justification,
            request.expires_at,
        )
        .await?;

    Ok(Json(DispositionResponse {
        id: disposition.id,
        result_id: disposition.result_id,
        user_id: disposition.user_id,
        status: disposition.status,
        justification: disposition.justification,
        reviewed_by: disposition.reviewed_by,
        reviewed_at: disposition.reviewed_at,
        expires_at: disposition.expires_at,
        created_at: disposition.created_at,
        updated_at: disposition.updated_at,
    }))
}

/// Get disposition details.
#[utoipa::path(
    get,
    path = "/governance/outliers/dispositions/{disposition_id}",
    tag = "Governance - Outlier Detection",
    params(
        ("disposition_id" = Uuid, Path, description = "Disposition ID")
    ),
    responses(
        (status = 200, description = "Disposition retrieved", body = DispositionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Disposition not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_disposition(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(disposition_id): Path<Uuid>,
) -> ApiResult<Json<DispositionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let disposition = state
        .outlier_scoring_service
        .get_disposition(tenant_id, disposition_id)
        .await?;

    Ok(Json(DispositionResponse {
        id: disposition.id,
        result_id: disposition.result_id,
        user_id: disposition.user_id,
        status: disposition.status,
        justification: disposition.justification,
        reviewed_by: disposition.reviewed_by,
        reviewed_at: disposition.reviewed_at,
        expires_at: disposition.expires_at,
        created_at: disposition.created_at,
        updated_at: disposition.updated_at,
    }))
}

/// Update disposition status.
#[utoipa::path(
    put,
    path = "/governance/outliers/dispositions/{disposition_id}",
    tag = "Governance - Outlier Detection",
    params(
        ("disposition_id" = Uuid, Path, description = "Disposition ID")
    ),
    request_body = CreateDispositionRequest,
    responses(
        (status = 200, description = "Disposition updated", body = DispositionResponse),
        (status = 400, description = "Invalid status transition"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Disposition not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_disposition(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(disposition_id): Path<Uuid>,
    Json(request): Json<CreateDispositionRequest>,
) -> ApiResult<Json<DispositionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let reviewer_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let disposition = state
        .outlier_scoring_service
        .update_disposition(
            tenant_id,
            disposition_id,
            reviewer_id,
            request.status,
            request.justification,
        )
        .await?;

    Ok(Json(DispositionResponse {
        id: disposition.id,
        result_id: disposition.result_id,
        user_id: disposition.user_id,
        status: disposition.status,
        justification: disposition.justification,
        reviewed_by: disposition.reviewed_by,
        reviewed_at: disposition.reviewed_at,
        expires_at: disposition.expires_at,
        created_at: disposition.created_at,
        updated_at: disposition.updated_at,
    }))
}

/// List dispositions with filtering.
#[utoipa::path(
    get,
    path = "/governance/outliers/dispositions",
    tag = "Governance - Outlier Detection",
    params(ListDispositionsQuery),
    responses(
        (status = 200, description = "Dispositions retrieved", body = PaginatedDispositionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_dispositions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDispositionsQuery>,
) -> ApiResult<Json<PaginatedResponse<DispositionResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (dispositions, total) = state
        .outlier_scoring_service
        .list_dispositions(
            tenant_id,
            query.user_id,
            query.status,
            query.reviewed_by,
            query.include_expired.unwrap_or(false),
            limit,
            offset,
        )
        .await?;

    let items: Vec<DispositionResponse> = dispositions
        .into_iter()
        .map(|d| DispositionResponse {
            id: d.id,
            result_id: d.result_id,
            user_id: d.user_id,
            status: d.status,
            justification: d.justification,
            reviewed_by: d.reviewed_by,
            reviewed_at: d.reviewed_at,
            expires_at: d.expires_at,
            created_at: d.created_at,
            updated_at: d.updated_at,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(items, total, limit, offset)))
}

/// Get disposition summary by status.
#[utoipa::path(
    get,
    path = "/governance/outliers/dispositions/summary",
    tag = "Governance - Outlier Detection",
    responses(
        (status = 200, description = "Disposition summary retrieved", body = DispositionSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_disposition_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<DispositionSummaryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state
        .outlier_scoring_service
        .get_disposition_summary(tenant_id)
        .await?;

    Ok(Json(DispositionSummaryResponse {
        new_count: summary.new_count,
        legitimate_count: summary.legitimate_count,
        requires_remediation_count: summary.requires_remediation_count,
        under_investigation_count: summary.under_investigation_count,
        remediated_count: summary.remediated_count,
    }))
}

// ============================================================================
// Alert Endpoints
// ============================================================================

/// List outlier alerts.
#[utoipa::path(
    get,
    path = "/governance/outliers/alerts",
    tag = "Governance - Outlier Detection",
    params(ListAlertsQuery),
    responses(
        (status = 200, description = "Alerts retrieved", body = PaginatedAlertResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_alerts(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListAlertsQuery>,
) -> ApiResult<Json<PaginatedResponse<AlertResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (alerts, total) = state
        .outlier_scoring_service
        .list_alerts(
            tenant_id,
            query.user_id,
            query.analysis_id,
            query.alert_type,
            query.severity,
            query.is_read,
            query.is_dismissed,
            limit,
            offset,
        )
        .await?;

    let items: Vec<AlertResponse> = alerts
        .into_iter()
        .map(|a| AlertResponse {
            id: a.id,
            analysis_id: a.analysis_id,
            user_id: a.user_id,
            alert_type: a.alert_type,
            severity: a.severity,
            score: a.score,
            classification: a.classification,
            is_read: a.is_read,
            is_dismissed: a.is_dismissed,
            created_at: a.created_at,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(items, total, limit, offset)))
}

/// Get alert summary.
#[utoipa::path(
    get,
    path = "/governance/outliers/alerts/summary",
    tag = "Governance - Outlier Detection",
    responses(
        (status = 200, description = "Alert summary retrieved", body = AlertSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_alert_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<AlertSummaryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state
        .outlier_scoring_service
        .get_alert_summary(tenant_id)
        .await?;

    Ok(Json(AlertSummaryResponse {
        total_count: summary.total_count,
        unread_count: summary.unread_count,
        critical_count: summary.critical_count,
        high_count: summary.high_count,
        medium_count: summary.medium_count,
        low_count: summary.low_count,
    }))
}

/// Mark alert as read.
#[utoipa::path(
    post,
    path = "/governance/outliers/alerts/{alert_id}/read",
    tag = "Governance - Outlier Detection",
    params(
        ("alert_id" = Uuid, Path, description = "Alert ID")
    ),
    responses(
        (status = 200, description = "Alert marked as read", body = AlertResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Alert not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn mark_alert_read(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(alert_id): Path<Uuid>,
) -> ApiResult<Json<AlertResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let alert = state
        .outlier_scoring_service
        .mark_alert_read(tenant_id, alert_id)
        .await?;

    Ok(Json(AlertResponse {
        id: alert.id,
        analysis_id: alert.analysis_id,
        user_id: alert.user_id,
        alert_type: alert.alert_type,
        severity: alert.severity,
        score: alert.score,
        classification: alert.classification,
        is_read: alert.is_read,
        is_dismissed: alert.is_dismissed,
        created_at: alert.created_at,
    }))
}

/// Dismiss an alert.
#[utoipa::path(
    post,
    path = "/governance/outliers/alerts/{alert_id}/dismiss",
    tag = "Governance - Outlier Detection",
    params(
        ("alert_id" = Uuid, Path, description = "Alert ID")
    ),
    responses(
        (status = 200, description = "Alert dismissed", body = AlertResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Alert not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn dismiss_alert(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(alert_id): Path<Uuid>,
) -> ApiResult<Json<AlertResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let alert = state
        .outlier_scoring_service
        .dismiss_alert(tenant_id, alert_id)
        .await?;

    Ok(Json(AlertResponse {
        id: alert.id,
        analysis_id: alert.analysis_id,
        user_id: alert.user_id,
        alert_type: alert.alert_type,
        severity: alert.severity,
        score: alert.score,
        classification: alert.classification,
        is_read: alert.is_read,
        is_dismissed: alert.is_dismissed,
        created_at: alert.created_at,
    }))
}

// ============================================================================
// Report Endpoints
// ============================================================================

/// Generate outlier detection report.
#[utoipa::path(
    post,
    path = "/governance/outliers/reports",
    tag = "Governance - Outlier Detection",
    request_body = GenerateOutlierReportRequest,
    responses(
        (status = 200, description = "Report generated", body = OutlierReportResponse),
        (status = 400, description = "Invalid date range"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn generate_report(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<GenerateOutlierReportRequest>,
) -> ApiResult<Json<OutlierReportResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let report = state
        .outlier_scoring_service
        .generate_report(
            tenant_id,
            request.start_date,
            request.end_date,
            request.include_trends,
            request.include_peer_breakdown,
        )
        .await?;

    Ok(Json(report))
}
