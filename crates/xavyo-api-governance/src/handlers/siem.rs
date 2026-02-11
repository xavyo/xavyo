//! SIEM handlers for governance API (F078).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateSiemDestination, UpdateSiemDestination};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::siem::{
    CreateBatchExportRequest, CreateSiemDestinationRequest, DeadLetterQuery, HealthHistoryQuery,
    ListBatchExportsQuery, ListSiemDestinationsQuery, RedeliverResponse,
    SiemBatchExportListResponse, SiemBatchExportResponse, SiemDestinationListResponse,
    SiemDestinationResponse, SiemHealthSummaryResponse, TestConnectivityResponse,
    UpdateSiemDestinationRequest,
};
use crate::router::GovernanceState;

// ---------------------------------------------------------------------------
// Destination CRUD
// ---------------------------------------------------------------------------

/// List SIEM destinations.
#[utoipa::path(
    get,
    path = "/governance/siem/destinations",
    tag = "Governance - Audit Export",
    params(ListSiemDestinationsQuery),
    responses(
        (status = 200, description = "List of destinations", body = SiemDestinationListResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_destinations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSiemDestinationsQuery>,
) -> ApiResult<Json<SiemDestinationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (destinations, total) = state
        .siem_destination_service
        .list_destinations(tenant_id, query.enabled, query.limit, query.offset)
        .await?;

    Ok(Json(SiemDestinationListResponse {
        items: destinations.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Create a SIEM destination.
#[utoipa::path(
    post,
    path = "/governance/siem/destinations",
    tag = "Governance - Audit Export",
    request_body = CreateSiemDestinationRequest,
    responses(
        (status = 201, description = "Destination created", body = SiemDestinationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Duplicate name"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_destination(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateSiemDestinationRequest>,
) -> ApiResult<(StatusCode, Json<SiemDestinationResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Encrypt auth config if provided
    let auth_config = if let Some(ref b64) = request.auth_config_b64 {
        let key = state.siem_encryption_key();
        let encrypted = xavyo_siem::crypto::encrypt_auth_config(b64, key)
            .map_err(|e| ApiGovernanceError::Internal(format!("Encryption failed: {e}")))?;
        Some(encrypted)
    } else {
        None
    };

    let input = CreateSiemDestination {
        name: request.name,
        destination_type: request.destination_type,
        endpoint_host: request.endpoint_host,
        endpoint_port: request.endpoint_port,
        export_format: request.export_format,
        auth_config,
        event_type_filter: request.event_type_filter.unwrap_or(serde_json::json!([])),
        rate_limit_per_second: request.rate_limit_per_second.unwrap_or(1000),
        queue_buffer_size: request.queue_buffer_size.unwrap_or(10000),
        circuit_breaker_threshold: request.circuit_breaker_threshold.unwrap_or(5),
        circuit_breaker_cooldown_secs: request.circuit_breaker_cooldown_secs.unwrap_or(60),
        enabled: request.enabled.unwrap_or(true),
        splunk_source: request.splunk_source,
        splunk_sourcetype: request.splunk_sourcetype,
        splunk_index: request.splunk_index,
        splunk_ack_enabled: request.splunk_ack_enabled.unwrap_or(false),
        syslog_facility: request.syslog_facility.unwrap_or(10),
        tls_verify_cert: request.tls_verify_cert.unwrap_or(true),
    };

    let destination = state
        .siem_destination_service
        .create_destination(tenant_id, user_id, input)
        .await?;

    Ok((StatusCode::CREATED, Json(destination.into())))
}

/// Get a SIEM destination by ID.
#[utoipa::path(
    get,
    path = "/governance/siem/destinations/{id}",
    tag = "Governance - Audit Export",
    params(("id" = Uuid, Path, description = "Destination ID")),
    responses(
        (status = 200, description = "Destination details", body = SiemDestinationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_destination(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SiemDestinationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let destination = state
        .siem_destination_service
        .get_destination(tenant_id, id)
        .await?;

    Ok(Json(destination.into()))
}

/// Update a SIEM destination.
#[utoipa::path(
    put,
    path = "/governance/siem/destinations/{id}",
    tag = "Governance - Audit Export",
    params(("id" = Uuid, Path, description = "Destination ID")),
    request_body = UpdateSiemDestinationRequest,
    responses(
        (status = 200, description = "Destination updated", body = SiemDestinationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Duplicate name"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_destination(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateSiemDestinationRequest>,
) -> ApiResult<Json<SiemDestinationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Encrypt auth config if provided
    let auth_config = if let Some(ref b64) = request.auth_config_b64 {
        let key = state.siem_encryption_key();
        let encrypted = xavyo_siem::crypto::encrypt_auth_config(b64, key)
            .map_err(|e| ApiGovernanceError::Internal(format!("Encryption failed: {e}")))?;
        Some(encrypted)
    } else {
        None
    };

    let input = UpdateSiemDestination {
        name: request.name,
        endpoint_host: request.endpoint_host,
        endpoint_port: request.endpoint_port,
        export_format: request.export_format,
        auth_config,
        event_type_filter: request.event_type_filter,
        rate_limit_per_second: request.rate_limit_per_second,
        queue_buffer_size: request.queue_buffer_size,
        circuit_breaker_threshold: request.circuit_breaker_threshold,
        circuit_breaker_cooldown_secs: request.circuit_breaker_cooldown_secs,
        enabled: request.enabled,
        splunk_source: request.splunk_source,
        splunk_sourcetype: request.splunk_sourcetype,
        splunk_index: request.splunk_index,
        splunk_ack_enabled: request.splunk_ack_enabled,
        syslog_facility: request.syslog_facility,
        tls_verify_cert: request.tls_verify_cert,
    };

    let destination = state
        .siem_destination_service
        .update_destination(tenant_id, id, input)
        .await?;

    Ok(Json(destination.into()))
}

/// Delete a SIEM destination.
#[utoipa::path(
    delete,
    path = "/governance/siem/destinations/{id}",
    tag = "Governance - Audit Export",
    params(("id" = Uuid, Path, description = "Destination ID")),
    responses(
        (status = 204, description = "Destination deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_destination(
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

    state
        .siem_destination_service
        .delete_destination(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Test connectivity to a SIEM destination.
#[utoipa::path(
    post,
    path = "/governance/siem/destinations/{id}/test",
    tag = "Governance - Audit Export",
    params(("id" = Uuid, Path, description = "Destination ID")),
    responses(
        (status = 200, description = "Test result", body = TestConnectivityResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_destination(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TestConnectivityResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let key = state.siem_encryption_key();
    let (success, latency_ms, error) = state
        .siem_destination_service
        .test_connectivity(tenant_id, id, key)
        .await?;

    Ok(Json(TestConnectivityResponse {
        success,
        latency_ms,
        error,
    }))
}

// ---------------------------------------------------------------------------
// Batch Export CRUD
// ---------------------------------------------------------------------------

/// List batch exports.
#[utoipa::path(
    get,
    path = "/governance/siem/exports",
    tag = "Governance - Audit Export",
    params(ListBatchExportsQuery),
    responses(
        (status = 200, description = "List of batch exports", body = SiemBatchExportListResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_batch_exports(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListBatchExportsQuery>,
) -> ApiResult<Json<SiemBatchExportListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (exports, total) = state
        .siem_batch_export_service
        .list_exports(
            tenant_id,
            query.status.as_deref(),
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(SiemBatchExportListResponse {
        items: exports.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Create a batch export job.
#[utoipa::path(
    post,
    path = "/governance/siem/exports",
    tag = "Governance - Audit Export",
    request_body = CreateBatchExportRequest,
    responses(
        (status = 201, description = "Batch export created", body = SiemBatchExportResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_batch_export(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateBatchExportRequest>,
) -> ApiResult<(StatusCode, Json<SiemBatchExportResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let input = xavyo_db::models::CreateSiemBatchExport {
        date_range_start: request.date_range_start,
        date_range_end: request.date_range_end,
        event_type_filter: request.event_type_filter.unwrap_or(serde_json::json!([])),
        output_format: request.output_format,
    };

    let export = state
        .siem_batch_export_service
        .create_export(tenant_id, user_id, input)
        .await?;

    Ok((StatusCode::CREATED, Json(export.into())))
}

/// Get a batch export by ID.
#[utoipa::path(
    get,
    path = "/governance/siem/exports/{id}",
    tag = "Governance - Audit Export",
    params(("id" = Uuid, Path, description = "Batch export ID")),
    responses(
        (status = 200, description = "Batch export details", body = SiemBatchExportResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_batch_export(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SiemBatchExportResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let export = state
        .siem_batch_export_service
        .get_export(tenant_id, id)
        .await?;

    Ok(Json(export.into()))
}

/// Download a completed batch export file.
#[utoipa::path(
    get,
    path = "/governance/siem/exports/{id}/download",
    tag = "Governance - Audit Export",
    params(("id" = Uuid, Path, description = "Batch export ID")),
    responses(
        (status = 200, description = "Export file download"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn download_batch_export(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let _file_path = state
        .siem_batch_export_service
        .get_download_path(tenant_id, id)
        .await?;

    // In production, this would stream the file via StreamBody or
    // return a pre-signed URL from object storage. For now, confirm
    // the export is ready without exposing the internal server path.
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "export_id": id,
            "status": "ready",
            "message": "Export file is ready for download"
        })),
    ))
}

// ---------------------------------------------------------------------------
// Delivery Health & Dead Letter
// ---------------------------------------------------------------------------

/// Get delivery health summary for a destination.
#[utoipa::path(
    get,
    path = "/governance/siem/destinations/{id}/health",
    tag = "Governance - Audit Export",
    params(("id" = Uuid, Path, description = "Destination ID")),
    responses(
        (status = 200, description = "Health summary", body = SiemHealthSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Destination not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_destination_health(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SiemHealthSummaryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state
        .siem_health_service
        .get_health_summary(tenant_id, id)
        .await?;

    Ok(Json(SiemHealthSummaryResponse {
        destination_id: summary.destination_id,
        total_events_sent: summary.total_events_sent,
        total_events_delivered: summary.total_events_delivered,
        total_events_failed: summary.total_events_failed,
        total_events_dropped: summary.total_events_dropped,
        avg_latency_ms: summary.avg_latency_ms,
        last_success_at: summary.last_success_at,
        last_failure_at: summary.last_failure_at,
        success_rate_percent: summary.success_rate_percent,
        circuit_state: summary.circuit_state,
        dead_letter_count: summary.dead_letter_count,
    }))
}

/// Get delivery health history for a destination.
#[utoipa::path(
    get,
    path = "/governance/siem/destinations/{id}/health/history",
    tag = "Governance - Audit Export",
    params(
        ("id" = Uuid, Path, description = "Destination ID"),
        HealthHistoryQuery,
    ),
    responses(
        (status = 200, description = "Health history windows"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Destination not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_delivery_history(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<HealthHistoryQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (windows, total) = state
        .siem_health_service
        .get_health_history(
            tenant_id,
            id,
            query.from,
            query.to,
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(serde_json::json!({
        "items": windows,
        "total": total,
        "limit": query.limit,
        "offset": query.offset,
    })))
}

/// List dead letter events for a destination.
#[utoipa::path(
    get,
    path = "/governance/siem/destinations/{id}/dead-letter",
    tag = "Governance - Audit Export",
    params(
        ("id" = Uuid, Path, description = "Destination ID"),
        DeadLetterQuery,
    ),
    responses(
        (status = 200, description = "Dead letter events"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Destination not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_dead_letter(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<DeadLetterQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (events, total) = state
        .siem_health_service
        .list_dead_letter_events(tenant_id, id, query.limit, query.offset)
        .await?;

    Ok(Json(serde_json::json!({
        "items": events,
        "total": total,
        "limit": query.limit,
        "offset": query.offset,
    })))
}

/// Re-deliver all dead letter events for a destination.
#[utoipa::path(
    post,
    path = "/governance/siem/destinations/{id}/dead-letter/redeliver",
    tag = "Governance - Audit Export",
    params(("id" = Uuid, Path, description = "Destination ID")),
    responses(
        (status = 200, description = "Re-delivery result", body = RedeliverResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Destination not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn redeliver_dead_letter(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<RedeliverResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let events_requeued = state
        .siem_health_service
        .redeliver_events(tenant_id, id)
        .await?;

    Ok(Json(RedeliverResponse { events_requeued }))
}
