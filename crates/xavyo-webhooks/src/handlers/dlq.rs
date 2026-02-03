//! HTTP handlers for webhook dead letter queue API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::{ApiResult, WebhookError};
use crate::router::WebhooksState;
use crate::services::dlq_service::{
    BulkReplayRequest, BulkReplayResponse, DlqEntryDetail, DlqEntryList, ReplayResponse,
};
use xavyo_db::models::DlqFilter;

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, WebhookError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(WebhookError::Unauthorized)
}

/// Query parameters for listing DLQ entries.
#[derive(Debug, Clone, Deserialize)]
pub struct ListDlqQuery {
    pub subscription_id: Option<Uuid>,
    pub event_type: Option<String>,
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub include_replayed: bool,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

// ---------------------------------------------------------------------------
// DLQ List and Detail Handlers
// ---------------------------------------------------------------------------

/// List dead letter queue entries.
#[utoipa::path(
    get,
    path = "/webhooks/dlq",
    tag = "Dead Letter Queue",
    params(
        ("subscription_id" = Option<Uuid>, Query, description = "Filter by subscription"),
        ("event_type" = Option<String>, Query, description = "Filter by event type"),
        ("from" = Option<String>, Query, description = "Filter entries created after this time"),
        ("to" = Option<String>, Query, description = "Filter entries created before this time"),
        ("include_replayed" = Option<bool>, Query, description = "Include replayed entries"),
        ("limit" = Option<i64>, Query, description = "Max entries to return (default 50, max 100)"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination"),
    ),
    responses(
        (status = 200, description = "List of DLQ entries", body = DlqEntryList),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_dlq_entries_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDlqQuery>,
) -> ApiResult<Json<DlqEntryList>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let filter = DlqFilter {
        subscription_id: query.subscription_id,
        event_type: query.event_type,
        from: query.from,
        to: query.to,
        include_replayed: query.include_replayed,
    };

    let result = state
        .dlq_service
        .list_entries(tenant_id, filter, query.limit, query.offset)
        .await?;

    Ok(Json(result))
}

/// Get details of a DLQ entry.
#[utoipa::path(
    get,
    path = "/webhooks/dlq/{id}",
    tag = "Dead Letter Queue",
    params(
        ("id" = Uuid, Path, description = "DLQ entry ID")
    ),
    responses(
        (status = 200, description = "DLQ entry details", body = DlqEntryDetail),
        (status = 404, description = "Entry not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_dlq_entry_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<DlqEntryDetail>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let detail = state.dlq_service.get_entry_detail(tenant_id, id).await?;

    Ok(Json(detail))
}

/// Delete a DLQ entry.
#[utoipa::path(
    delete,
    path = "/webhooks/dlq/{id}",
    tag = "Dead Letter Queue",
    params(
        ("id" = Uuid, Path, description = "DLQ entry ID")
    ),
    responses(
        (status = 204, description = "Entry deleted"),
        (status = 404, description = "Entry not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_dlq_entry_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = extract_tenant_id(&claims)?;

    let deleted = state.dlq_service.delete_entry(tenant_id, id).await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(WebhookError::DlqEntryNotFound)
    }
}

// ---------------------------------------------------------------------------
// Replay Handlers
// ---------------------------------------------------------------------------

/// Replay a single DLQ entry.
#[utoipa::path(
    post,
    path = "/webhooks/dlq/{id}/replay",
    tag = "Dead Letter Queue",
    params(
        ("id" = Uuid, Path, description = "DLQ entry ID")
    ),
    responses(
        (status = 200, description = "Webhook queued for replay", body = ReplayResponse),
        (status = 404, description = "Entry not found"),
        (status = 409, description = "Entry already replayed"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn replay_single_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ReplayResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state.dlq_service.replay_single(tenant_id, id).await?;

    Ok(Json(response))
}

/// Bulk replay DLQ entries.
#[utoipa::path(
    post,
    path = "/webhooks/dlq/replay",
    tag = "Dead Letter Queue",
    request_body = BulkReplayRequest,
    responses(
        (status = 200, description = "Webhooks queued for replay", body = BulkReplayResponse),
        (status = 400, description = "Invalid filter criteria"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn replay_bulk_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BulkReplayRequest>,
) -> ApiResult<Json<BulkReplayResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state.dlq_service.replay_bulk(tenant_id, request).await?;

    Ok(Json(response))
}
