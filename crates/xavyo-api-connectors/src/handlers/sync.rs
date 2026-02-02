//! Sync API handlers for live synchronization.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiError, ConnectorApiError, Result as ApiResult};
use crate::router::SyncState;

/// Response for sync configuration.
#[derive(Debug, Serialize, ToSchema)]
pub struct SyncConfigResponse {
    pub connector_id: Uuid,
    pub enabled: bool,
    pub sync_mode: String,
    pub polling_interval_secs: i32,
    pub batch_size: i32,
    pub rate_limit_per_minute: i32,
    pub conflict_resolution: String,
}

/// Request to update sync configuration.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSyncConfigRequest {
    pub enabled: Option<bool>,
    pub sync_mode: Option<String>,
    pub polling_interval_secs: Option<i32>,
    pub batch_size: Option<i32>,
    pub rate_limit_per_minute: Option<i32>,
    pub conflict_resolution: Option<String>,
}

/// Response for sync status.
#[derive(Debug, Serialize, ToSchema)]
pub struct SyncStatusResponse {
    pub connector_id: Uuid,
    pub current_state: String,
    pub is_throttled: bool,
    pub changes_processed: i64,
    pub changes_pending: i32,
    pub conflicts_pending: i32,
    pub current_rate: f64,
    pub last_sync_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sync_error: Option<String>,
}

/// Response for sync token.
#[derive(Debug, Serialize, ToSchema)]
pub struct SyncTokenResponse {
    pub connector_id: Uuid,
    pub token_value: String,
    pub token_type: String,
    pub sequence_number: i64,
    pub is_valid: bool,
    pub last_processed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Response for sync trigger.
#[derive(Debug, Serialize, ToSchema)]
pub struct SyncTriggerResponse {
    pub connector_id: Uuid,
    pub processed: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub conflicts: usize,
    pub has_more: bool,
}

/// Query parameters for listing changes.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListChangesQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for an inbound change.
#[derive(Debug, Serialize, ToSchema)]
pub struct InboundChangeResponse {
    pub id: Uuid,
    pub change_type: String,
    pub external_uid: String,
    pub object_class: String,
    pub sync_situation: String,
    pub processing_status: String,
    pub linked_identity_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Response for listing changes.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListChangesResponse {
    pub changes: Vec<InboundChangeResponse>,
    pub total: i64,
}

/// Query parameters for listing conflicts.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListConflictsQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
}

/// Response for a sync conflict.
#[derive(Debug, Serialize, ToSchema)]
pub struct SyncConflictResponse {
    pub id: Uuid,
    pub change_id: Uuid,
    pub conflict_type: String,
    pub status: String,
    pub inbound_value: serde_json::Value,
    pub outbound_value: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Response for listing conflicts.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListConflictsResponse {
    pub conflicts: Vec<SyncConflictResponse>,
    pub total: i64,
}

/// Request to resolve a conflict.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ResolveConflictRequest {
    pub resolution: String,
    pub notes: Option<String>,
    pub resolved_by: Uuid,
}

/// Request to manually link a change.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LinkChangeRequest {
    pub user_id: Uuid,
}

// Handler implementations

/// Get sync configuration for a connector.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/sync/config",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Sync configuration", body = SyncConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_sync_config(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<Json<SyncConfigResponse>, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    let config = state
        .sync_service
        .get_config(connector_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(SyncConfigResponse {
        connector_id: config.connector_id,
        enabled: config.enabled,
        sync_mode: config.sync_mode.as_str().to_string(),
        polling_interval_secs: config.polling_interval_secs,
        batch_size: config.batch_size,
        rate_limit_per_minute: config.rate_limit_per_minute,
        conflict_resolution: config.conflict_resolution.as_str().to_string(),
    }))
}

/// Update sync configuration.
#[utoipa::path(
    put,
    path = "/connectors/{connector_id}/sync/config",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = UpdateSyncConfigRequest,
    responses(
        (status = 200, description = "Updated sync configuration", body = SyncConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn update_sync_config(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Json(request): Json<UpdateSyncConfigRequest>,
) -> Result<Json<SyncConfigResponse>, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    let config = state
        .sync_service
        .update_config(
            connector_id,
            request.enabled,
            request.sync_mode,
            request.polling_interval_secs,
            request.batch_size,
            request.rate_limit_per_minute,
            request.conflict_resolution,
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(SyncConfigResponse {
        connector_id: config.connector_id,
        enabled: config.enabled,
        sync_mode: config.sync_mode.as_str().to_string(),
        polling_interval_secs: config.polling_interval_secs,
        batch_size: config.batch_size,
        rate_limit_per_minute: config.rate_limit_per_minute,
        conflict_resolution: config.conflict_resolution.as_str().to_string(),
    }))
}

/// Enable sync for a connector.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/sync/enable",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Sync enabled"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn enable_sync(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    state
        .sync_service
        .enable(connector_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Disable sync for a connector.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/sync/disable",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Sync disabled"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn disable_sync(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    state
        .sync_service
        .disable(connector_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get sync status for a connector.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/sync/status",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Sync status", body = SyncStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_sync_status(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<Json<SyncStatusResponse>, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    let status = state
        .sync_service
        .get_status(connector_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(SyncStatusResponse {
        connector_id: status.connector_id,
        current_state: status.current_state.as_str().to_string(),
        is_throttled: status.is_throttled,
        changes_processed: status.changes_processed,
        changes_pending: status.changes_pending,
        conflicts_pending: status.conflicts_pending,
        current_rate: status.current_rate,
        last_sync_completed_at: status.last_sync_completed_at,
        last_sync_error: status.last_sync_error,
    }))
}

/// Get sync token for a connector.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/sync/token",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Sync token", body = SyncTokenResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Token not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_sync_token(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<Json<SyncTokenResponse>, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    let token = state
        .sync_service
        .get_token(connector_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    match token {
        Some(t) => Ok(Json(SyncTokenResponse {
            connector_id: t.connector_id,
            token_value: t.token_value,
            token_type: t.token_type.as_str().to_string(),
            sequence_number: t.sequence_number,
            is_valid: t.is_valid,
            last_processed_at: t.last_processed_at,
        })),
        None => Err(ApiError::not_found("Sync token not found")),
    }
}

/// Reset sync token (trigger full resync).
#[utoipa::path(
    delete,
    path = "/connectors/{connector_id}/sync/token",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Token reset"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn reset_sync_token(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    state
        .sync_service
        .reset_token(connector_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Trigger a sync cycle manually.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/sync/trigger",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Sync triggered", body = SyncTriggerResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn trigger_sync(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> Result<Json<SyncTriggerResponse>, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    let result = state
        .sync_service
        .trigger_sync(connector_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(SyncTriggerResponse {
        connector_id,
        processed: result.processed,
        succeeded: result.succeeded,
        failed: result.failed,
        conflicts: result.conflicts,
        has_more: result.has_more,
    }))
}

/// List inbound changes.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/sync/changes",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ListChangesQuery
    ),
    responses(
        (status = 200, description = "List of changes", body = ListChangesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_changes(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Query(query): Query<ListChangesQuery>,
) -> Result<Json<ListChangesResponse>, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    let (changes, total) = state
        .sync_service
        .list_changes(
            connector_id,
            query.status.as_deref(),
            query.limit.unwrap_or(50),
            query.offset.unwrap_or(0),
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let changes = changes
        .into_iter()
        .map(|c| InboundChangeResponse {
            id: c.id,
            change_type: format!("{:?}", c.change_type).to_lowercase(),
            external_uid: c.external_uid,
            object_class: c.object_class,
            sync_situation: c.sync_situation.as_str().to_string(),
            processing_status: c.processing_status.as_str().to_string(),
            linked_identity_id: c.linked_identity_id,
            created_at: c.created_at,
        })
        .collect();

    Ok(Json(ListChangesResponse { changes, total }))
}

/// Get a specific inbound change.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/sync/changes/{change_id}",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("change_id" = Uuid, Path, description = "Change ID")
    ),
    responses(
        (status = 200, description = "Change details", body = InboundChangeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Change not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_change(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, change_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<InboundChangeResponse>, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    let change = state
        .sync_service
        .get_change(connector_id, change_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Change not found"))?;

    Ok(Json(InboundChangeResponse {
        id: change.id,
        change_type: format!("{:?}", change.change_type).to_lowercase(),
        external_uid: change.external_uid,
        object_class: change.object_class,
        sync_situation: change.sync_situation.as_str().to_string(),
        processing_status: change.processing_status.as_str().to_string(),
        linked_identity_id: change.linked_identity_id,
        created_at: change.created_at,
    }))
}

/// Retry processing a failed change.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/sync/changes/{change_id}/retry",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("change_id" = Uuid, Path, description = "Change ID")
    ),
    responses(
        (status = 204, description = "Retry initiated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Change not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn retry_change(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, change_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    state
        .sync_service
        .retry_change(connector_id, change_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Manually link a change to a user.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/sync/changes/{change_id}/link",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("change_id" = Uuid, Path, description = "Change ID")
    ),
    request_body = LinkChangeRequest,
    responses(
        (status = 204, description = "Change linked"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Change not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn link_change(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, change_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<LinkChangeRequest>,
) -> Result<StatusCode, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    state
        .sync_service
        .link_change(connector_id, change_id, request.user_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// List sync conflicts.
#[utoipa::path(
    get,
    path = "/connectors/{connector_id}/sync/conflicts",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ListConflictsQuery
    ),
    responses(
        (status = 200, description = "List of conflicts", body = ListConflictsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_sync_conflicts(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
    Query(query): Query<ListConflictsQuery>,
) -> Result<Json<ListConflictsResponse>, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    let (conflicts, total) = state
        .sync_service
        .list_conflicts(
            connector_id,
            query.status.as_deref(),
            query.limit.unwrap_or(50),
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let conflicts = conflicts
        .into_iter()
        .map(|c| SyncConflictResponse {
            id: c.id,
            change_id: c.inbound_change_id,
            conflict_type: c.conflict_type.as_str().to_string(),
            status: c.resolution_strategy.as_str().to_string(),
            inbound_value: c.inbound_value,
            outbound_value: c.outbound_value.unwrap_or(serde_json::json!({})),
            created_at: c.created_at,
        })
        .collect();

    Ok(Json(ListConflictsResponse { conflicts, total }))
}

/// Resolve a sync conflict.
#[utoipa::path(
    post,
    path = "/connectors/{connector_id}/sync/conflicts/{conflict_id}/resolve",
    tag = "Connector Sync",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID"),
        ("conflict_id" = Uuid, Path, description = "Conflict ID")
    ),
    request_body = ResolveConflictRequest,
    responses(
        (status = 204, description = "Conflict resolved"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Conflict not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn resolve_sync_conflict(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
    Path((connector_id, conflict_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<ResolveConflictRequest>,
) -> Result<StatusCode, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    state
        .sync_service
        .resolve_conflict(
            connector_id,
            conflict_id,
            &request.resolution,
            request.notes,
            request.resolved_by,
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get sync status for all connectors.
#[utoipa::path(
    get,
    path = "/connectors/sync/status",
    tag = "Connector Sync",
    responses(
        (status = 200, description = "All sync statuses", body = Vec<SyncStatusResponse>),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_all_sync_status(
    State(state): State<SyncState>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<Vec<SyncStatusResponse>>, ApiError> {
    let _tenant_id = extract_tenant_id(&claims)?;

    let statuses = state
        .sync_service
        .get_all_status()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let responses = statuses
        .into_iter()
        .map(|status| SyncStatusResponse {
            connector_id: status.connector_id,
            current_state: status.current_state.as_str().to_string(),
            is_throttled: status.is_throttled,
            changes_processed: status.changes_processed,
            changes_pending: status.changes_pending,
            conflicts_pending: status.conflicts_pending,
            current_rate: status.current_rate,
            last_sync_completed_at: status.last_sync_completed_at,
            last_sync_error: status.last_sync_error,
        })
        .collect();

    Ok(Json(responses))
}

/// Extract tenant ID from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> ApiResult<Uuid> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ConnectorApiError::Validation(
            "Missing tenant_id in claims".to_string(),
        ))
}
