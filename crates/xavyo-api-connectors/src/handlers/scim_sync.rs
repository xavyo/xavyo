//! HTTP handlers for SCIM sync and reconciliation operations (F087 - US5).
//!
//! Provides endpoints to trigger full syncs, reconciliation runs,
//! and view sync run history.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{ScimSyncRun, ScimTarget};

use crate::error::{ConnectorApiError, Result};
use crate::handlers::scim_targets::ScimTargetState;

/// Query parameters for listing sync runs.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListSyncRunsQuery {
    pub run_type: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Response for a triggered sync/reconciliation.
#[derive(Debug, Serialize, ToSchema)]
pub struct TriggerSyncResponse {
    pub sync_run_id: Uuid,
    pub status: String,
    pub message: String,
}

/// Response for listing sync runs.
#[derive(Debug, Serialize, ToSchema)]
pub struct SyncRunListResponse {
    pub target_id: Uuid,
    pub items: Vec<ScimSyncRun>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ConnectorApiError::Unauthorized {
            message: "Missing tenant_id in claims".to_string(),
        })
}

/// POST /admin/scim-targets/:id/sync — Trigger a full sync.
///
/// Returns 202 Accepted with `sync_run_id`, or 409 if a sync is already running.
#[utoipa::path(
    post,
    path = "/admin/scim-targets/{target_id}/sync",
    tag = "SCIM Target Sync",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    responses(
        (status = 202, description = "Full sync initiated", body = TriggerSyncResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found"),
        (status = 409, description = "Sync already in progress")
    ),
    security(("bearerAuth" = []))
)]
pub async fn trigger_sync(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
) -> Result<(StatusCode, Json<TriggerSyncResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();
    let triggered_by = Uuid::parse_str(&claims.sub).ok();

    // Verify target exists and is active.
    let target = ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    if target.status != "active" {
        return Err(ConnectorApiError::Conflict(format!(
            "SCIM target is not active (status: {})",
            target.status,
        )));
    }

    // Atomically create a sync run only if no active run exists.
    let run = ScimSyncRun::create_if_no_active_run(
        pool,
        xavyo_db::models::CreateScimSyncRun {
            tenant_id,
            target_id,
            run_type: "full_sync".to_string(),
            triggered_by,
            total_resources: 0,
        },
    )
    .await?
    .ok_or_else(|| {
        ConnectorApiError::Conflict("A sync is already running for this target".to_string())
    })?;

    // TODO: Dispatch actual sync work to background task using SyncEngine.

    Ok((
        StatusCode::ACCEPTED,
        Json(TriggerSyncResponse {
            sync_run_id: run.id,
            status: "running".to_string(),
            message: "Full sync initiated".to_string(),
        }),
    ))
}

/// POST /admin/scim-targets/:id/reconcile — Trigger a reconciliation.
///
/// Returns 202 Accepted with `sync_run_id`, or 409 if a sync is already running.
#[utoipa::path(
    post,
    path = "/admin/scim-targets/{target_id}/reconcile",
    tag = "SCIM Target Sync",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    responses(
        (status = 202, description = "Reconciliation initiated", body = TriggerSyncResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found"),
        (status = 409, description = "Sync already in progress")
    ),
    security(("bearerAuth" = []))
)]
pub async fn trigger_reconciliation(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
) -> Result<(StatusCode, Json<TriggerSyncResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();
    let triggered_by = Uuid::parse_str(&claims.sub).ok();

    // Verify target exists and is active.
    let target = ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    if target.status != "active" {
        return Err(ConnectorApiError::Conflict(format!(
            "SCIM target is not active (status: {})",
            target.status,
        )));
    }

    // Atomically create a reconciliation run only if no active run exists.
    let run = ScimSyncRun::create_if_no_active_run(
        pool,
        xavyo_db::models::CreateScimSyncRun {
            tenant_id,
            target_id,
            run_type: "reconciliation".to_string(),
            triggered_by,
            total_resources: 0,
        },
    )
    .await?
    .ok_or_else(|| {
        ConnectorApiError::Conflict(
            "A sync/reconciliation is already running for this target".to_string(),
        )
    })?;

    Ok((
        StatusCode::ACCEPTED,
        Json(TriggerSyncResponse {
            sync_run_id: run.id,
            status: "running".to_string(),
            message: "Reconciliation initiated".to_string(),
        }),
    ))
}

/// GET /admin/scim-targets/:id/sync-runs — List sync runs for a target.
#[utoipa::path(
    get,
    path = "/admin/scim-targets/{target_id}/sync-runs",
    tag = "SCIM Target Sync",
    params(
        ("target_id" = Uuid, Path, description = "SCIM target ID"),
        ListSyncRunsQuery
    ),
    responses(
        (status = 200, description = "List of sync runs", body = SyncRunListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_sync_runs(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
    Query(query): Query<ListSyncRunsQuery>,
) -> Result<Json<SyncRunListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();

    // Verify target exists.
    ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let (items, total_count) = ScimSyncRun::list_by_target(
        pool,
        tenant_id,
        target_id,
        query.run_type.as_deref(),
        limit,
        offset,
    )
    .await?;

    Ok(Json(SyncRunListResponse {
        target_id,
        items,
        total_count,
        limit,
        offset,
    }))
}

/// GET /admin/scim-targets/:id/sync-runs/:run_id — Get a specific sync run.
#[utoipa::path(
    get,
    path = "/admin/scim-targets/{target_id}/sync-runs/{run_id}",
    tag = "SCIM Target Sync",
    params(
        ("target_id" = Uuid, Path, description = "SCIM target ID"),
        ("run_id" = Uuid, Path, description = "Sync run ID")
    ),
    responses(
        (status = 200, description = "Sync run details", body = ScimSyncRun),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target or run not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_sync_run(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path((target_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ScimSyncRun>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();

    // Verify target exists.
    ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    let run = ScimSyncRun::get_by_id(pool, tenant_id, run_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_sync_run".to_string(),
            id: run_id.to_string(),
        })?;

    // Verify the run belongs to the correct target.
    if run.target_id != target_id {
        return Err(ConnectorApiError::NotFound {
            resource: "scim_sync_run".to_string(),
            id: run_id.to_string(),
        });
    }

    Ok(Json(run))
}
