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

/// Outbound SCIM target full-sync and reconciliation are not wired.
///
/// Callers must not receive HTTP 202 with `status: running` and no worker.
pub fn reject_unimplemented_scim_target_sync() -> ConnectorApiError {
    ConnectorApiError::not_implemented(
        "SCIM target sync/reconciliation execution is not implemented",
    )
}

async fn require_active_target(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    target_id: Uuid,
) -> Result<ScimTarget> {
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
    Ok(target)
}

/// POST /admin/scim-targets/:id/sync — Trigger a full sync.
///
/// Returns 501 until a worker actually performs the outbound sync.
#[utoipa::path(
    post,
    path = "/admin/scim-targets/{target_id}/sync",
    tag = "SCIM Target Sync",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    responses(
        (status = 501, description = "Outbound full sync is not implemented"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found"),
        (status = 409, description = "Target is not active")
    ),
    security(("bearerAuth" = []))
)]
pub async fn trigger_sync(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
) -> Result<(StatusCode, Json<TriggerSyncResponse>)> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();
    require_active_target(pool, tenant_id, target_id).await?;
    Err(reject_unimplemented_scim_target_sync())
}

/// POST /admin/scim-targets/:id/reconcile — Trigger a reconciliation.
///
/// Returns 501 until a worker actually performs the outbound reconciliation.
#[utoipa::path(
    post,
    path = "/admin/scim-targets/{target_id}/reconcile",
    tag = "SCIM Target Sync",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    responses(
        (status = 501, description = "Outbound reconciliation is not implemented"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found"),
        (status = 409, description = "Target is not active")
    ),
    security(("bearerAuth" = []))
)]
pub async fn trigger_reconciliation(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
) -> Result<(StatusCode, Json<TriggerSyncResponse>)> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();
    require_active_target(pool, tenant_id, target_id).await?;
    Err(reject_unimplemented_scim_target_sync())
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
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
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
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn scim_target_sync_is_501_without_running_body() {
        let response = reject_unimplemented_scim_target_sync().into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert!(
            !response.status().is_success(),
            "unimplemented SCIM target sync must not be HTTP success"
        );

        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("response body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("not_implemented"), "{text}");
        for needle in [
            r#""status":"running""#,
            "Full sync initiated",
            "Reconciliation initiated",
            "sync_run_id",
        ] {
            assert!(
                !text.contains(needle),
                "501 body must not look like a started sync ({needle}): {text}"
            );
        }
    }

    #[test]
    fn trigger_handlers_do_not_persist_fake_running_runs() {
        let src = include_str!("scim_sync.rs");
        let production = src
            .split("mod tests")
            .next()
            .expect("production source before tests");
        assert!(
            production.contains("reject_unimplemented_scim_target_sync"),
            "trigger handlers must fail closed"
        );
        for needle in [
            format!("{}_{}", "create_if_no", "active_run"),
            format!("{} sync initiated", "Full"),
            format!("{} initiated", "Reconciliation"),
            format!("status: \"{}\"", "running"),
        ] {
            assert!(
                !production.contains(&needle),
                "SCIM target trigger handlers must not fake a running sync ({needle})"
            );
        }
    }
}
