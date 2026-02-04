//! Access snapshot handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::{AccessSnapshotFilter, GovAccessSnapshot};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{AccessSnapshotListResponse, AccessSnapshotResponse, ListAccessSnapshotsQuery};
use crate::router::GovernanceState;

/// List access snapshots with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/access-snapshots",
    tag = "Governance - Lifecycle",
    params(ListAccessSnapshotsQuery),
    responses(
        (status = 200, description = "List of access snapshots", body = AccessSnapshotListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_snapshots(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListAccessSnapshotsQuery>,
) -> ApiResult<Json<AccessSnapshotListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let filter = AccessSnapshotFilter {
        user_id: query.user_id,
        event_id: query.event_id,
        snapshot_type: query.snapshot_type,
    };

    let snapshots = GovAccessSnapshot::list_by_tenant(
        state.lifecycle_event_service.pool(),
        tenant_id,
        &filter,
        limit,
        offset,
    )
    .await
    .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

    // Count total (simplified - in production would use a count query)
    let total = snapshots.len() as i64;
    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(AccessSnapshotListResponse {
        items: snapshots.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get an access snapshot by ID.
#[utoipa::path(
    get,
    path = "/governance/access-snapshots/{id}",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Snapshot ID")
    ),
    responses(
        (status = 200, description = "Snapshot details", body = AccessSnapshotResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Snapshot not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_snapshot(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AccessSnapshotResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let snapshot =
        GovAccessSnapshot::find_by_id(state.lifecycle_event_service.pool(), tenant_id, id)
            .await
            .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Access snapshot {id} not found"
            )))?;

    Ok(Json(snapshot.into()))
}

/// List access snapshots for a specific user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/access-snapshots",
    tag = "Governance - Lifecycle",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Results to skip")
    ),
    responses(
        (status = 200, description = "List of user's access snapshots", body = AccessSnapshotListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_user_snapshots(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<ListAccessSnapshotsQuery>,
) -> ApiResult<Json<AccessSnapshotListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let snapshots = GovAccessSnapshot::list_by_user(
        state.lifecycle_event_service.pool(),
        tenant_id,
        user_id,
        limit,
        offset,
    )
    .await
    .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

    let total =
        GovAccessSnapshot::count_by_user(state.lifecycle_event_service.pool(), tenant_id, user_id)
            .await
            .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(AccessSnapshotListResponse {
        items: snapshots.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}
