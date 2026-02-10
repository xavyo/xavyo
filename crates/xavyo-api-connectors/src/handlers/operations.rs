//! HTTP handlers for provisioning operations.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ConnectorApiError, Result};
use crate::router::OperationState;
use crate::services::{
    AttemptListResponse, ConflictListResponse, ConflictResponse, DlqListResponse,
    ListConflictsQuery, OperationFilter, OperationListResponse, OperationLogResponse,
    OperationResponse, QueueStatsResponse, ResolveConflictRequest, ResolveOperationRequest,
    TriggerOperationRequest,
};
use xavyo_db::models::{ConflictFilter, ResolutionOutcome};

/// Query parameters for listing operations.
#[derive(Debug, Clone, Deserialize, utoipa::IntoParams)]
pub struct ListOperationsQuery {
    /// Filter by connector ID.
    pub connector_id: Option<Uuid>,

    /// Filter by user ID.
    pub user_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<String>,

    /// Filter by operation type.
    pub operation_type: Option<String>,

    /// Filter operations created on or after this date (RFC3339).
    pub from_date: Option<chrono::DateTime<chrono::Utc>>,

    /// Filter operations created on or before this date (RFC3339).
    pub to_date: Option<chrono::DateTime<chrono::Utc>>,

    /// Maximum results (default: 50).
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

impl Default for ListOperationsQuery {
    fn default() -> Self {
        Self {
            connector_id: None,
            user_id: None,
            status: None,
            operation_type: None,
            from_date: None,
            to_date: None,
            limit: 50,
            offset: 0,
        }
    }
}

fn default_limit() -> i64 {
    50
}

/// List provisioning operations with optional filtering.
#[utoipa::path(
    get,
    path = "/operations",
    tag = "Connector Operations",
    params(ListOperationsQuery),
    responses(
        (status = 200, description = "List of operations", body = OperationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_operations(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListOperationsQuery>,
) -> Result<Json<OperationListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let filter = OperationFilter {
        connector_id: query.connector_id,
        user_id: query.user_id,
        status: query.status,
        operation_type: query.operation_type,
        limit: query.limit.min(100),
        offset: query.offset.max(0),
    };

    let response = state
        .operation_service
        .list_operations(tenant_id, filter)
        .await?;

    Ok(Json(response))
}

/// Get an operation by ID.
#[utoipa::path(
    get,
    path = "/operations/{id}",
    tag = "Connector Operations",
    params(
        ("id" = Uuid, Path, description = "Operation ID")
    ),
    responses(
        (status = 200, description = "Operation details", body = OperationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Operation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_operation(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<OperationResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let operation = state.operation_service.get_operation(tenant_id, id).await?;

    Ok(Json(operation))
}

/// Trigger a manual provisioning operation.
#[utoipa::path(
    post,
    path = "/operations",
    tag = "Connector Operations",
    request_body = TriggerOperationRequest,
    responses(
        (status = 201, description = "Operation created", body = OperationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_operation(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<TriggerOperationRequest>,
) -> Result<(StatusCode, Json<OperationResponse>)> {
    let tenant_id = extract_tenant_id(&claims)?;
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }

    let operation = state
        .operation_service
        .trigger_operation(tenant_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(operation)))
}

/// Retry a failed operation.
#[utoipa::path(
    post,
    path = "/operations/{id}/retry",
    tag = "Connector Operations",
    params(
        ("id" = Uuid, Path, description = "Operation ID")
    ),
    responses(
        (status = 200, description = "Operation scheduled for retry", body = OperationResponse),
        (status = 400, description = "Operation cannot be retried"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Operation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn retry_operation(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<OperationResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }

    let operation = state
        .operation_service
        .retry_operation(tenant_id, id)
        .await?;

    Ok(Json(operation))
}

/// Cancel a pending operation.
#[utoipa::path(
    post,
    path = "/operations/{id}/cancel",
    tag = "Connector Operations",
    params(
        ("id" = Uuid, Path, description = "Operation ID")
    ),
    responses(
        (status = 200, description = "Operation cancelled", body = OperationResponse),
        (status = 400, description = "Operation cannot be cancelled"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Operation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_operation(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<OperationResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }

    let operation = state
        .operation_service
        .cancel_operation(tenant_id, id)
        .await?;

    Ok(Json(operation))
}

/// Get logs for an operation.
#[utoipa::path(
    get,
    path = "/operations/{id}/logs",
    tag = "Connector Operations",
    params(
        ("id" = Uuid, Path, description = "Operation ID")
    ),
    responses(
        (status = 200, description = "Operation logs", body = Vec<OperationLogResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Operation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_operation_logs(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<OperationLogResponse>>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let logs = state
        .operation_service
        .get_operation_logs(tenant_id, id)
        .await?;

    Ok(Json(logs))
}

/// Get queue statistics.
#[utoipa::path(
    get,
    path = "/operations/stats",
    tag = "Connector Operations",
    params(
        ("connector_id" = Option<Uuid>, Query, description = "Filter by connector ID")
    ),
    responses(
        (status = 200, description = "Queue statistics", body = QueueStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_queue_stats(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<StatsQuery>,
) -> Result<Json<QueueStatsResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let stats = state
        .operation_service
        .get_queue_stats(tenant_id, params.connector_id)
        .await?;

    Ok(Json(stats))
}

/// Query parameters for stats endpoint.
#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
pub struct StatsQuery {
    /// Filter by connector ID.
    pub connector_id: Option<Uuid>,
}

/// Query parameters for DLQ listing.
#[derive(Debug, Clone, Deserialize, utoipa::IntoParams)]
pub struct DlqQuery {
    /// Filter by connector ID.
    pub connector_id: Option<Uuid>,

    /// Maximum results (default: 50).
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

impl Default for DlqQuery {
    fn default() -> Self {
        Self {
            connector_id: None,
            limit: 50,
            offset: 0,
        }
    }
}

/// List dead letter queue operations.
#[utoipa::path(
    get,
    path = "/operations/dlq",
    tag = "Connector Operations",
    params(DlqQuery),
    responses(
        (status = 200, description = "List of dead letter operations", body = DlqListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_dead_letter(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<DlqQuery>,
) -> Result<Json<DlqListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .operation_service
        .list_dead_letter(
            tenant_id,
            query.connector_id,
            query.limit.min(100),
            query.offset.max(0),
        )
        .await?;

    Ok(Json(response))
}

/// Resolve a dead letter operation.
#[utoipa::path(
    post,
    path = "/operations/{id}/resolve",
    tag = "Connector Operations",
    params(
        ("id" = Uuid, Path, description = "Operation ID")
    ),
    request_body = ResolveOperationRequest,
    responses(
        (status = 200, description = "Operation resolved", body = OperationResponse),
        (status = 400, description = "Operation cannot be resolved"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Operation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn resolve_operation(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ResolveOperationRequest>,
) -> Result<Json<OperationResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let user_id = Uuid::parse_str(&claims.sub).unwrap_or_else(|_| Uuid::new_v4());

    let operation = state
        .operation_service
        .resolve_operation(tenant_id, id, user_id, request.resolution_notes.as_deref())
        .await?;

    Ok(Json(operation))
}

/// Get operation attempts (execution history).
#[utoipa::path(
    get,
    path = "/operations/{id}/attempts",
    tag = "Connector Operations",
    params(
        ("id" = Uuid, Path, description = "Operation ID")
    ),
    responses(
        (status = 200, description = "Operation attempts", body = AttemptListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Operation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_operation_attempts(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<AttemptListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let attempts = state
        .operation_service
        .get_operation_attempts(tenant_id, id)
        .await?;

    Ok(Json(AttemptListResponse {
        attempts,
        operation_id: id,
    }))
}

/// List conflicts with optional filtering.
#[utoipa::path(
    get,
    path = "/operations/conflicts",
    tag = "Connector Conflicts",
    params(ListConflictsQuery),
    responses(
        (status = 200, description = "List of conflicts", body = ConflictListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 501, description = "Conflict service not configured"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_conflicts(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListConflictsQuery>,
) -> Result<Json<ConflictListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Ensure conflict service is configured
    let conflict_service = state.conflict_service.as_ref().ok_or_else(|| {
        ConnectorApiError::Validation("Conflict service not configured".to_string())
    })?;

    // Parse conflict type if provided
    let conflict_type = if let Some(ref type_str) = query.conflict_type {
        Some(
            type_str
                .parse()
                .map_err(|e: String| ConnectorApiError::Validation(e))?,
        )
    } else {
        None
    };

    let filter = ConflictFilter {
        operation_id: query.operation_id,
        conflict_type,
        resolution_outcome: None,
        pending_only: query.pending_only,
    };

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);

    let conflicts = conflict_service
        .list_conflicts(tenant_id, &filter, limit, offset)
        .await
        .map_err(|e| ConnectorApiError::Conflict(e.to_string()))?;

    let pending_count = conflict_service
        .count_pending_conflicts(tenant_id)
        .await
        .map_err(|e| ConnectorApiError::Conflict(e.to_string()))?;

    let response = ConflictListResponse {
        conflicts: conflicts.iter().map(ConflictResponse::from).collect(),
        pending_count,
        offset,
        limit,
    };

    Ok(Json(response))
}

/// Get a conflict by ID.
#[utoipa::path(
    get,
    path = "/operations/conflicts/{conflict_id}",
    tag = "Connector Conflicts",
    params(
        ("conflict_id" = Uuid, Path, description = "Conflict ID")
    ),
    responses(
        (status = 200, description = "Conflict details", body = ConflictResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Conflict not found"),
        (status = 501, description = "Conflict service not configured"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_conflict(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(conflict_id): Path<Uuid>,
) -> Result<Json<ConflictResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Ensure conflict service is configured
    let conflict_service = state.conflict_service.as_ref().ok_or_else(|| {
        ConnectorApiError::Validation("Conflict service not configured".to_string())
    })?;

    let conflict = conflict_service
        .get_conflict(tenant_id, conflict_id)
        .await
        .map_err(|e| ConnectorApiError::Conflict(e.to_string()))?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "conflict".to_string(),
            id: conflict_id.to_string(),
        })?;

    Ok(Json(ConflictResponse::from(&conflict)))
}

/// Resolve a conflict manually.
#[utoipa::path(
    post,
    path = "/operations/conflicts/{conflict_id}/resolve",
    tag = "Connector Conflicts",
    params(
        ("conflict_id" = Uuid, Path, description = "Conflict ID")
    ),
    request_body = ResolveConflictRequest,
    responses(
        (status = 200, description = "Conflict resolved", body = ConflictResponse),
        (status = 400, description = "Invalid resolution outcome"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Conflict not found"),
        (status = 409, description = "Conflict already resolved"),
        (status = 501, description = "Conflict service not configured"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn resolve_conflict(
    State(state): State<OperationState>,
    Extension(claims): Extension<JwtClaims>,
    Path(conflict_id): Path<Uuid>,
    Json(request): Json<ResolveConflictRequest>,
) -> Result<Json<ConflictResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let user_id = Uuid::parse_str(&claims.sub).unwrap_or_else(|_| Uuid::new_v4());

    // Ensure conflict service is configured
    let conflict_service = state.conflict_service.as_ref().ok_or_else(|| {
        ConnectorApiError::Validation("Conflict service not configured".to_string())
    })?;

    // Parse outcome
    let outcome: ResolutionOutcome = request
        .outcome
        .parse()
        .map_err(|e: String| ConnectorApiError::Validation(e))?;

    let resolved = conflict_service
        .resolve_conflict(
            tenant_id,
            conflict_id,
            user_id,
            outcome,
            request.notes.as_deref(),
        )
        .await
        .map_err(|e| match e {
            xavyo_provisioning::ConflictError::NotFound { id } => ConnectorApiError::NotFound {
                resource: "conflict".to_string(),
                id: id.to_string(),
            },
            xavyo_provisioning::ConflictError::AlreadyResolved { id } => {
                ConnectorApiError::Conflict(format!("Conflict {id} already resolved"))
            }
            other => ConnectorApiError::Conflict(other.to_string()),
        })?;

    Ok(Json(ConflictResponse::from(&resolved)))
}

/// Extract tenant ID from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid> {
    claims
        .tenant_id()
        .map(|tid| *tid.as_uuid())
        .ok_or(ConnectorApiError::Unauthorized {
            message: "Missing tenant ID in token".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_operations_query_default() {
        let query = ListOperationsQuery::default();
        assert!(query.connector_id.is_none());
        assert!(query.status.is_none());
        assert_eq!(query.limit, 50);
        assert_eq!(query.offset, 0);
    }

    #[test]
    fn test_stats_query_default() {
        let query = StatsQuery::default();
        assert!(query.connector_id.is_none());
    }
}
