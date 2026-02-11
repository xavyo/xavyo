//! HTTP handlers for bulk state operations (F052).
//!
//! These handlers provide endpoints for performing bulk state transitions
//! on multiple objects at once, useful for organizational changes.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use crate::{
    error::ApiResult,
    models::{
        BulkOperationDetailResponse, BulkOperationListResponse, BulkOperationResponse,
        CreateBulkOperationRequest, ListBulkOperationsQuery,
    },
    router::GovernanceState,
};
use xavyo_auth::JwtClaims;

/// Create a bulk state operation.
///
/// Creates a new bulk operation to transition multiple objects to a target state.
/// Maximum of 1000 objects per operation.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/bulk-operations",
    request_body = CreateBulkOperationRequest,
    responses(
        (status = 202, description = "Bulk operation created and queued for processing", body = BulkOperationResponse),
        (status = 400, description = "Invalid request or too many objects"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - Bulk Operations"
)]
pub async fn create_bulk_operation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateBulkOperationRequest>,
) -> ApiResult<(StatusCode, Json<BulkOperationResponse>)> {
    if !claims.has_role("admin") {
        return Err(crate::error::ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| crate::error::ApiGovernanceError::Unauthorized)?;
    let operation = state
        .bulk_operation_service
        .create_bulk_operation(tenant_id, user_id, request)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(operation)))
}

/// List bulk operations.
///
/// Returns a paginated list of bulk operations with optional filters.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/bulk-operations",
    params(ListBulkOperationsQuery),
    responses(
        (status = 200, description = "List of bulk operations", body = BulkOperationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - Bulk Operations"
)]
pub async fn list_bulk_operations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListBulkOperationsQuery>,
) -> ApiResult<Json<BulkOperationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let operations = state
        .bulk_operation_service
        .list_bulk_operations(tenant_id, &params)
        .await?;
    Ok(Json(operations))
}

/// Get a bulk operation by ID.
///
/// Returns detailed information about a bulk operation including
/// progress and any failures.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/bulk-operations/{operation_id}",
    params(
        ("operation_id" = Uuid, Path, description = "Bulk operation ID")
    ),
    responses(
        (status = 200, description = "Bulk operation details", body = BulkOperationDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Operation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - Bulk Operations"
)]
pub async fn get_bulk_operation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(operation_id): Path<Uuid>,
) -> ApiResult<Json<BulkOperationDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let operation = state
        .bulk_operation_service
        .get_bulk_operation(tenant_id, operation_id)
        .await?;
    Ok(Json(operation))
}

/// Cancel a bulk operation.
///
/// Cancels a pending or in-progress bulk operation.
/// Objects that have already been processed will remain in their new state.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/bulk-operations/{operation_id}/cancel",
    params(
        ("operation_id" = Uuid, Path, description = "Bulk operation ID")
    ),
    responses(
        (status = 200, description = "Operation cancelled", body = BulkOperationResponse),
        (status = 400, description = "Operation cannot be cancelled"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Operation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - Bulk Operations"
)]
pub async fn cancel_bulk_operation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(operation_id): Path<Uuid>,
) -> ApiResult<Json<BulkOperationResponse>> {
    if !claims.has_role("admin") {
        return Err(crate::error::ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| crate::error::ApiGovernanceError::Unauthorized)?;
    let operation = state
        .bulk_operation_service
        .cancel_bulk_operation(tenant_id, operation_id, user_id)
        .await?;
    Ok(Json(operation))
}

/// Trigger processing of pending bulk operations.
///
/// This endpoint is typically called by a background job scheduler.
/// Processes pending bulk operations in order.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/bulk-operations/process",
    responses(
        (status = 200, description = "Processing triggered"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - Bulk Operations"
)]
pub async fn process_bulk_operations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(crate::error::ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    state
        .bulk_operation_service
        .process_pending_operations(tenant_id)
        .await?;
    Ok(StatusCode::OK)
}
