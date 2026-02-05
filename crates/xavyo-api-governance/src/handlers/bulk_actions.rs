//! Bulk action handlers for F-064: Bulk Action Engine.
//!
//! Provides HTTP handlers for creating, previewing, and managing bulk actions.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    BulkActionDetailResponse, BulkActionListResponse, BulkActionPreviewResponse,
    BulkActionResponse, CreateBulkActionRequest, ExpressionValidationResponse,
    ListBulkActionsQuery, PreviewBulkActionQuery, ValidateExpressionRequest,
};
use crate::router::GovernanceState;

/// List bulk actions with filtering and pagination.
#[utoipa::path(
    get,
    path = "/admin/bulk-actions",
    tag = "Governance - Bulk Actions",
    params(ListBulkActionsQuery),
    responses(
        (status = 200, description = "List of bulk actions", body = BulkActionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_bulk_actions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListBulkActionsQuery>,
) -> ApiResult<Json<BulkActionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .bulk_action_service
        .list_bulk_actions(tenant_id, &query)
        .await?;

    Ok(Json(response))
}

/// Get a bulk action by ID.
#[utoipa::path(
    get,
    path = "/admin/bulk-actions/{id}",
    tag = "Governance - Bulk Actions",
    params(
        ("id" = Uuid, Path, description = "Bulk action ID")
    ),
    responses(
        (status = 200, description = "Bulk action details", body = BulkActionDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Bulk action not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_bulk_action(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<BulkActionDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let action = state
        .bulk_action_service
        .get_bulk_action(tenant_id, id)
        .await?;

    Ok(Json(action))
}

/// Create a new bulk action.
#[utoipa::path(
    post,
    path = "/admin/bulk-actions",
    tag = "Governance - Bulk Actions",
    request_body = CreateBulkActionRequest,
    responses(
        (status = 201, description = "Bulk action created", body = BulkActionResponse),
        (status = 400, description = "Validation error or invalid expression"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_bulk_action(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateBulkActionRequest>,
) -> ApiResult<(StatusCode, Json<BulkActionResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Validate request
    request
        .validate()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;

    let action = state
        .bulk_action_service
        .create_bulk_action(tenant_id, request, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(action)))
}

/// Preview the users that would be affected by a bulk action.
#[utoipa::path(
    post,
    path = "/admin/bulk-actions/{id}/preview",
    tag = "Governance - Bulk Actions",
    params(
        ("id" = Uuid, Path, description = "Bulk action ID"),
        PreviewBulkActionQuery
    ),
    responses(
        (status = 200, description = "Preview results", body = BulkActionPreviewResponse),
        (status = 400, description = "Action already executed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Bulk action not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn preview_bulk_action(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<PreviewBulkActionQuery>,
) -> ApiResult<Json<BulkActionPreviewResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let preview = state
        .bulk_action_service
        .preview_bulk_action(tenant_id, id, &query)
        .await?;

    Ok(Json(preview))
}

/// Validate a filter expression.
#[utoipa::path(
    post,
    path = "/admin/bulk-actions/validate-expression",
    tag = "Governance - Bulk Actions",
    request_body = ValidateExpressionRequest,
    responses(
        (status = 200, description = "Validation result", body = ExpressionValidationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn validate_expression(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<ValidateExpressionRequest>,
) -> ApiResult<Json<ExpressionValidationResponse>> {
    // Verify authentication (tenant_id not needed for validation)
    let _ = claims.tenant_id().ok_or(ApiGovernanceError::Unauthorized)?;

    // Validate request format
    request
        .validate()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;

    let result = state
        .bulk_action_service
        .validate_expression(&request.expression);

    Ok(Json(result))
}

/// Execute a bulk action.
///
/// Transitions the action from 'pending' to 'running', executes the action
/// on each matched user, and updates the final status to 'completed' or 'failed'.
#[utoipa::path(
    post,
    path = "/admin/bulk-actions/{id}/execute",
    tag = "Governance - Bulk Actions",
    params(
        ("id" = Uuid, Path, description = "Bulk action ID")
    ),
    responses(
        (status = 200, description = "Bulk action execution result", body = BulkActionDetailResponse),
        (status = 400, description = "Action already executed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Bulk action not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn execute_bulk_action(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<BulkActionDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .bulk_action_service
        .execute_bulk_action(tenant_id, id, user_id)
        .await?;

    Ok(Json(result))
}

/// Cancel a pending or running bulk action.
///
/// Only actions in 'pending' or 'running' status can be cancelled.
/// Cancelled actions cannot be executed.
#[utoipa::path(
    post,
    path = "/admin/bulk-actions/{id}/cancel",
    tag = "Governance - Bulk Actions",
    params(
        ("id" = Uuid, Path, description = "Bulk action ID")
    ),
    responses(
        (status = 200, description = "Bulk action cancelled", body = BulkActionDetailResponse),
        (status = 400, description = "Action cannot be cancelled"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Bulk action not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_bulk_action(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<BulkActionDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .bulk_action_service
        .cancel_bulk_action(tenant_id, id)
        .await?;

    Ok(Json(result))
}

/// Delete a bulk action.
///
/// Only actions in 'completed', 'failed', or 'cancelled' status can be deleted.
#[utoipa::path(
    delete,
    path = "/admin/bulk-actions/{id}",
    tag = "Governance - Bulk Actions",
    params(
        ("id" = Uuid, Path, description = "Bulk action ID")
    ),
    responses(
        (status = 204, description = "Bulk action deleted"),
        (status = 400, description = "Action cannot be deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Bulk action not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_bulk_action(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .bulk_action_service
        .delete_bulk_action(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    // Handler tests will be added as integration tests in Phase 3
}
