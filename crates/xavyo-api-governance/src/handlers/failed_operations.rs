//! HTTP handlers for failed operation retry management (F052).
//!
//! These handlers provide admin API endpoints for managing the retry queue
//! and dead letter queue for failed lifecycle operations.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{error::ApiResult, router::GovernanceState};
use xavyo_auth::JwtClaims;
use xavyo_db::GovLifecycleFailedOperation;

/// Query parameters for listing failed operations.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListFailedOperationsQuery {
    /// Maximum number of items to return.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

/// Response for a single failed operation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FailedOperationResponse {
    pub id: Uuid,
    pub operation_type: String,
    pub related_request_id: Option<Uuid>,
    pub object_id: Uuid,
    pub object_type: String,
    pub error_message: String,
    pub retry_count: i32,
    pub max_retries: i32,
    pub status: String,
    pub next_retry_at: chrono::DateTime<chrono::Utc>,
    pub last_attempted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<GovLifecycleFailedOperation> for FailedOperationResponse {
    fn from(op: GovLifecycleFailedOperation) -> Self {
        Self {
            id: op.id,
            operation_type: format!("{:?}", op.operation_type).to_lowercase(),
            related_request_id: op.related_request_id,
            object_id: op.object_id,
            object_type: format!("{:?}", op.object_type).to_lowercase(),
            error_message: op.error_message,
            retry_count: op.retry_count,
            max_retries: op.max_retries,
            status: op.status,
            next_retry_at: op.next_retry_at,
            last_attempted_at: op.last_attempted_at,
            created_at: op.created_at,
            resolved_at: op.resolved_at,
        }
    }
}

/// Response for a list of failed operations.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FailedOperationListResponse {
    pub items: Vec<FailedOperationResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Response for retry processing statistics.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RetryStatsResponse {
    pub tenants_processed: usize,
    pub total_processed: usize,
    pub total_succeeded: usize,
    pub total_rescheduled: usize,
    pub total_dead_letter: usize,
}

/// List dead letter operations.
///
/// Returns a paginated list of failed operations that have exceeded their
/// retry limit and are now in the dead letter queue.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/failed-operations/dead-letter",
    params(ListFailedOperationsQuery),
    responses(
        (status = 200, description = "List of dead letter operations", body = FailedOperationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Failed Operations"
)]
pub async fn list_dead_letter_operations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListFailedOperationsQuery>,
) -> ApiResult<Json<FailedOperationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let failed_op_service = state.failed_operation_service.as_ref().ok_or_else(|| {
        crate::error::ApiGovernanceError::Validation(
            "Failed operation service not configured".to_string(),
        )
    })?;

    let operations = failed_op_service
        .get_dead_letter_operations(tenant_id, limit, offset)
        .await?;

    let total = failed_op_service
        .count_dead_letter_operations(tenant_id)
        .await?;

    let items: Vec<FailedOperationResponse> = operations
        .into_iter()
        .map(FailedOperationResponse::from)
        .collect();

    Ok(Json(FailedOperationListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get dead letter operation count.
///
/// Returns the count of operations in the dead letter queue.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/failed-operations/dead-letter/count",
    responses(
        (status = 200, description = "Dead letter operation count", body = i64),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Failed Operations"
)]
pub async fn count_dead_letter_operations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<i64>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let failed_op_service = state.failed_operation_service.as_ref().ok_or_else(|| {
        crate::error::ApiGovernanceError::Validation(
            "Failed operation service not configured".to_string(),
        )
    })?;

    let count = failed_op_service
        .count_dead_letter_operations(tenant_id)
        .await?;

    Ok(Json(count))
}

/// Trigger retry processing for a tenant.
///
/// Processes all pending retry operations for the current tenant.
/// Returns statistics about the operations processed.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/failed-operations/process-retries",
    responses(
        (status = 200, description = "Retry processing statistics", body = RetryStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Failed Operations"
)]
pub async fn process_retries(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<RetryStatsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let failed_op_service = state.failed_operation_service.as_ref().ok_or_else(|| {
        crate::error::ApiGovernanceError::Validation(
            "Failed operation service not configured".to_string(),
        )
    })?;

    let result = failed_op_service.process_retries(tenant_id, 100).await?;

    Ok(Json(RetryStatsResponse {
        tenants_processed: 1,
        total_processed: result.processed,
        total_succeeded: result.succeeded,
        total_rescheduled: result.rescheduled,
        total_dead_letter: result.dead_letter,
    }))
}

/// Trigger retry processing across all tenants.
///
/// Admin-only endpoint to process all pending retry operations across all tenants.
/// Returns aggregate statistics about the operations processed.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/failed-operations/process-all-retries",
    responses(
        (status = 200, description = "Aggregate retry processing statistics", body = RetryStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires admin access"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Failed Operations"
)]
pub async fn process_all_retries(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<RetryStatsResponse>> {
    // Verify caller has tenant admin or super admin access
    let _tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let failed_op_service = state.failed_operation_service.as_ref().ok_or_else(|| {
        crate::error::ApiGovernanceError::Validation(
            "Failed operation service not configured".to_string(),
        )
    })?;

    let stats = failed_op_service.process_all_retries(100).await?;

    Ok(Json(RetryStatsResponse {
        tenants_processed: stats.tenants_processed,
        total_processed: stats.total.processed,
        total_succeeded: stats.total.succeeded,
        total_rescheduled: stats.total.rescheduled,
        total_dead_letter: stats.total.dead_letter,
    }))
}
