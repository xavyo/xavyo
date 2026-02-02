//! Human-in-the-Loop Approval handlers (F092).
//!
//! Provides HTTP endpoints for managing approval requests for AI agent
//! tool invocations that require human oversight.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{
    ApprovalListResponse, ApprovalResponse, ApprovalStatusResponse, ApproveRequest, DenyRequest,
    ListApprovalsQuery,
};
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Extract user_id from JWT claims.
fn extract_user_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims.sub.parse().map_err(|_| ApiAgentsError::MissingUser)
}

/// GET /approvals - List approval requests.
///
/// Returns a paginated list of approval requests with optional filtering.
/// Supports filtering by status (pending, approved, denied, expired) and agent_id.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/approvals",
    tag = "AI Agent Approvals",
    operation_id = "listApprovals",
    params(
        ("status" = Option<String>, Query, description = "Filter by status: pending, approved, denied, expired"),
        ("agent_id" = Option<Uuid>, Query, description = "Filter by agent ID"),
        ("limit" = Option<i32>, Query, description = "Maximum number of results (default 50, max 100)"),
        ("offset" = Option<i32>, Query, description = "Offset for pagination (default 0)")
    ),
    responses(
        (status = 200, description = "List of approval requests", body = ApprovalListResponse),
        (status = 400, description = "Invalid request parameters"),
        (status = 401, description = "Authentication required"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_approvals(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListApprovalsQuery>,
) -> Result<Json<ApprovalListResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let response = state
        .approval_service
        .list_approvals(tenant_id, query.status, query.agent_id, limit, offset)
        .await?;

    Ok(Json(response))
}

/// GET /approvals/{id} - Get approval request details.
///
/// Returns the full details of an approval request including parameters,
/// context, and decision information.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/approvals/{id}",
    tag = "AI Agent Approvals",
    operation_id = "getApproval",
    params(
        ("id" = Uuid, Path, description = "Approval request ID")
    ),
    responses(
        (status = 200, description = "Approval request details", body = ApprovalResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Approval request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_approval(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(approval_id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .approval_service
        .get_approval(tenant_id, approval_id)
        .await?;

    Ok(Json(response))
}

/// GET /approvals/{id}/status - Check approval status (lightweight).
///
/// Returns a minimal response with just the status for efficient polling.
/// This is the recommended endpoint for agents to poll while waiting.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/approvals/{id}/status",
    tag = "AI Agent Approvals",
    operation_id = "checkApprovalStatus",
    params(
        ("id" = Uuid, Path, description = "Approval request ID")
    ),
    responses(
        (status = 200, description = "Approval status", body = ApprovalStatusResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Approval request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn check_approval_status(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(approval_id): Path<Uuid>,
) -> Result<Json<ApprovalStatusResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .approval_service
        .check_status(tenant_id, approval_id)
        .await?;

    Ok(Json(response))
}

/// POST /approvals/{id}/approve - Approve a pending request.
///
/// Approves a pending approval request. The user must be authorized
/// (agent owner or team member) to approve. Optional conditions can
/// be attached to the approval.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/approvals/{id}/approve",
    tag = "AI Agent Approvals",
    operation_id = "approveRequest",
    params(
        ("id" = Uuid, Path, description = "Approval request ID")
    ),
    request_body = ApproveRequest,
    responses(
        (status = 200, description = "Approval granted", body = ApprovalResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Not authorized to approve this request"),
        (status = 404, description = "Approval request not found"),
        (status = 409, description = "Approval already decided or expired"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn approve_request(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(approval_id): Path<Uuid>,
    Json(request): Json<ApproveRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;

    let response = state
        .approval_service
        .approve(
            tenant_id,
            approval_id,
            user_id,
            request.reason,
            request.conditions,
        )
        .await?;

    Ok((StatusCode::OK, Json(response)))
}

/// POST /approvals/{id}/deny - Deny a pending request.
///
/// Denies a pending approval request. A reason must be provided.
/// The user must be authorized (agent owner or team member) to deny.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/approvals/{id}/deny",
    tag = "AI Agent Approvals",
    operation_id = "denyRequest",
    params(
        ("id" = Uuid, Path, description = "Approval request ID")
    ),
    request_body = DenyRequest,
    responses(
        (status = 200, description = "Approval denied", body = ApprovalResponse),
        (status = 400, description = "Invalid request (reason required)"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Not authorized to deny this request"),
        (status = 404, description = "Approval request not found"),
        (status = 409, description = "Approval already decided or expired"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearerAuth" = []))
))]
pub async fn deny_request(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(approval_id): Path<Uuid>,
    Json(request): Json<DenyRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;

    let response = state
        .approval_service
        .deny(tenant_id, approval_id, user_id, request.reason)
        .await?;

    Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_query_params() {
        let query = ListApprovalsQuery::default();
        assert!(query.status.is_none());
        assert!(query.agent_id.is_none());
        assert!(query.limit.is_none());
        assert!(query.offset.is_none());
    }
}
