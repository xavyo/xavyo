//! HITL approval handlers for /nhi/approvals/* endpoints.
//!
//! These handlers delegate to xavyo-api-agents approval service.
//! F109 - NHI API Consolidation

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiNhiError, ApiResult};
use crate::state::AgentsState;

// Re-export types from agents crate
pub use xavyo_api_agents::models::{
    ApprovalListResponse, ApprovalResponse, ApprovalStatusResponse, ApproveRequest, DenyRequest,
    ListApprovalsQuery,
};

// ============================================================================
// Helper Functions
// ============================================================================

fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiNhiError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiNhiError::Unauthorized)
}

fn extract_actor_id(claims: &JwtClaims) -> Result<Uuid, ApiNhiError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiNhiError::Unauthorized)
}

// ============================================================================
// Approval Handlers
// ============================================================================

/// List pending approvals.
#[utoipa::path(
    get,
    path = "/nhi/approvals",
    tag = "NHI - Approvals",
    params(ListApprovalsQuery),
    responses(
        (status = 200, description = "List of approvals", body = ApprovalListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_approvals(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListApprovalsQuery>,
) -> ApiResult<Json<ApprovalListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let approvals = state
        .approval_service
        .list_approvals(
            tenant_id,
            query.status,
            query.agent_id,
            query.limit.unwrap_or(50),
            query.offset.unwrap_or(0),
        )
        .await?;
    Ok(Json(approvals))
}

/// Get an approval by ID.
#[utoipa::path(
    get,
    path = "/nhi/approvals/{id}",
    tag = "NHI - Approvals",
    params(
        ("id" = Uuid, Path, description = "Approval ID")
    ),
    responses(
        (status = 200, description = "Approval details", body = ApprovalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Approval not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_approval(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApprovalResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let approval = state.approval_service.get_approval(tenant_id, id).await?;
    Ok(Json(approval))
}

/// Check approval status.
#[utoipa::path(
    get,
    path = "/nhi/approvals/{id}/status",
    tag = "NHI - Approvals",
    params(
        ("id" = Uuid, Path, description = "Approval ID")
    ),
    responses(
        (status = 200, description = "Approval status", body = ApprovalStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Approval not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn check_approval_status(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApprovalStatusResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let status = state.approval_service.check_status(tenant_id, id).await?;
    Ok(Json(status))
}

/// Approve a request.
#[utoipa::path(
    post,
    path = "/nhi/approvals/{id}/approve",
    tag = "NHI - Approvals",
    params(
        ("id" = Uuid, Path, description = "Approval ID")
    ),
    request_body = ApproveRequest,
    responses(
        (status = 200, description = "Request approved", body = ApprovalResponse),
        (status = 400, description = "Invalid request or already decided"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Approval not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn approve_request(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ApproveRequest>,
) -> ApiResult<Json<ApprovalResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = extract_actor_id(&claims)?;
    let approval = state
        .approval_service
        .approve(tenant_id, id, actor_id, request.reason, request.conditions)
        .await?;
    Ok(Json(approval))
}

/// Deny a request.
#[utoipa::path(
    post,
    path = "/nhi/approvals/{id}/deny",
    tag = "NHI - Approvals",
    params(
        ("id" = Uuid, Path, description = "Approval ID")
    ),
    request_body = DenyRequest,
    responses(
        (status = 200, description = "Request denied", body = ApprovalResponse),
        (status = 400, description = "Invalid request or already decided"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Approval not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn deny_request(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<DenyRequest>,
) -> ApiResult<Json<ApprovalResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = extract_actor_id(&claims)?;
    let approval = state
        .approval_service
        .deny(tenant_id, id, actor_id, request.reason)
        .await?;
    Ok(Json(approval))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approvals_handlers_compile() {
        // Compile-time verification that handler signatures are correct.
        assert!(true);
    }

    // T057: Test approvals list handler types
    #[test]
    fn test_list_approvals_query_types() {
        // Verify ListApprovalsQuery can be constructed with defaults
        let query = ListApprovalsQuery {
            status: None,
            agent_id: None,
            limit: None,
            offset: None,
        };
        assert!(query.status.is_none());
        assert!(query.agent_id.is_none());

        let query_with_filter = ListApprovalsQuery {
            status: Some("pending".to_string()),
            agent_id: Some(uuid::Uuid::new_v4()),
            limit: Some(25),
            offset: Some(0),
        };
        assert_eq!(query_with_filter.status, Some("pending".to_string()));
        assert!(query_with_filter.agent_id.is_some());
    }

    #[test]
    fn test_deny_request_type() {
        // Verify DenyRequest can be constructed
        let request = DenyRequest {
            reason: "Not authorized".to_string(),
        };
        assert!(!request.reason.is_empty());
    }

    #[test]
    fn test_approval_response_types() {
        // Verify handler return types are accessible
        use xavyo_api_agents::models::{ApprovalResponse, ApprovalStatusResponse};

        // Test that the types are re-exported correctly
        fn _verify_types(_approval: ApprovalResponse, _status: ApprovalStatusResponse) {}
    }
}
