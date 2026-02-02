//! Approval handlers for governance API.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::GovDecisionType;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ApprovalActionResponse, ApproveRequestRequest, DecisionSummary, ListPendingApprovalsQuery,
    PendingApprovalItem, PendingApprovalListResponse, RejectRequestRequest,
};
use crate::router::GovernanceState;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Get pending approvals for the current user.
#[utoipa::path(
    get,
    path = "/governance/my-approvals",
    tag = "Governance - Approvals",
    params(ListPendingApprovalsQuery),
    responses(
        (status = 200, description = "List of pending approvals", body = PendingApprovalListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_pending_approvals(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListPendingApprovalsQuery>,
) -> ApiResult<Json<PendingApprovalListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (approvals, total) = state
        .approval_service
        .get_pending_approvals(tenant_id, user_id, limit, offset)
        .await?;

    // Batch fetch entitlement names for all pending approvals
    let entitlement_ids: Vec<Uuid> = approvals
        .iter()
        .map(|info| info.request.entitlement_id)
        .collect();

    let mut entitlement_names: HashMap<Uuid, String> = HashMap::new();
    for entitlement_id in entitlement_ids {
        if let std::collections::hash_map::Entry::Vacant(e) =
            entitlement_names.entry(entitlement_id)
        {
            if let Ok(entitlement) = state
                .entitlement_service
                .get_entitlement(tenant_id, entitlement_id)
                .await
            {
                e.insert(entitlement.name);
            }
        }
    }

    // Convert to API response format
    let items: Vec<PendingApprovalItem> = approvals
        .into_iter()
        .map(|info| {
            let previous_decisions: Vec<DecisionSummary> = info
                .previous_decisions
                .into_iter()
                .map(|d| DecisionSummary {
                    step_order: d.step_order,
                    decision: d.decision,
                    approver_id: d.approver_id,
                    approver_name: None, // Would need user lookup
                    comments: d.comments,
                    decided_at: d.decided_at,
                })
                .collect();

            let entitlement_name = entitlement_names
                .get(&info.request.entitlement_id)
                .cloned()
                .unwrap_or_else(|| format!("Unknown ({})", info.request.entitlement_id));

            PendingApprovalItem {
                request_id: info.request.id,
                requester_id: info.request.requester_id,
                requester_name: None, // Would need user lookup
                entitlement_id: info.request.entitlement_id,
                entitlement_name,
                justification: info.request.justification.clone(),
                current_step: info.current_step,
                total_steps: info.total_steps,
                has_sod_warning: info.request.has_sod_warning,
                sod_warnings: None, // Would need to parse from JSON
                is_delegate: info.is_delegate,
                delegator_id: info.delegator_id,
                submitted_at: info.request.created_at,
                previous_decisions,
            }
        })
        .collect();

    Ok(Json(PendingApprovalListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Approve an access request.
#[utoipa::path(
    post,
    path = "/governance/access-requests/{id}/approve",
    tag = "Governance - Approvals",
    params(
        ("id" = Uuid, Path, description = "Access Request ID")
    ),
    request_body = ApproveRequestRequest,
    responses(
        (status = 200, description = "Request approved", body = ApprovalActionResponse),
        (status = 400, description = "Request is not pending"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot approve own request or not authorized"),
        (status = 404, description = "Access request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn approve_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    publisher: Option<Extension<EventPublisher>>,
    Path(id): Path<Uuid>,
    Json(request): Json<ApproveRequestRequest>,
) -> ApiResult<Json<ApprovalActionResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .approval_service
        .approve_request(tenant_id, id, user_id, request.comments)
        .await?;

    let message = match result.provisioned_assignment_id {
        Some(_) => "Request approved and entitlement provisioned".to_string(),
        None => "Request approved, advancing to next approval level".to_string(),
    };

    // F085: Publish access_request.approved webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "access_request.approved".to_string(),
            tenant_id,
            actor_id: Some(user_id),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "request_id": id,
                "approver_id": user_id,
                "new_status": "approved",
            }),
        });
    }

    Ok(Json(ApprovalActionResponse {
        request_id: id,
        new_status: result.new_status,
        decision: GovDecisionType::Approved,
        message,
        provisioned_assignment_id: result.provisioned_assignment_id,
    }))
}

/// Reject an access request.
#[utoipa::path(
    post,
    path = "/governance/access-requests/{id}/reject",
    tag = "Governance - Approvals",
    params(
        ("id" = Uuid, Path, description = "Access Request ID")
    ),
    request_body = RejectRequestRequest,
    responses(
        (status = 200, description = "Request rejected", body = ApprovalActionResponse),
        (status = 400, description = "Request is not pending or comments required"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot reject own request or not authorized"),
        (status = 404, description = "Access request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    publisher: Option<Extension<EventPublisher>>,
    Path(id): Path<Uuid>,
    Json(request): Json<RejectRequestRequest>,
) -> ApiResult<Json<ApprovalActionResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .approval_service
        .reject_request(tenant_id, id, user_id, request.comments)
        .await?;

    // F085: Publish access_request.denied webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "access_request.denied".to_string(),
            tenant_id,
            actor_id: Some(user_id),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "request_id": id,
                "reviewer_id": user_id,
            }),
        });
    }

    Ok(Json(ApprovalActionResponse {
        request_id: id,
        new_status: result.new_status,
        decision: GovDecisionType::Rejected,
        message: "Request rejected".to_string(),
        provisioned_assignment_id: None,
    }))
}
