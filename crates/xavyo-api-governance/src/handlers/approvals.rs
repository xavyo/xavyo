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

use xavyo_db::models::User;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    access_request_sod_violations, ApprovalActionResponse, ApproveRequestRequest, DecisionSummary,
    ListPendingApprovalsQuery, PendingApprovalItem, PendingApprovalListResponse,
    RejectRequestRequest, SodViolationSummary, SodWarningSummary,
};
use crate::router::GovernanceState;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Prefer a non-empty display name, otherwise the user's email.
fn user_display_name(display_name: Option<&str>, email: &str) -> String {
    display_name
        .filter(|name| !name.is_empty())
        .unwrap_or(email)
        .to_string()
}

async fn load_user_display_names(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    user_ids: impl IntoIterator<Item = Uuid>,
) -> ApiResult<HashMap<Uuid, String>> {
    let mut names = HashMap::new();
    for user_id in user_ids {
        if names.contains_key(&user_id) {
            continue;
        }
        if let Some(user) = User::find_by_id_in_tenant(pool, tenant_id, user_id).await? {
            names.insert(
                user_id,
                user_display_name(user.display_name.as_deref(), &user.email),
            );
        }
    }
    Ok(names)
}

fn pending_sod_warnings(
    sod: Option<&[SodViolationSummary]>,
    entitlement_names: &HashMap<Uuid, String>,
) -> Option<Vec<SodWarningSummary>> {
    sod.map(|items| {
        items
            .iter()
            .map(|v| SodWarningSummary {
                rule_name: v.rule_name.clone(),
                severity: v.severity,
                conflicting_entitlement_name: entitlement_names
                    .get(&v.conflicting_entitlement_id)
                    .cloned()
                    .unwrap_or_else(|| format!("Unknown ({})", v.conflicting_entitlement_id)),
            })
            .collect()
    })
}

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
    let (tenant_id, user_id) = crate::handlers::access_requests::requester_from_claims(&claims)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (approvals, total) = state
        .approval_service
        .get_pending_approvals(tenant_id, user_id, limit, offset)
        .await?;

    // Batch fetch entitlement names for requested and SoD-conflicting entitlements.
    let mut entitlement_ids: Vec<Uuid> = approvals
        .iter()
        .map(|info| info.request.entitlement_id)
        .collect();
    let mut sod_by_request: HashMap<Uuid, Option<Vec<SodViolationSummary>>> = HashMap::new();
    for info in &approvals {
        let sod = access_request_sod_violations(info.request.sod_violations.clone())?;
        if let Some(items) = &sod {
            for v in items {
                entitlement_ids.push(v.conflicting_entitlement_id);
            }
        }
        sod_by_request.insert(info.request.id, sod);
    }

    let mut entitlement_names: HashMap<Uuid, String> = HashMap::new();
    for entitlement_id in entitlement_ids {
        if let std::collections::hash_map::Entry::Vacant(e) =
            entitlement_names.entry(entitlement_id)
        {
            match state
                .entitlement_service
                .get_entitlement(tenant_id, entitlement_id)
                .await
            {
                Ok(entitlement) => {
                    e.insert(entitlement.name);
                }
                Err(xavyo_governance::error::GovernanceError::EntitlementNotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    let mut user_ids: Vec<Uuid> = approvals
        .iter()
        .map(|info| info.request.requester_id)
        .collect();
    for info in &approvals {
        for decision in &info.previous_decisions {
            user_ids.push(decision.approver_id);
        }
    }
    let user_names = load_user_display_names(state.pool(), tenant_id, user_ids).await?;

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
                    approver_name: user_names.get(&d.approver_id).cloned(),
                    comments: d.comments,
                    decided_at: d.decided_at,
                })
                .collect();

            let entitlement_name = entitlement_names
                .get(&info.request.entitlement_id)
                .cloned()
                .unwrap_or_else(|| format!("Unknown ({})", info.request.entitlement_id));
            let sod_warnings = pending_sod_warnings(
                sod_by_request
                    .get(&info.request.id)
                    .and_then(Option::as_deref),
                &entitlement_names,
            );

            PendingApprovalItem {
                request_id: info.request.id,
                requester_id: info.request.requester_id,
                requester_name: user_names.get(&info.request.requester_id).cloned(),
                entitlement_id: info.request.entitlement_id,
                entitlement_name,
                justification: info.request.justification.clone(),
                current_step: info.current_step,
                total_steps: info.total_steps,
                has_sod_warning: info.request.has_sod_warning,
                sod_warnings,
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

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::GovSodSeverity;

    #[test]
    fn user_display_name_prefers_non_empty_display_name() {
        assert_eq!(user_display_name(Some("Ada"), "ada@example.com"), "Ada");
        assert_eq!(
            user_display_name(Some(""), "ada@example.com"),
            "ada@example.com"
        );
        assert_eq!(
            user_display_name(None, "ada@example.com"),
            "ada@example.com"
        );
    }

    #[test]
    fn pending_sod_warnings_fill_conflicting_entitlement_names() {
        let entitlement_id = Uuid::new_v4();
        let mut names = HashMap::new();
        names.insert(entitlement_id, "Payroll".to_string());
        let sod = [SodViolationSummary {
            rule_id: Uuid::new_v4(),
            rule_name: "no-pay".to_string(),
            severity: GovSodSeverity::High,
            conflicting_entitlement_id: entitlement_id,
        }];
        let warnings = pending_sod_warnings(Some(&sod), &names).expect("warnings");
        assert_eq!(warnings[0].conflicting_entitlement_name, "Payroll");
        assert_eq!(warnings[0].rule_name, "no-pay");
    }

    #[test]
    fn pending_approvals_do_not_skip_entitlement_lookup_errors() {
        let src = include_str!("approvals.rs");
        let production = src.split("mod tests").next().expect("production source");
        let list = production
            .split("pub async fn list_pending_approvals")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("list_pending_approvals");
        assert!(
            !list.contains("if let Ok(entitlement)") && list.contains("EntitlementNotFound"),
            "pending approvals must not hide entitlement lookup errors as unknown names"
        );
        assert!(
            list.contains("load_user_display_names(")
                && list.contains("pending_sod_warnings(")
                && list.contains("access_request_sod_violations(")
                && !list.contains("requester_name: None")
                && !list.contains("approver_name: None")
                && !list.contains("sod_warnings: None"),
            "pending approvals must look up requester/approver names and parse SoD warnings"
        );
    }
}
