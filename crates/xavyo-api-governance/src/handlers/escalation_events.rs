//! Escalation event handlers for governance API (F054).
//!
//! Provides audit trail query capabilities for escalation events:
//! - List escalation events with filters (T053)
//! - Get escalation history for a specific request (T054)
//! - Cancel pending escalation for a request (T067-T069)
//! - Reset escalation to original approver (T068-T070)

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{EscalationEventFilter, GovAccessRequest, GovEscalationEvent};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CancelEscalationResponse, EscalationEventListResponse, EscalationEventResponse,
    EscalationHistoryResponse, ListEscalationEventsQuery, ResetEscalationResponse,
};
use crate::router::GovernanceState;

/// List escalation events with optional filters.
///
/// Supports filtering by:
/// - `request_id`: Events for a specific access request
/// - `original_approver_id`: Events where a specific user was the original approver
/// - `escalation_target_id`: Events where a specific user received an escalation
/// - reason: Filter by escalation reason (timeout, `manual_escalation`, `target_unavailable`)
/// - `from_date/to_date`: Date range filtering
#[utoipa::path(
    get,
    path = "/governance/escalation-events",
    tag = "Governance - Workflow Escalation",
    params(ListEscalationEventsQuery),
    responses(
        (status = 200, description = "List of escalation events", body = EscalationEventListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_escalation_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListEscalationEventsQuery>,
) -> ApiResult<Json<EscalationEventListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    // Build filter from query parameters
    let filter = EscalationEventFilter {
        request_id: query.request_id,
        original_approver_id: query.original_approver_id,
        escalation_target_id: query.escalation_target_id,
        from_date: query.from_date,
        to_date: query.to_date,
        reason: query.reason,
    };

    // Query events with filter
    let pool = state.escalation_policy_service.pool();
    let events =
        GovEscalationEvent::list_by_tenant(pool, tenant_id, &filter, limit, offset).await?;
    let total = GovEscalationEvent::count_by_tenant(pool, tenant_id, &filter).await?;

    let items: Vec<EscalationEventResponse> = events
        .into_iter()
        .map(EscalationEventResponse::from)
        .collect();

    Ok(Json(EscalationEventListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get escalation history for a specific access request.
///
/// Returns all escalation events for the request in chronological order,
/// along with summary information about the current escalation state.
#[utoipa::path(
    get,
    path = "/governance/access-requests/{request_id}/escalation-history",
    tag = "Governance - Workflow Escalation",
    params(
        ("request_id" = Uuid, Path, description = "Access Request ID")
    ),
    responses(
        (status = 200, description = "Escalation history for the request", body = EscalationHistoryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Access request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_request_escalation_history(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(request_id): Path<Uuid>,
) -> ApiResult<Json<EscalationHistoryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let pool = state.escalation_policy_service.pool();

    // Verify the request exists and belongs to the tenant
    let request = GovAccessRequest::find_by_id(pool, tenant_id, request_id)
        .await?
        .ok_or_else(|| {
            ApiGovernanceError::NotFound(format!("Access request {request_id} not found"))
        })?;

    // Get all escalation events for this request
    let events = GovEscalationEvent::find_by_request(pool, tenant_id, request_id).await?;

    let total_escalations = events.len();
    let events: Vec<EscalationEventResponse> = events
        .into_iter()
        .map(EscalationEventResponse::from)
        .collect();

    // Check if levels have been exhausted (look for metadata indicating this)
    let levels_exhausted = events.iter().any(|e| {
        e.metadata
            .as_ref()
            .and_then(|m| m.get("levels_exhausted"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    });

    Ok(Json(EscalationHistoryResponse {
        request_id,
        events,
        current_level: request.current_escalation_level,
        levels_exhausted,
        total_escalations,
    }))
}

/// Cancel pending escalation for an access request.
///
/// Stops the escalation timer but keeps the current assignee (the escalation
/// target who received the work item). The request remains at its current
/// escalation level for audit purposes.
///
/// This is useful when:
/// - An external event makes escalation unnecessary
/// - The current assignee needs more time without further escalation
/// - Manual intervention is overriding the automatic process
#[utoipa::path(
    post,
    path = "/governance/access-requests/{request_id}/cancel-escalation",
    tag = "Governance - Workflow Escalation",
    params(
        ("request_id" = Uuid, Path, description = "Access Request ID")
    ),
    responses(
        (status = 200, description = "Escalation cancelled successfully", body = CancelEscalationResponse),
        (status = 400, description = "Request has not been escalated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Access request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_escalation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(request_id): Path<Uuid>,
) -> ApiResult<Json<CancelEscalationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .escalation_service
        .cancel_escalation(tenant_id, request_id, user_id)
        .await
        .map_err(ApiGovernanceError::from)?;

    Ok(Json(CancelEscalationResponse {
        success: result.success,
        previous_level: result.previous_level,
        current_assignee_id: result.current_assignee_id,
        message: format!(
            "Escalation cancelled. Work item remains with current assignee. Previous escalation level: {}",
            result.previous_level
        ),
    }))
}

/// Reset escalation to original approver.
///
/// Returns the work item to the original approver and restarts the escalation
/// timer from the beginning. The escalation level is reset to 0.
///
/// This is useful when:
/// - The original approver is now available
/// - A mistake was made in the escalation process
/// - The request needs to start fresh with the original workflow
#[utoipa::path(
    post,
    path = "/governance/access-requests/{request_id}/reset-escalation",
    tag = "Governance - Workflow Escalation",
    params(
        ("request_id" = Uuid, Path, description = "Access Request ID")
    ),
    responses(
        (status = 200, description = "Escalation reset successfully", body = ResetEscalationResponse),
        (status = 400, description = "Request has not been escalated or cannot determine original approver"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Access request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_escalation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(request_id): Path<Uuid>,
) -> ApiResult<Json<ResetEscalationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .escalation_service
        .reset_escalation(tenant_id, request_id, user_id)
        .await
        .map_err(ApiGovernanceError::from)?;

    Ok(Json(ResetEscalationResponse {
        success: result.success,
        previous_level: result.previous_level,
        original_approver_id: result.original_approver_id,
        new_deadline: result.new_deadline,
        message: format!(
            "Escalation reset. Work item returned to original approver. Previous escalation level: {}",
            result.previous_level
        ),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_list_escalation_events_query_default() {
        let query = ListEscalationEventsQuery::default();
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.offset, Some(0));
        assert!(query.request_id.is_none());
        assert!(query.original_approver_id.is_none());
        assert!(query.escalation_target_id.is_none());
        assert!(query.reason.is_none());
        assert!(query.from_date.is_none());
        assert!(query.to_date.is_none());
    }

    #[test]
    fn test_escalation_event_response_from() {
        use xavyo_db::models::{EscalationReason, EscalationTargetType};

        let event = GovEscalationEvent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            step_order: 1,
            escalation_level: 1,
            original_approver_id: Some(Uuid::new_v4()),
            escalation_target_type: EscalationTargetType::Manager,
            escalation_target_ids: vec![Uuid::new_v4()],
            reason: EscalationReason::Timeout,
            previous_deadline: Some(Utc::now()),
            new_deadline: Some(Utc::now()),
            metadata: None,
            created_at: Utc::now(),
        };

        let response = EscalationEventResponse::from(event.clone());
        assert_eq!(response.id, event.id);
        assert_eq!(response.request_id, event.request_id);
        assert_eq!(response.escalation_level, 1);
    }
}
