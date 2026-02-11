//! Risk event handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CleanupEventsResponse, CreateRiskEventRequest, ListRiskEventsQuery, RiskEventListResponse,
    RiskEventResponse,
};
use crate::router::GovernanceState;

/// List risk events for a user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/risk-events",
    tag = "Governance - Risk Events",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ListRiskEventsQuery
    ),
    responses(
        (status = 200, description = "List of risk events", body = RiskEventListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_user_risk_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<ListRiskEventsQuery>,
) -> ApiResult<Json<RiskEventListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .risk_event_service
        .list_for_user(tenant_id, user_id, query)
        .await?;

    Ok(Json(response))
}

/// Create a new risk event.
#[utoipa::path(
    post,
    path = "/governance/risk-events",
    tag = "Governance - Risk Events",
    request_body = CreateRiskEventRequest,
    responses(
        (status = 201, description = "Risk event created", body = RiskEventResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_risk_event(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateRiskEventRequest>,
) -> ApiResult<(StatusCode, Json<RiskEventResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let event = state.risk_event_service.create(tenant_id, request).await?;

    Ok((StatusCode::CREATED, Json(event)))
}

/// Get a risk event by ID.
#[utoipa::path(
    get,
    path = "/governance/risk-events/{event_id}",
    tag = "Governance - Risk Events",
    params(
        ("event_id" = Uuid, Path, description = "Risk event ID")
    ),
    responses(
        (status = 200, description = "Risk event details", body = RiskEventResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk event not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_risk_event(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(event_id): Path<Uuid>,
) -> ApiResult<Json<RiskEventResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let event = state.risk_event_service.get(tenant_id, event_id).await?;

    Ok(Json(event))
}

/// Delete a risk event.
#[utoipa::path(
    delete,
    path = "/governance/risk-events/{event_id}",
    tag = "Governance - Risk Events",
    params(
        ("event_id" = Uuid, Path, description = "Risk event ID")
    ),
    responses(
        (status = 204, description = "Risk event deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Risk event not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_risk_event(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(event_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state.risk_event_service.delete(tenant_id, event_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Cleanup expired risk events.
#[utoipa::path(
    post,
    path = "/governance/risk-events/cleanup",
    tag = "Governance - Risk Events",
    responses(
        (status = 200, description = "Cleanup result", body = CleanupEventsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cleanup_expired_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<CleanupEventsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state.risk_event_service.cleanup_expired(tenant_id).await?;

    Ok(Json(response))
}
