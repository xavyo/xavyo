//! Lifecycle event handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::{CreateLifecycleEvent, LifecycleEventFilter};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateLifecycleEventRequest, LifecycleEventListResponse, LifecycleEventResponse,
    LifecycleEventWithActionsResponse, ListLifecycleEventsQuery, ProcessEventResult,
};
use crate::router::GovernanceState;

/// List lifecycle events with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/lifecycle-events",
    tag = "Governance - Lifecycle",
    params(ListLifecycleEventsQuery),
    responses(
        (status = 200, description = "List of lifecycle events", body = LifecycleEventListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListLifecycleEventsQuery>,
) -> ApiResult<Json<LifecycleEventListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let filter = LifecycleEventFilter {
        user_id: query.user_id,
        event_type: query.event_type,
        from: query.from,
        to: query.to,
        processed: query.processed,
    };

    let (events, total) = state
        .lifecycle_event_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let page = if limit > 0 { offset / limit } else { 0 };

    Ok(Json(LifecycleEventListResponse {
        items: events.into_iter().map(Into::into).collect(),
        total,
        page,
        page_size: limit,
    }))
}

/// Get a lifecycle event by ID with its actions.
#[utoipa::path(
    get,
    path = "/governance/lifecycle-events/{id}",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Event ID")
    ),
    responses(
        (status = 200, description = "Event details with actions", body = LifecycleEventWithActionsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Event not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_event(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<LifecycleEventWithActionsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let event = state.lifecycle_event_service.get(tenant_id, id).await?;

    let actions = state.lifecycle_event_service.get_event_actions(id).await?;

    // Get snapshot if one exists for this event
    let snapshot = xavyo_db::GovAccessSnapshot::find_by_event(
        state.lifecycle_event_service.pool(),
        tenant_id,
        id,
    )
    .await
    .ok()
    .flatten()
    .map(crate::models::AccessSnapshotSummary::from);

    Ok(Json(LifecycleEventWithActionsResponse {
        event: LifecycleEventResponse::from(event),
        actions: actions.into_iter().map(Into::into).collect(),
        snapshot,
    }))
}

/// Create a lifecycle event (for testing/manual trigger).
#[utoipa::path(
    post,
    path = "/governance/lifecycle-events",
    tag = "Governance - Lifecycle",
    request_body = CreateLifecycleEventRequest,
    responses(
        (status = 201, description = "Event created", body = LifecycleEventResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_event(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateLifecycleEventRequest>,
) -> ApiResult<(StatusCode, Json<LifecycleEventResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateLifecycleEvent {
        user_id: request.user_id,
        event_type: request.event_type,
        attributes_before: request.attributes_before,
        attributes_after: request.attributes_after,
        source: request.source,
    };

    let event = state
        .lifecycle_event_service
        .create(tenant_id, input)
        .await?;

    Ok((StatusCode::CREATED, Json(event.into())))
}

/// Process a lifecycle event (trigger provisioning/deprovisioning).
#[utoipa::path(
    post,
    path = "/governance/lifecycle-events/{id}/process",
    tag = "Governance - Lifecycle",
    params(
        ("id" = Uuid, Path, description = "Event ID")
    ),
    responses(
        (status = 200, description = "Event processed", body = ProcessEventResult),
        (status = 400, description = "Event already processed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Event not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn process_event(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ProcessEventResult>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .lifecycle_event_service
        .process_event(tenant_id, id)
        .await?;

    Ok(Json(result))
}

/// Create and immediately process a lifecycle event.
#[utoipa::path(
    post,
    path = "/governance/lifecycle-events/trigger",
    tag = "Governance - Lifecycle",
    request_body = CreateLifecycleEventRequest,
    responses(
        (status = 200, description = "Event created and processed", body = ProcessEventResult),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_event(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateLifecycleEventRequest>,
) -> ApiResult<Json<ProcessEventResult>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateLifecycleEvent {
        user_id: request.user_id,
        event_type: request.event_type,
        attributes_before: request.attributes_before,
        attributes_after: request.attributes_after,
        source: request.source,
    };

    // Create the event
    let event = state
        .lifecycle_event_service
        .create(tenant_id, input)
        .await?;

    // Process it immediately
    let result = state
        .lifecycle_event_service
        .process_event(tenant_id, event.id)
        .await?;

    Ok(Json(result))
}
