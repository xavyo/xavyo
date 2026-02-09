//! CRUD handlers for webhook subscriptions.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;

use crate::error::{ApiResult, WebhookError};
use crate::models::{
    CreateWebhookSubscriptionRequest, EventTypeInfo, EventTypeListResponse, ListSubscriptionsQuery,
    UpdateWebhookSubscriptionRequest, WebhookEventType, WebhookSubscriptionListResponse,
    WebhookSubscriptionResponse,
};
use crate::router::WebhooksState;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, WebhookError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(WebhookError::Unauthorized)
}

// ---------------------------------------------------------------------------
// Subscription CRUD handlers
// ---------------------------------------------------------------------------

/// Create a new webhook subscription.
#[utoipa::path(
    post,
    path = "/webhooks/subscriptions",
    tag = "Webhooks",
    request_body = CreateWebhookSubscriptionRequest,
    responses(
        (status = 201, description = "Subscription created", body = WebhookSubscriptionResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Subscription limit exceeded"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_subscription_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateWebhookSubscriptionRequest>,
) -> ApiResult<(StatusCode, Json<WebhookSubscriptionResponse>)> {
    if !claims.has_role("admin") {
        return Err(WebhookError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let actor_id = Uuid::parse_str(&claims.sub).ok();

    request
        .validate()
        .map_err(|e| WebhookError::Validation(e.to_string()))?;

    let response = state
        .subscription_service
        .create_subscription(tenant_id, actor_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(response)))
}

/// List webhook subscriptions.
#[utoipa::path(
    get,
    path = "/webhooks/subscriptions",
    tag = "Webhooks",
    params(ListSubscriptionsQuery),
    responses(
        (status = 200, description = "Paginated subscription list", body = WebhookSubscriptionListResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_subscriptions_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSubscriptionsQuery>,
) -> ApiResult<Json<WebhookSubscriptionListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .subscription_service
        .list_subscriptions(tenant_id, query)
        .await?;

    Ok(Json(response))
}

/// Get a single webhook subscription.
#[utoipa::path(
    get,
    path = "/webhooks/subscriptions/{id}",
    tag = "Webhooks",
    params(
        ("id" = Uuid, Path, description = "Subscription ID")
    ),
    responses(
        (status = 200, description = "Subscription details", body = WebhookSubscriptionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Subscription not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_subscription_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<WebhookSubscriptionResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .subscription_service
        .get_subscription(tenant_id, id)
        .await?;

    Ok(Json(response))
}

/// Update a webhook subscription.
#[utoipa::path(
    patch,
    path = "/webhooks/subscriptions/{id}",
    tag = "Webhooks",
    params(
        ("id" = Uuid, Path, description = "Subscription ID")
    ),
    request_body = UpdateWebhookSubscriptionRequest,
    responses(
        (status = 200, description = "Subscription updated", body = WebhookSubscriptionResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Subscription not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_subscription_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateWebhookSubscriptionRequest>,
) -> ApiResult<Json<WebhookSubscriptionResponse>> {
    if !claims.has_role("admin") {
        return Err(WebhookError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;

    request
        .validate()
        .map_err(|e| WebhookError::Validation(e.to_string()))?;

    let response = state
        .subscription_service
        .update_subscription(tenant_id, id, request)
        .await?;

    Ok(Json(response))
}

/// Delete a webhook subscription.
#[utoipa::path(
    delete,
    path = "/webhooks/subscriptions/{id}",
    tag = "Webhooks",
    params(
        ("id" = Uuid, Path, description = "Subscription ID")
    ),
    responses(
        (status = 204, description = "Subscription deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Subscription not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_subscription_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(WebhookError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .subscription_service
        .delete_subscription(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Event types handler
// ---------------------------------------------------------------------------

/// List all supported webhook event types.
#[utoipa::path(
    get,
    path = "/webhooks/event-types",
    tag = "Webhooks",
    responses(
        (status = 200, description = "List of event types", body = EventTypeListResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_event_types_handler() -> Json<EventTypeListResponse> {
    let event_types = WebhookEventType::all()
        .into_iter()
        .map(|et| EventTypeInfo {
            event_type: et.as_str().to_string(),
            category: et.category().to_string(),
            description: et.description().to_string(),
        })
        .collect();

    Json(EventTypeListResponse { event_types })
}
