//! Delivery history query handlers.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::{ApiResult, WebhookError};
use crate::models::{
    ListDeliveriesQuery, WebhookDeliveryDetailResponse, WebhookDeliveryListResponse,
    WebhookDeliveryResponse,
};
use crate::router::WebhooksState;
use xavyo_db::models::{WebhookDelivery, WebhookSubscription};

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, WebhookError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(WebhookError::Unauthorized)
}

// ---------------------------------------------------------------------------
// Delivery history handlers
// ---------------------------------------------------------------------------

/// List delivery attempts for a subscription.
#[utoipa::path(
    get,
    path = "/webhooks/subscriptions/{id}/deliveries",
    tag = "Webhooks",
    params(
        ("id" = Uuid, Path, description = "Subscription ID"),
        ListDeliveriesQuery,
    ),
    responses(
        (status = 200, description = "Paginated delivery list", body = WebhookDeliveryListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Subscription not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_deliveries_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Path(subscription_id): Path<Uuid>,
    Query(query): Query<ListDeliveriesQuery>,
) -> ApiResult<Json<WebhookDeliveryListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Verify subscription exists and belongs to tenant
    WebhookSubscription::find_by_id(state.pool(), tenant_id, subscription_id)
        .await
        .map_err(WebhookError::Database)?
        .ok_or(WebhookError::SubscriptionNotFound)?;

    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);
    let status = query.status.as_deref();

    let deliveries = WebhookDelivery::list_by_subscription(
        state.pool(),
        tenant_id,
        subscription_id,
        limit,
        offset,
        status,
    )
    .await
    .map_err(WebhookError::Database)?;

    let total =
        WebhookDelivery::count_by_subscription(state.pool(), tenant_id, subscription_id, status)
            .await
            .map_err(WebhookError::Database)?;

    let items = deliveries.into_iter().map(delivery_to_response).collect();

    Ok(Json(WebhookDeliveryListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get detailed information about a specific delivery attempt.
#[utoipa::path(
    get,
    path = "/webhooks/subscriptions/{id}/deliveries/{delivery_id}",
    tag = "Webhooks",
    params(
        ("id" = Uuid, Path, description = "Subscription ID"),
        ("delivery_id" = Uuid, Path, description = "Delivery ID"),
    ),
    responses(
        (status = 200, description = "Delivery details", body = WebhookDeliveryDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Delivery or subscription not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_delivery_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Path((subscription_id, delivery_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<WebhookDeliveryDetailResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Verify subscription exists and belongs to tenant
    WebhookSubscription::find_by_id(state.pool(), tenant_id, subscription_id)
        .await
        .map_err(WebhookError::Database)?
        .ok_or(WebhookError::SubscriptionNotFound)?;

    let delivery =
        WebhookDelivery::find_by_id(state.pool(), tenant_id, subscription_id, delivery_id)
            .await
            .map_err(WebhookError::Database)?
            .ok_or(WebhookError::DeliveryNotFound)?;

    Ok(Json(delivery_to_detail_response(delivery)))
}

// ---------------------------------------------------------------------------
// Response converters
// ---------------------------------------------------------------------------

/// Convert a DB delivery model to a summary response.
fn delivery_to_response(d: WebhookDelivery) -> WebhookDeliveryResponse {
    WebhookDeliveryResponse {
        id: d.id,
        subscription_id: d.subscription_id,
        event_id: d.event_id,
        event_type: d.event_type,
        status: d.status,
        attempt_number: d.attempt_number,
        response_code: d.response_code,
        latency_ms: d.latency_ms,
        error_message: d.error_message,
        created_at: d.created_at,
        completed_at: d.completed_at,
    }
}

/// Convert a DB delivery model to a full detail response.
fn delivery_to_detail_response(d: WebhookDelivery) -> WebhookDeliveryDetailResponse {
    WebhookDeliveryDetailResponse {
        id: d.id,
        subscription_id: d.subscription_id,
        event_id: d.event_id,
        event_type: d.event_type,
        status: d.status,
        attempt_number: d.attempt_number,
        max_attempts: d.max_attempts,
        next_attempt_at: d.next_attempt_at,
        request_payload: d.request_payload,
        request_headers: d.request_headers,
        response_code: d.response_code,
        response_body: d.response_body,
        error_message: d.error_message,
        latency_ms: d.latency_ms,
        created_at: d.created_at,
        completed_at: d.completed_at,
    }
}
