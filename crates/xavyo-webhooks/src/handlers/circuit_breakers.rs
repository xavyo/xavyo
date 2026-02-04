//! HTTP handlers for circuit breaker status API.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::circuit_breaker::CircuitBreakerStatus;
use crate::error::{ApiResult, WebhookError};
use crate::router::WebhooksState;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, WebhookError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(WebhookError::Unauthorized)
}

/// Response containing a list of circuit breaker statuses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerListResponse {
    pub circuit_breakers: Vec<CircuitBreakerStatus>,
    pub total: usize,
}

// ---------------------------------------------------------------------------
// Circuit Breaker Status Handlers
// ---------------------------------------------------------------------------

/// List all circuit breakers for the tenant.
#[utoipa::path(
    get,
    path = "/webhooks/circuit-breakers",
    tag = "Circuit Breakers",
    responses(
        (status = 200, description = "List of circuit breaker statuses", body = CircuitBreakerListResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_circuit_breakers_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<CircuitBreakerListResponse>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let statuses = state
        .circuit_breaker_registry
        .get_all_status(tenant_id)
        .await?;

    let total = statuses.len();

    Ok(Json(CircuitBreakerListResponse {
        circuit_breakers: statuses,
        total,
    }))
}

/// Get circuit breaker status for a specific subscription.
#[utoipa::path(
    get,
    path = "/webhooks/circuit-breakers/{subscription_id}",
    tag = "Circuit Breakers",
    params(
        ("subscription_id" = Uuid, Path, description = "Subscription ID")
    ),
    responses(
        (status = 200, description = "Circuit breaker status", body = CircuitBreakerStatus),
        (status = 404, description = "Circuit breaker not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_circuit_breaker_handler(
    State(state): State<WebhooksState>,
    Extension(claims): Extension<JwtClaims>,
    Path(subscription_id): Path<Uuid>,
) -> ApiResult<Json<CircuitBreakerStatus>> {
    let tenant_id = extract_tenant_id(&claims)?;

    let status = state
        .circuit_breaker_registry
        .get_status(tenant_id, subscription_id)
        .await?
        .ok_or(WebhookError::CircuitBreakerNotFound { subscription_id })?;

    Ok(Json(status))
}
