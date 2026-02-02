//! Webhook callback handlers for ticketing integrations (F064).
//!
//! Receives status updates from external ticketing systems via webhook callbacks.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use xavyo_db::GovTicketingConfiguration;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    router::GovernanceState,
    services::ticket_sync_service::WebhookCallbackPayload,
};

/// Webhook callback request body.
#[derive(Debug, Deserialize)]
pub struct WebhookCallbackRequest {
    /// External ticket ID/reference.
    pub ticket_id: String,
    /// New status from external system.
    pub status: String,
    /// Resolution notes if resolved.
    #[serde(default)]
    pub resolution_notes: Option<String>,
    /// Who resolved the ticket.
    #[serde(default)]
    pub resolved_by: Option<String>,
}

/// Response to webhook callback.
#[derive(Debug, Serialize)]
pub struct WebhookCallbackResponse {
    /// Whether the webhook was processed successfully.
    pub processed: bool,
    /// Message describing the result.
    pub message: String,
}

/// Query parameters for webhook callback.
#[derive(Debug, Deserialize)]
pub struct WebhookQueryParams {
    /// Optional secret passed as query parameter.
    pub secret: Option<String>,
}

/// Handle webhook callback from external ticketing system.
///
/// This endpoint is called by external ticketing systems (ServiceNow, Jira, or custom webhooks)
/// to notify us of ticket status changes. The endpoint authenticates using a shared secret
/// passed as a query parameter or header.
#[utoipa::path(
    post,
    path = "/governance/webhooks/ticketing/{configuration_id}",
    tag = "Governance - Ticketing Webhooks",
    params(
        ("configuration_id" = Uuid, Path, description = "Ticketing configuration ID"),
        ("secret" = Option<String>, Query, description = "Webhook callback secret for authentication")
    ),
    request_body = WebhookCallbackRequest,
    responses(
        (status = 200, description = "Webhook processed successfully", body = WebhookCallbackResponse),
        (status = 401, description = "Invalid or missing webhook secret"),
        (status = 404, description = "Configuration not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn handle_webhook_callback(
    State(state): State<GovernanceState>,
    Path(configuration_id): Path<Uuid>,
    Query(query): Query<WebhookQueryParams>,
    headers: axum::http::HeaderMap,
    Json(request): Json<WebhookCallbackRequest>,
) -> ApiResult<(StatusCode, Json<WebhookCallbackResponse>)> {
    // Get the configuration to verify the webhook secret and find the tenant
    let config = sqlx::query_as::<_, GovTicketingConfiguration>(
        r#"
        SELECT * FROM gov_ticketing_configurations
        WHERE id = $1 AND is_active = true
        "#,
    )
    .bind(configuration_id)
    .fetch_optional(state.ticket_sync_service.pool())
    .await
    .map_err(ApiGovernanceError::Database)?
    .ok_or_else(|| {
        ApiGovernanceError::NotFound(format!(
            "Ticketing configuration {} not found",
            configuration_id
        ))
    })?;

    // Verify the webhook secret
    let provided_secret = query.secret.or_else(|| {
        headers
            .get("x-webhook-secret")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });

    if let Some(expected_secret) = &config.webhook_callback_secret {
        let expected_str = String::from_utf8_lossy(expected_secret);
        match provided_secret {
            Some(s) if s == expected_str.as_ref() => {}
            _ => {
                tracing::warn!(
                    configuration_id = %configuration_id,
                    "Webhook callback with invalid or missing secret"
                );
                return Err(ApiGovernanceError::Unauthorized);
            }
        }
    }

    // Process the webhook
    let payload = WebhookCallbackPayload {
        ticket_id: request.ticket_id,
        status: request.status,
        resolution_notes: request.resolution_notes,
        resolved_by: request.resolved_by,
    };

    let result = state
        .ticket_sync_service
        .process_webhook_callback(config.tenant_id, configuration_id, &payload)
        .await
        .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

    Ok((
        if result.processed {
            StatusCode::OK
        } else {
            StatusCode::NOT_FOUND
        },
        Json(WebhookCallbackResponse {
            processed: result.processed,
            message: result.message,
        }),
    ))
}

/// Trigger a manual sync of all pending tickets for a tenant.
///
/// Admin endpoint to force synchronization of all pending external tickets.
#[utoipa::path(
    post,
    path = "/governance/admin/tickets/sync",
    tag = "Governance - Ticketing Admin",
    responses(
        (status = 200, description = "Sync completed", body = TicketSyncResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_ticket_sync(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<TicketSyncResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // TODO: Check for admin permissions

    let result = state
        .ticket_sync_service
        .sync_all_pending_tickets(tenant_id)
        .await
        .map_err(|e| ApiGovernanceError::Internal(e.to_string()))?;

    Ok(Json(TicketSyncResponse {
        total_tickets: result.total_tickets,
        synced_count: result.synced_count,
        error_count: result.errors.len(),
        errors: result
            .errors
            .into_iter()
            .map(|e| TicketSyncErrorResponse {
                ticket_id: e.ticket_id,
                error: e.error,
            })
            .collect(),
    }))
}

/// Response from ticket sync operation.
#[derive(Debug, Serialize)]
pub struct TicketSyncResponse {
    /// Total number of tickets checked.
    pub total_tickets: usize,
    /// Number of tickets that were updated.
    pub synced_count: usize,
    /// Number of errors encountered.
    pub error_count: usize,
    /// Details of any errors.
    pub errors: Vec<TicketSyncErrorResponse>,
}

/// Error from ticket sync.
#[derive(Debug, Serialize)]
pub struct TicketSyncErrorResponse {
    pub ticket_id: Uuid,
    pub error: String,
}

/// Force sync a specific ticket.
#[utoipa::path(
    post,
    path = "/governance/admin/tickets/{ticket_id}/sync",
    tag = "Governance - Ticketing Admin",
    params(
        ("ticket_id" = Uuid, Path, description = "Ticket ID to sync")
    ),
    responses(
        (status = 200, description = "Ticket synced", body = SingleTicketSyncResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Ticket not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn sync_single_ticket(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(ticket_id): Path<Uuid>,
) -> ApiResult<Json<SingleTicketSyncResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .ticket_sync_service
        .sync_ticket_by_id(tenant_id, ticket_id)
        .await
        .map_err(|e| match &e {
            xavyo_governance::error::GovernanceError::ExternalTicketNotFound(_) => {
                ApiGovernanceError::NotFound(format!("Ticket {} not found", ticket_id))
            }
            _ => ApiGovernanceError::Internal(e.to_string()),
        })?;

    Ok(Json(SingleTicketSyncResponse {
        ticket_id: result.ticket_id,
        was_updated: result.was_updated,
        synced_at: result.synced_at,
    }))
}

/// Response from single ticket sync.
#[derive(Debug, Serialize)]
pub struct SingleTicketSyncResponse {
    pub ticket_id: Uuid,
    pub was_updated: bool,
    pub synced_at: chrono::DateTime<chrono::Utc>,
}
