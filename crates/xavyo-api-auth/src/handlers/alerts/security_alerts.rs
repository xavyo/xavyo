//! Security alerts handlers for user alert endpoints.

use crate::error::ApiAuthError;
use crate::models::{SecurityAlertResponse, SecurityAlertsQuery, SecurityAlertsResponse};
use crate::services::AlertService;
use axum::{
    extract::{Path, Query},
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_core::TenantId;

/// GET /security-alerts
///
/// Returns paginated security alerts for the authenticated user.
#[utoipa::path(
    get,
    path = "/security-alerts",
    params(SecurityAlertsQuery),
    responses(
        (status = 200, description = "Security alerts retrieved", body = SecurityAlertsResponse),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Security Alerts"
)]
pub async fn get_security_alerts(
    Extension(alert_service): Extension<Arc<AlertService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<Uuid>,
    Query(query): Query<SecurityAlertsQuery>,
) -> Result<Json<SecurityAlertsResponse>, ApiAuthError> {
    // Clamp limit to valid range
    let limit = query.limit.clamp(1, 100);

    let (alerts, total, unacknowledged_count) = alert_service
        .get_user_alerts(
            *tenant_id.as_uuid(),
            user_id,
            query.alert_type.as_deref(),
            query.severity.as_deref(),
            query.acknowledged,
            query.cursor,
            limit,
        )
        .await?;

    // Calculate next cursor if there are more results
    let next_cursor = if alerts.len() as i32 == limit && !alerts.is_empty() {
        alerts.last().map(|a| a.created_at)
    } else {
        None
    };

    let items: Vec<SecurityAlertResponse> = alerts.into_iter().map(Into::into).collect();

    Ok(Json(SecurityAlertsResponse {
        items,
        total,
        unacknowledged_count,
        next_cursor,
    }))
}

/// POST /security-alerts/:id/acknowledge
///
/// Acknowledges a security alert for the authenticated user.
#[utoipa::path(
    post,
    path = "/security-alerts/{id}/acknowledge",
    params(
        ("id" = Uuid, Path, description = "Alert ID"),
    ),
    responses(
        (status = 200, description = "Alert acknowledged", body = SecurityAlertResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Alert not found"),
        (status = 409, description = "Alert already acknowledged"),
    ),
    tag = "Security Alerts"
)]
pub async fn acknowledge_alert(
    Extension(alert_service): Extension<Arc<AlertService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<Uuid>,
    Path(alert_id): Path<Uuid>,
) -> Result<Json<SecurityAlertResponse>, ApiAuthError> {
    // First verify the alert exists and belongs to this user
    let alert = alert_service
        .get_alert_by_id(*tenant_id.as_uuid(), alert_id)
        .await?
        .ok_or(ApiAuthError::AlertNotFound)?;

    if alert.user_id != user_id {
        return Err(ApiAuthError::AlertNotFound);
    }

    // Acknowledge the alert
    let updated_alert = alert_service
        .acknowledge_alert(*tenant_id.as_uuid(), alert_id, user_id)
        .await?
        .ok_or(ApiAuthError::AlertAlreadyAcknowledged)?;

    Ok(Json(updated_alert.into()))
}
