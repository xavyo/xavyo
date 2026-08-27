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

    let alert_type = parse_optional_alert_type(query.alert_type.as_deref())?;
    let severity = parse_optional_severity(query.severity.as_deref())?;
    let (alerts, total, unacknowledged_count) = alert_service
        .get_user_alerts(
            *tenant_id.as_uuid(),
            user_id,
            alert_type,
            severity,
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

/// Invalid alert-type filters must not silently list every alert.
fn parse_optional_alert_type(value: Option<&str>) -> Result<Option<&str>, ApiAuthError> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s)
            if matches!(
                s,
                "new_device" | "new_location" | "failed_attempts" | "password_change" | "mfa_disabled"
            ) =>
        {
            Ok(Some(s))
        }
        Some(s) => Err(ApiAuthError::Validation(format!(
            "Invalid alert type '{s}'. Must be one of: new_device, new_location, failed_attempts, password_change, mfa_disabled"
        ))),
    }
}

/// Invalid severity filters must not silently list every alert.
fn parse_optional_severity(value: Option<&str>) -> Result<Option<&str>, ApiAuthError> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "info" | "warning" | "critical") => Ok(Some(s)),
        Some(s) => Err(ApiAuthError::Validation(format!(
            "Invalid alert severity '{s}'. Must be one of: info, warning, critical"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_alert_filters_do_not_list_all_alerts() {
        assert_eq!(parse_optional_alert_type(None).unwrap(), None);
        assert_eq!(
            parse_optional_alert_type(Some("new_device")).unwrap(),
            Some("new_device")
        );
        assert!(parse_optional_alert_type(Some("bogus")).is_err());
        assert_eq!(parse_optional_severity(None).unwrap(), None);
        assert_eq!(
            parse_optional_severity(Some("warning")).unwrap(),
            Some("warning")
        );
        assert!(parse_optional_severity(Some("bogus")).is_err());
        let src = include_str!("security_alerts.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_optional_alert_type(")
                && production.contains("parse_optional_severity(")
                && !production.contains("query.alert_type.as_deref(),"),
            "invalid security-alert filters must be 400/422, not an unfiltered list"
        );
    }
}
