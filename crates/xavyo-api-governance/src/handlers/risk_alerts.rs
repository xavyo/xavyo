//! Risk alert handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    AcknowledgeAlertResponse, AlertSummary, BulkAcknowledgeResponse, ListRiskAlertsQuery,
    RiskAlertListResponse, RiskAlertResponse,
};
use crate::router::GovernanceState;

/// List all risk alerts with filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/risk-alerts",
    tag = "Governance - Risk Alerts",
    params(ListRiskAlertsQuery),
    responses(
        (status = 200, description = "List of risk alerts", body = RiskAlertListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_risk_alerts(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListRiskAlertsQuery>,
) -> ApiResult<Json<RiskAlertListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state.risk_alert_service.list(tenant_id, query).await?;

    Ok(Json(response))
}

/// Get a risk alert by ID.
#[utoipa::path(
    get,
    path = "/governance/risk-alerts/{alert_id}",
    tag = "Governance - Risk Alerts",
    params(
        ("alert_id" = Uuid, Path, description = "Alert ID")
    ),
    responses(
        (status = 200, description = "Risk alert details", body = RiskAlertResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Alert not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_risk_alert(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(alert_id): Path<Uuid>,
) -> ApiResult<Json<RiskAlertResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let alert = state.risk_alert_service.get(tenant_id, alert_id).await?;

    Ok(Json(alert))
}

/// Acknowledge a risk alert.
#[utoipa::path(
    post,
    path = "/governance/risk-alerts/{alert_id}/acknowledge",
    tag = "Governance - Risk Alerts",
    params(
        ("alert_id" = Uuid, Path, description = "Alert ID")
    ),
    responses(
        (status = 200, description = "Alert acknowledged", body = AcknowledgeAlertResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Alert not found or already acknowledged"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn acknowledge_risk_alert(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(alert_id): Path<Uuid>,
) -> ApiResult<Json<AcknowledgeAlertResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let response = state
        .risk_alert_service
        .acknowledge(tenant_id, alert_id, user_id)
        .await?;

    Ok(Json(response))
}

/// Acknowledge all alerts for a user.
#[utoipa::path(
    post,
    path = "/governance/users/{user_id}/risk-alerts/acknowledge-all",
    tag = "Governance - Risk Alerts",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Alerts acknowledged", body = BulkAcknowledgeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn acknowledge_user_alerts(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<BulkAcknowledgeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let acknowledged_by =
        Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let response = state
        .risk_alert_service
        .acknowledge_for_user(tenant_id, user_id, acknowledged_by)
        .await?;

    Ok(Json(response))
}

/// Get alert summary (unacknowledged counts by severity).
#[utoipa::path(
    get,
    path = "/governance/risk-alerts/summary",
    tag = "Governance - Risk Alerts",
    responses(
        (status = 200, description = "Alert summary", body = AlertSummary),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_alert_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<AlertSummary>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state.risk_alert_service.get_summary(tenant_id).await?;

    Ok(Json(summary))
}

/// Delete a risk alert.
#[utoipa::path(
    delete,
    path = "/governance/risk-alerts/{alert_id}",
    tag = "Governance - Risk Alerts",
    params(
        ("alert_id" = Uuid, Path, description = "Alert ID")
    ),
    responses(
        (status = 204, description = "Alert deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Alert not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_risk_alert(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(alert_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state.risk_alert_service.delete(tenant_id, alert_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get most recent alert for a user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/risk-alerts/latest",
    tag = "Governance - Risk Alerts",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Most recent alert", body = Option<RiskAlertResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_latest_alert(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<Option<RiskAlertResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let alert = state
        .risk_alert_service
        .get_most_recent_for_user(tenant_id, user_id)
        .await?;

    Ok(Json(alert))
}
