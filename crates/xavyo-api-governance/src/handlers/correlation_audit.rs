use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::correlation::{
        CorrelationAuditEventResponse, CorrelationAuditListResponse, ListCorrelationAuditQuery,
    },
    router::GovernanceState,
    services::correlation_audit_service::build_audit_filter,
};

/// List correlation audit events
#[utoipa::path(
    get,
    path = "/governance/correlation/audit",
    tag = "Governance - Correlation Audit",
    params(ListCorrelationAuditQuery),
    responses(
        (status = 200, description = "Correlation audit events retrieved", body = CorrelationAuditListResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_correlation_audit_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCorrelationAuditQuery>,
) -> ApiResult<Json<CorrelationAuditListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let filter = build_audit_filter(&query)?;
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let response = state
        .correlation_audit_service
        .list_events(tenant_id, &filter, limit, offset)
        .await?;

    Ok(Json(response))
}

/// Get a specific correlation audit event by ID
#[utoipa::path(
    get,
    path = "/governance/correlation/audit/{event_id}",
    tag = "Governance - Correlation Audit",
    params(
        ("event_id" = Uuid, Path, description = "Correlation audit event ID")
    ),
    responses(
        (status = 200, description = "Correlation audit event retrieved", body = CorrelationAuditEventResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Correlation audit event not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_correlation_audit_event(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(event_id): Path<Uuid>,
) -> ApiResult<Json<CorrelationAuditEventResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .correlation_audit_service
        .get_event(tenant_id, event_id)
        .await?;

    Ok(Json(response))
}
