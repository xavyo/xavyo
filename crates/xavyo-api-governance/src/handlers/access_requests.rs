//! Access request handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    AccessRequestCreatedResponse, AccessRequestListResponse, AccessRequestResponse,
    CreateAccessRequestRequest, ListAccessRequestsQuery,
};
use crate::router::GovernanceState;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Tenant + requester taken from the JWT (self-service; no admin role required).
pub fn requester_from_claims(claims: &JwtClaims) -> Result<(Uuid, Uuid), ApiGovernanceError> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;
    Ok((tenant_id, user_id))
}

/// List the current user's access requests.
#[utoipa::path(
    get,
    path = "/governance/access-requests",
    tag = "Governance - Access Requests",
    params(ListAccessRequestsQuery),
    responses(
        (status = 200, description = "List of access requests", body = AccessRequestListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_my_requests(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListAccessRequestsQuery>,
) -> ApiResult<Json<AccessRequestListResponse>> {
    let (tenant_id, user_id) = requester_from_claims(&claims)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (requests, total) = state
        .access_request_service
        .list_my_requests(
            tenant_id,
            user_id,
            query.status,
            query.entitlement_id,
            query.has_sod_warning,
            limit,
            offset,
        )
        .await?;

    let items: Vec<AccessRequestResponse> = requests
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(AccessRequestListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get an access request by ID.
#[utoipa::path(
    get,
    path = "/governance/access-requests/{id}",
    tag = "Governance - Access Requests",
    params(
        ("id" = Uuid, Path, description = "Access Request ID")
    ),
    responses(
        (status = 200, description = "Access request details", body = AccessRequestResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Access request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AccessRequestResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let request = state
        .access_request_service
        .get_request(tenant_id, id)
        .await?;

    Ok(Json(request.try_into()?))
}

/// Submit a new access request.
#[utoipa::path(
    post,
    path = "/governance/access-requests",
    tag = "Governance - Access Requests",
    request_body = CreateAccessRequestRequest,
    responses(
        (status = 201, description = "Access request created", body = AccessRequestCreatedResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement not found"),
        (status = 409, description = "Request already exists or entitlement already assigned"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    publisher: Option<Extension<EventPublisher>>,
    Json(request): Json<CreateAccessRequestRequest>,
) -> ApiResult<(StatusCode, Json<AccessRequestCreatedResponse>)> {
    request.validate()?;

    let (tenant_id, user_id) = requester_from_claims(&claims)?;

    let created = state
        .access_request_service
        .create_request(
            tenant_id,
            user_id,
            request.entitlement_id,
            request.justification,
            request.requested_expires_at,
        )
        .await?;

    let sod_warning_message = if created.has_sod_warning {
        Some("This request has SoD warnings. The approver will be notified.".to_string())
    } else {
        None
    };

    let response: AccessRequestResponse = created.try_into()?;

    // F085: Publish access_request.created webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "access_request.created".to_string(),
            tenant_id,
            actor_id: Some(user_id),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "request_id": response.id,
                "requester_id": user_id,
                "entitlement_id": response.entitlement_id,
                "status": response.status,
            }),
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(AccessRequestCreatedResponse {
            request: response,
            sod_warning_message,
        }),
    ))
}

/// Cancel a pending access request.
#[utoipa::path(
    post,
    path = "/governance/access-requests/{id}/cancel",
    tag = "Governance - Access Requests",
    params(
        ("id" = Uuid, Path, description = "Access Request ID")
    ),
    responses(
        (status = 200, description = "Request cancelled", body = AccessRequestResponse),
        (status = 400, description = "Cannot cancel non-pending request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not authorized to cancel this request"),
        (status = 404, description = "Access request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AccessRequestResponse>> {
    let (tenant_id, user_id) = requester_from_claims(&claims)?;

    let request = state
        .access_request_service
        .cancel_request(tenant_id, id, user_id)
        .await?;

    Ok(Json(request.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::requester_from_claims;
    use xavyo_auth::JwtClaims;
    use xavyo_core::TenantId;

    #[test]
    fn non_admin_jwt_is_enough_to_identify_requester() {
        let user_id = uuid::Uuid::new_v4();
        let tenant = TenantId::new();
        let claims = JwtClaims::builder()
            .subject(user_id.to_string())
            .tenant_id(tenant)
            .roles(vec!["user"])
            .expires_in_secs(3600)
            .build();
        let (tid, uid) = requester_from_claims(&claims).expect("user JWT must work without admin");
        assert_eq!(tid, *tenant.as_uuid());
        assert_eq!(uid, user_id);
    }

    #[test]
    fn missing_tenant_is_unauthorized() {
        let claims = JwtClaims::builder()
            .subject(uuid::Uuid::new_v4().to_string())
            .roles(vec!["user"])
            .expires_in_secs(3600)
            .build();
        assert!(requester_from_claims(&claims).is_err());
    }

    #[test]
    fn list_my_requests_honors_advertised_filters() {
        let src = include_str!("access_requests.rs");
        let production = src.split("mod tests").next().expect("production source");
        let list = production
            .split("pub async fn list_my_requests")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("list_my_requests");
        assert!(
            list.contains("query.entitlement_id") && list.contains("query.has_sod_warning"),
            "GET /governance/access-requests must apply advertised entitlement_id and has_sod_warning filters"
        );
    }
}
