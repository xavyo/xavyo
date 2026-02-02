//! Handlers for authorization query endpoints (F083).
//!
//! - can-i: Check if the current user can perform an action
//! - admin-check: Check if a specified user can perform an action (admin only)
//! - bulk-check: Check multiple authorization queries at once (admin only)

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_authorization::AuthorizationRequest;

use crate::error::{ApiAuthorizationError, ApiResult};
use crate::models::query::{
    AdminCheckQuery, AuthorizationDecisionResponse, BulkCheckRequest, BulkCheckResponse, CanIQuery,
};
use crate::router::AuthorizationState;
use crate::services::AuthorizationAudit;

/// Check if the current user can perform an action on a resource type.
///
/// Uses the caller's identity (from JWT) as the subject.
#[utoipa::path(
    get,
    path = "/authorization/can-i",
    tag = "Authorization - Query",
    params(CanIQuery),
    responses(
        (status = 200, description = "Authorization decision", body = AuthorizationDecisionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn can_i_handler(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<CanIQuery>,
) -> ApiResult<Json<AuthorizationDecisionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthorizationError::Unauthorized)?;

    let request = AuthorizationRequest {
        subject_id: user_id,
        tenant_id,
        action: query.action,
        resource_type: query.resource_type,
        resource_id: query.resource_id,
    };

    let decision = state
        .pdp
        .evaluate(&state.pool, request.clone(), &claims.roles, None)
        .await;

    // Emit audit event
    AuthorizationAudit::emit_decision(&decision, &request, &state.audit_verbosity);

    Ok(Json(AuthorizationDecisionResponse::from(decision)))
}

/// Check if a specified user can perform an action on a resource type.
///
/// Admin-only endpoint for checking authorization on behalf of another user.
#[utoipa::path(
    get,
    path = "/admin/authorization/check",
    tag = "Authorization - Query",
    params(AdminCheckQuery),
    responses(
        (status = 200, description = "Authorization decision", body = AuthorizationDecisionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn admin_check_handler(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<AdminCheckQuery>,
) -> ApiResult<Json<AuthorizationDecisionResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    let request = AuthorizationRequest {
        subject_id: query.user_id,
        tenant_id,
        action: query.action,
        resource_type: query.resource_type,
        resource_id: query.resource_id,
    };

    // Note: for admin check, we pass empty roles since the target user's roles
    // are resolved from the entitlement system, not from the admin's JWT.
    let decision = state
        .pdp
        .evaluate(&state.pool, request.clone(), &[], None)
        .await;

    AuthorizationAudit::emit_decision(&decision, &request, &state.audit_verbosity);

    Ok(Json(AuthorizationDecisionResponse::from(decision)))
}

/// Perform multiple authorization checks at once.
///
/// Admin-only endpoint. Maximum 100 checks per request.
#[utoipa::path(
    post,
    path = "/admin/authorization/bulk-check",
    tag = "Authorization - Query",
    request_body = BulkCheckRequest,
    responses(
        (status = 200, description = "Bulk authorization decisions", body = BulkCheckResponse),
        (status = 400, description = "Too many checks (max 100)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn bulk_check_handler(
    State(state): State<AuthorizationState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BulkCheckRequest>,
) -> ApiResult<Json<BulkCheckResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiAuthorizationError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiAuthorizationError::Unauthorized)?
        .as_uuid();

    // Validate bulk check size
    if request.checks.len() > 100 {
        return Err(ApiAuthorizationError::Validation(
            "Maximum 100 checks per bulk request".to_string(),
        ));
    }

    if request.checks.is_empty() {
        return Ok(Json(BulkCheckResponse {
            results: Vec::new(),
        }));
    }

    // Determine subject: explicit user_id or caller
    let (subject_id, roles) = match request.user_id {
        Some(uid) => (uid, vec![]),
        None => {
            let uid =
                Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthorizationError::Unauthorized)?;
            (uid, claims.roles.clone())
        }
    };

    let mut results = Vec::with_capacity(request.checks.len());

    for check in request.checks {
        let auth_request = AuthorizationRequest {
            subject_id,
            tenant_id,
            action: check.action,
            resource_type: check.resource_type,
            resource_id: check.resource_id,
        };

        let decision = state
            .pdp
            .evaluate(&state.pool, auth_request.clone(), &roles, None)
            .await;

        AuthorizationAudit::emit_decision(&decision, &auth_request, &state.audit_verbosity);

        results.push(AuthorizationDecisionResponse::from(decision));
    }

    Ok(Json(BulkCheckResponse { results }))
}
