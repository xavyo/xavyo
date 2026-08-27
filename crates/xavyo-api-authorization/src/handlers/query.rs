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
use xavyo_db::UserRole;

use crate::error::{ApiAuthorizationError, ApiResult};
use crate::models::query::{
    AdminCheckQuery, AuthorizationDecisionResponse, BulkCheckRequest, BulkCheckResponse, CanIQuery,
};
use crate::router::AuthorizationState;
use crate::services::AuthorizationAudit;

/// Roles for a target user. Lookup errors must not evaluate as "no roles".
pub(crate) async fn target_user_roles(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
) -> ApiResult<Vec<String>> {
    Ok(UserRole::get_user_roles(pool, user_id, tenant_id).await?)
}

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
        delegation: None,
    };

    let decision = state
        .pdp
        .evaluate(&state.pdp_pool, request.clone(), &claims.roles, None)
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
        delegation: None,
    };

    let roles = target_user_roles(&state.pdp_pool, tenant_id, query.user_id).await?;
    let decision = state
        .pdp
        .evaluate(&state.pdp_pool, request.clone(), &roles, None)
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
    let (subject_id, roles) = if let Some(uid) = request.user_id {
        (
            uid,
            target_user_roles(&state.pdp_pool, tenant_id, uid).await?,
        )
    } else {
        let uid = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthorizationError::Unauthorized)?;
        (uid, claims.roles.clone())
    };

    let mut results = Vec::with_capacity(request.checks.len());

    for check in request.checks {
        let auth_request = AuthorizationRequest {
            subject_id,
            tenant_id,
            action: check.action,
            resource_type: check.resource_type,
            resource_id: check.resource_id,
            delegation: None,
        };

        let decision = state
            .pdp
            .evaluate(&state.pdp_pool, auth_request.clone(), &roles, None)
            .await;

        AuthorizationAudit::emit_decision(&decision, &auth_request, &state.audit_verbosity);

        results.push(AuthorizationDecisionResponse::from(decision));
    }

    Ok(Json(BulkCheckResponse { results }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn admin_and_bulk_check_load_target_user_roles() {
        let src = include_str!("query.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("target_user_roles("),
            "admin/bulk check must load the target user's roles"
        );
        let admin = production
            .split("pub async fn admin_check_handler")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("admin_check_handler");
        assert!(
            admin.contains("target_user_roles(") && !admin.contains("&[]"),
            "GET /admin/authorization/check must not evaluate the target with empty roles"
        );
        let bulk = production
            .split("pub async fn bulk_check_handler")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("bulk_check_handler");
        assert!(
            bulk.contains("target_user_roles(") && !bulk.contains("vec![]"),
            "POST /admin/authorization/bulk-check must not evaluate another user with empty roles"
        );
    }
}
