//! Effective access handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{EffectiveAccessQuery, EffectiveAccessResponse};
use crate::router::GovernanceState;
use crate::services::PersonaEntitlementResult;

/// Get effective access for a user.
///
/// Returns all entitlements the user has access to, consolidated from:
/// - Direct user assignments
/// - Group memberships
/// - Role mappings
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/effective-access",
    tag = "Governance - Effective Access",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        EffectiveAccessQuery
    ),
    responses(
        (status = 200, description = "Effective access for user", body = EffectiveAccessResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_effective_access(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<EffectiveAccessQuery>,
) -> ApiResult<Json<EffectiveAccessResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .effective_access_service
        .get_effective_access(tenant_id, user_id, query.application_id)
        .await?;

    Ok(Json(result.into()))
}

/// Get effective access for a user with persona context (F063 integration).
///
/// Returns entitlements considering active persona precedence rules:
/// - If user has an active persona, returns persona entitlements only (precedence rule)
/// - If no active persona, returns physical user entitlements
/// - Response includes persona context information for auditing
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/persona-effective-access",
    tag = "Governance - Effective Access",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        EffectiveAccessQuery
    ),
    responses(
        (status = 200, description = "Effective access with persona context", body = PersonaEntitlementResult),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_persona_effective_access(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<EffectiveAccessQuery>,
) -> ApiResult<Json<PersonaEntitlementResult>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .persona_entitlement_service
        .get_effective_entitlements(tenant_id, user_id, query.application_id)
        .await?;

    Ok(Json(result))
}

/// Check if a user has access to a specific entitlement with persona context.
///
/// This endpoint respects persona precedence rules:
/// - Returns error if active persona is deactivated/expired
/// - Checks against effective identity (persona or physical user)
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/entitlements/{entitlement_id}/check",
    tag = "Governance - Effective Access",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("entitlement_id" = Uuid, Path, description = "Entitlement ID to check")
    ),
    responses(
        (status = 200, description = "Access check result", body = bool),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Persona deactivated"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn check_entitlement_access(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((user_id, entitlement_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<bool>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let has_access = state
        .persona_entitlement_service
        .check_entitlement_access(tenant_id, user_id, entitlement_id)
        .await?;

    Ok(Json(has_access))
}
