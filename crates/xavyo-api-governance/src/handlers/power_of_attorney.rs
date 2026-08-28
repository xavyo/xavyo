//! Power of Attorney handlers for governance API (F-061).
//!
//! Handles HTTP requests for Power of Attorney operations including
//! granting, listing, retrieving, and revoking PoA grants.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{PoaStatus, User};

use crate::error::{ApiGovernanceError, ApiResult};
use xavyo_db::models::{PoaAuditEventFilter, PoaEventType as DbPoaEventType};

use crate::models::power_of_attorney::{
    AdminListPoaQuery, AssumeIdentityResponse, CurrentAssumptionResponse, DropIdentityResponse,
    ExtendPoaRequest, GrantPoaRequest, ListPoaAuditQuery, ListPoaQuery, PoaAuditEventResponse,
    PoaAuditListResponse, PoaListResponse, PoaResponse, RevokePoaRequest,
};
use crate::router::GovernanceState;

/// Prefer a non-empty display name, otherwise the user's email.
fn user_display_name(display_name: Option<&str>, email: &str) -> String {
    display_name
        .filter(|name| !name.is_empty())
        .unwrap_or(email)
        .to_string()
}

async fn load_user_display_name(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
) -> ApiResult<Option<String>> {
    Ok(User::find_by_id_in_tenant(pool, tenant_id, user_id)
        .await?
        .map(|user| user_display_name(user.display_name.as_deref(), &user.email)))
}

/// Grant a Power of Attorney.
///
/// Creates a new PoA grant from the authenticated user (donor) to the specified attorney.
#[utoipa::path(
    post,
    path = "/governance/power-of-attorney",
    tag = "Governance - Power of Attorney",
    request_body = GrantPoaRequest,
    responses(
        (status = 201, description = "Power of Attorney granted", body = PoaResponse),
        (status = 400, description = "Invalid request or duration exceeds maximum"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot grant PoA to yourself"),
        (status = 404, description = "Attorney user not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn grant_poa(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<GrantPoaRequest>,
) -> ApiResult<(StatusCode, Json<PoaResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let donor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let poa = state
        .poa_service
        .grant_poa(tenant_id, donor_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(poa.into())))
}

/// Get a Power of Attorney by ID.
#[utoipa::path(
    get,
    path = "/governance/power-of-attorney/{id}",
    tag = "Governance - Power of Attorney",
    params(
        ("id" = Uuid, Path, description = "Power of Attorney ID")
    ),
    responses(
        (status = 200, description = "Power of Attorney details", body = PoaResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Power of Attorney not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_poa(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<PoaResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let poa = state.poa_service.get_poa(tenant_id, id).await?;

    // Only allow access if user is donor or attorney
    if poa.donor_id != user_id && poa.attorney_id != user_id {
        return Err(ApiGovernanceError::Governance(
            xavyo_governance::error::GovernanceError::PoaNotFound(id),
        ));
    }

    Ok(Json(poa.into()))
}

/// List Power of Attorney grants.
///
/// Returns PoA grants where the user is either the donor (outgoing) or attorney (incoming).
/// Use the `direction` query parameter to filter.
#[utoipa::path(
    get,
    path = "/governance/power-of-attorney",
    tag = "Governance - Power of Attorney",
    params(ListPoaQuery),
    responses(
        (status = 200, description = "List of Power of Attorney grants", body = PoaListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_poa(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListPoaQuery>,
) -> ApiResult<Json<PoaListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let status = parse_optional_poa_status(query.status.as_deref())?;

    let (poas, total) = state
        .poa_service
        .list_poa(
            tenant_id,
            user_id,
            query.direction,
            status,
            query.active_now,
            limit,
            offset,
        )
        .await?;

    Ok(Json(PoaListResponse {
        items: poas.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    }))
}

/// Revoke a Power of Attorney.
///
/// Only the donor can revoke their own PoA grant.
#[utoipa::path(
    post,
    path = "/governance/power-of-attorney/{id}/revoke",
    tag = "Governance - Power of Attorney",
    params(
        ("id" = Uuid, Path, description = "Power of Attorney ID to revoke")
    ),
    request_body = RevokePoaRequest,
    responses(
        (status = 200, description = "Power of Attorney revoked", body = PoaResponse),
        (status = 400, description = "PoA is already revoked or expired"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Power of Attorney not found or not owned by user"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_poa(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<RevokePoaRequest>,
) -> ApiResult<Json<PoaResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let poa = state
        .poa_service
        .revoke_poa(tenant_id, id, user_id, request.reason)
        .await?;

    Ok(Json(poa.into()))
}

/// Extend a Power of Attorney.
///
/// Extends the end date of an active or pending PoA. Only the donor can extend.
#[utoipa::path(
    post,
    path = "/governance/power-of-attorney/{id}/extend",
    tag = "Governance - Power of Attorney",
    params(
        ("id" = Uuid, Path, description = "Power of Attorney ID to extend")
    ),
    request_body = ExtendPoaRequest,
    responses(
        (status = 200, description = "Power of Attorney extended", body = PoaResponse),
        (status = 400, description = "Invalid extension or would exceed maximum duration"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Power of Attorney not found or not owned by user"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn extend_poa(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ExtendPoaRequest>,
) -> ApiResult<Json<PoaResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let poa = state
        .poa_service
        .extend_poa(tenant_id, id, user_id, request.new_ends_at)
        .await?;

    Ok(Json(poa.into()))
}

/// Admin: List all Power of Attorney grants in the tenant.
#[utoipa::path(
    get,
    path = "/governance/admin/power-of-attorney",
    tag = "Governance - Power of Attorney (Admin)",
    params(AdminListPoaQuery),
    responses(
        (status = 200, description = "List of all Power of Attorney grants", body = PoaListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires admin role"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn admin_list_poa(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<AdminListPoaQuery>,
) -> ApiResult<Json<PoaListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let status = parse_optional_poa_status(query.status.as_deref())?;

    let (poas, total) = state
        .poa_service
        .admin_list_poa(
            tenant_id,
            query.donor_id,
            query.attorney_id,
            status,
            query.active_now,
            limit,
            offset,
        )
        .await?;

    Ok(Json(PoaListResponse {
        items: poas.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    }))
}

/// Admin: Revoke any Power of Attorney in the tenant.
#[utoipa::path(
    post,
    path = "/governance/admin/power-of-attorney/{id}/revoke",
    tag = "Governance - Power of Attorney (Admin)",
    params(
        ("id" = Uuid, Path, description = "Power of Attorney ID to revoke")
    ),
    request_body = RevokePoaRequest,
    responses(
        (status = 200, description = "Power of Attorney revoked by admin", body = PoaResponse),
        (status = 400, description = "PoA is already revoked or expired"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires admin role"),
        (status = 404, description = "Power of Attorney not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn admin_revoke_poa(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<RevokePoaRequest>,
) -> ApiResult<Json<PoaResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let admin_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let poa = state
        .poa_service
        .admin_revoke_poa(tenant_id, id, admin_id, request.reason)
        .await?;

    Ok(Json(poa.into()))
}

// =========================================================================
// Identity Assumption Handlers (T032-T034)
// =========================================================================

/// Assume the identity of a donor using a valid Power of Attorney.
///
/// Creates a new assumed session and returns a token with acting_as claims.
#[utoipa::path(
    post,
    path = "/governance/power-of-attorney/{id}/assume",
    tag = "Governance - Power of Attorney",
    params(
        ("id" = Uuid, Path, description = "Power of Attorney ID to use for identity assumption")
    ),
    responses(
        (status = 501, description = "Identity-switch JWT re-issuance is not implemented"),
        (status = 400, description = "PoA is not active or already assuming another identity"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Power of Attorney not found or not authorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn assume_identity(
    State(_state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(_poa_id): Path<Uuid>,
) -> ApiResult<Json<AssumeIdentityResponse>> {
    let _tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let _attorney_id =
        Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Fail closed: do not open an assumed session or return a placeholder
    // access_token. JwtClaims.acting_as_* is the trust boundary.
    Err(crate::identity_switch::unimplemented_identity_switch_jwt())
}

/// Drop the currently assumed identity and return to the attorney's own identity.
#[utoipa::path(
    post,
    path = "/governance/power-of-attorney/drop",
    tag = "Governance - Power of Attorney",
    responses(
        (status = 501, description = "Identity-switch JWT re-issuance is not implemented"),
        (status = 400, description = "Not currently assuming any identity"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn drop_identity(
    State(_state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<DropIdentityResponse>> {
    let _tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let _attorney_id =
        Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    Err(crate::identity_switch::unimplemented_identity_switch_jwt())
}

/// Get the current assumed identity status.
///
/// Returns whether the user is currently assuming another identity.
#[utoipa::path(
    get,
    path = "/governance/power-of-attorney/current-assumption",
    tag = "Governance - Power of Attorney",
    responses(
        (status = 200, description = "Current assumption status", body = CurrentAssumptionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_current_assumption(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<CurrentAssumptionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let attorney_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let assumption = state
        .poa_service
        .get_current_assumption(tenant_id, attorney_id)
        .await?;

    match assumption {
        Some((session, poa)) => {
            let donor_name = load_user_display_name(state.pool(), tenant_id, poa.donor_id).await?;
            Ok(Json(CurrentAssumptionResponse {
                is_assuming: true,
                poa_id: Some(poa.id),
                donor_id: Some(poa.donor_id),
                donor_name,
                session_id: Some(session.id),
                assumed_at: Some(session.assumed_at),
                scope: None,
            }))
        }
        None => Ok(Json(CurrentAssumptionResponse {
            is_assuming: false,
            poa_id: None,
            donor_id: None,
            donor_name: None,
            session_id: None,
            assumed_at: None,
            scope: None,
        })),
    }
}

// =========================================================================
// Audit Trail Handlers (T050-T053)
// =========================================================================

/// Get audit trail for a specific Power of Attorney.
///
/// Returns all audit events for the specified PoA grant.
/// Only the donor or attorney can view the audit trail.
#[utoipa::path(
    get,
    path = "/governance/power-of-attorney/{id}/audit",
    tag = "Governance - Power of Attorney",
    params(
        ("id" = Uuid, Path, description = "Power of Attorney ID"),
        ListPoaAuditQuery
    ),
    responses(
        (status = 200, description = "Audit trail for the Power of Attorney", body = PoaAuditListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Power of Attorney not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_poa_audit_trail(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListPoaAuditQuery>,
) -> ApiResult<Json<PoaAuditListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // First verify the user has access to this PoA (donor or attorney)
    let poa = state.poa_service.get_poa(tenant_id, id).await?;

    if poa.donor_id != user_id && poa.attorney_id != user_id {
        return Err(ApiGovernanceError::Governance(
            xavyo_governance::error::GovernanceError::PoaNotFound(id),
        ));
    }

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let event_type = query
        .event_type
        .as_deref()
        .map(parse_event_type)
        .transpose()?;

    let filter = PoaAuditEventFilter {
        event_type,
        actor_id: query.actor_id,
        affected_user_id: query.affected_user_id,
        after: query.after,
        before: query.before,
        ..Default::default()
    };

    let (events, total) = state
        .poa_service
        .list_poa_audit_events(tenant_id, id, filter, limit, offset)
        .await?;

    Ok(Json(PoaAuditListResponse {
        items: events
            .into_iter()
            .map(|e| PoaAuditEventResponse {
                id: e.id,
                event_type: e.event_type,
                actor_id: e.actor_id,
                actor_name: None,
                affected_user_id: e.affected_user_id,
                affected_user_name: None,
                details: e.details,
                created_at: e.created_at,
            })
            .collect(),
        total,
    }))
}

/// Invalid PoA status filters must not silently list every grant.
fn parse_optional_poa_status(
    status: Option<&str>,
) -> Result<Option<PoaStatus>, ApiGovernanceError> {
    match status {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => parse_poa_status(s).map(Some),
    }
}

fn parse_poa_status(s: &str) -> Result<PoaStatus, ApiGovernanceError> {
    match s.to_lowercase().as_str() {
        "pending" => Ok(PoaStatus::Pending),
        "active" => Ok(PoaStatus::Active),
        "expired" => Ok(PoaStatus::Expired),
        "revoked" => Ok(PoaStatus::Revoked),
        _ => Err(ApiGovernanceError::Validation(format!(
            "Invalid PoA status '{s}'. Must be one of: pending, active, expired, revoked"
        ))),
    }
}

/// Invalid event-type filters must not silently list every audit event.
fn parse_event_type(s: &str) -> Result<DbPoaEventType, ApiGovernanceError> {
    match s.to_lowercase().as_str() {
        "grant_created" => Ok(DbPoaEventType::GrantCreated),
        "grant_extended" => Ok(DbPoaEventType::GrantExtended),
        "grant_revoked" => Ok(DbPoaEventType::GrantRevoked),
        "grant_expired" => Ok(DbPoaEventType::GrantExpired),
        "identity_assumed" => Ok(DbPoaEventType::IdentityAssumed),
        "identity_dropped" => Ok(DbPoaEventType::IdentityDropped),
        "action_performed" => Ok(DbPoaEventType::ActionPerformed),
        _ => Err(ApiGovernanceError::Validation(format!(
            "Invalid PoA event type '{s}'. Must be one of: grant_created, grant_extended, grant_revoked, grant_expired, identity_assumed, identity_dropped, action_performed"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_poa_status_does_not_list_all_grants() {
        assert_eq!(parse_optional_poa_status(None).unwrap(), None);
        assert_eq!(parse_optional_poa_status(Some("")).unwrap(), None);
        assert_eq!(
            parse_optional_poa_status(Some("active")).unwrap(),
            Some(PoaStatus::Active)
        );
        assert!(parse_optional_poa_status(Some("bogus")).is_err());
        let src = include_str!("power_of_attorney.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_optional_poa_status(")
                && !production.contains("and_then(|s| match s.to_lowercase().as_str()"),
            "invalid PoA status must be 400, not an unfiltered list"
        );
    }

    #[test]
    fn invalid_poa_event_type_does_not_list_all_events() {
        assert_eq!(
            parse_event_type("grant_created").unwrap(),
            DbPoaEventType::GrantCreated
        );
        assert!(parse_event_type("bogus").is_err());
        let src = include_str!("power_of_attorney.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("map(parse_event_type)")
                && production.contains(".transpose()?")
                && !production.contains("and_then(parse_event_type)"),
            "invalid PoA event type must be 400, not an unfiltered audit list"
        );
    }

    #[test]
    fn poa_audit_trail_uses_service_total() {
        let src = include_str!("power_of_attorney.rs");
        let production = src.split("mod tests").next().expect("production source");
        let trail = production
            .split("pub async fn get_poa_audit_trail")
            .nth(1)
            .and_then(|s| s.split("fn ").next())
            .expect("get_poa_audit_trail");
        assert!(
            trail.contains("list_poa_audit_events(")
                && trail.contains("let (events, total)")
                && !trail.contains("events.len() as i64"),
            "GET PoA audit trail must use the service total, not the page length"
        );
    }

    #[test]
    fn current_assumption_looks_up_donor_name() {
        let src = include_str!("power_of_attorney.rs");
        let production = src.split("mod tests").next().expect("production source");
        let current = production
            .split("pub async fn get_current_assumption")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("get_current_assumption");
        assert!(
            current.contains("load_user_display_name(")
                && current.contains("poa.donor_id")
                && !current.contains("donor_name: None, // Would"),
            "GET /governance/power-of-attorney/current-assumption must look up the donor display name"
        );
    }
}
