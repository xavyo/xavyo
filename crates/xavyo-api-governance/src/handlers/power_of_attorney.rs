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
use xavyo_db::models::PoaStatus;

use crate::error::{ApiGovernanceError, ApiResult};
use xavyo_db::models::{PoaAuditEventFilter, PoaEventType as DbPoaEventType};

use crate::models::power_of_attorney::{
    AdminListPoaQuery, AssumeIdentityResponse, CurrentAssumptionResponse, DropIdentityResponse,
    ExtendPoaRequest, GrantPoaRequest, ListPoaAuditQuery, ListPoaQuery, PoaAuditEventResponse,
    PoaAuditListResponse, PoaListResponse, PoaResponse, RevokePoaRequest,
};
use crate::router::GovernanceState;

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

    // Parse status string to PoaStatus
    let status = query
        .status
        .as_deref()
        .and_then(|s| match s.to_lowercase().as_str() {
            "pending" => Some(PoaStatus::Pending),
            "active" => Some(PoaStatus::Active),
            "expired" => Some(PoaStatus::Expired),
            "revoked" => Some(PoaStatus::Revoked),
            _ => None,
        });

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

    let status = query
        .status
        .as_deref()
        .and_then(|s| match s.to_lowercase().as_str() {
            "pending" => Some(PoaStatus::Pending),
            "active" => Some(PoaStatus::Active),
            "expired" => Some(PoaStatus::Expired),
            "revoked" => Some(PoaStatus::Revoked),
            _ => None,
        });

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
        (status = 200, description = "Identity assumed successfully", body = AssumeIdentityResponse),
        (status = 400, description = "PoA is not active or already assuming another identity"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Power of Attorney not found or not authorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn assume_identity(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(poa_id): Path<Uuid>,
) -> ApiResult<Json<AssumeIdentityResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let attorney_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Generate a unique JTI for the assumed session token
    let session_jti = format!("poa-{}", Uuid::new_v4());

    // Extract IP and user agent from request context (would need headers in real impl)
    let ip_address: Option<String> = None;
    let user_agent: Option<String> = None;

    let (session, donor_id) = state
        .poa_service
        .assume_identity(
            tenant_id,
            attorney_id,
            poa_id,
            session_jti.clone(),
            ip_address,
            user_agent,
        )
        .await?;

    // In a real implementation, we would generate a new JWT here with:
    // - acting_as_user_id: donor_id
    // - acting_as_poa_id: poa_id
    // - acting_as_session_id: session.id
    // For now, we return a placeholder token
    let access_token = format!("assumed_token_{}", session.id);

    Ok(Json(AssumeIdentityResponse {
        access_token,
        session_id: session.id,
        donor_id,
        donor_name: None, // Would be populated from user lookup
        donor_email: None,
        scope: None,
    }))
}

/// Drop the currently assumed identity and return to the attorney's own identity.
#[utoipa::path(
    post,
    path = "/governance/power-of-attorney/drop",
    tag = "Governance - Power of Attorney",
    responses(
        (status = 200, description = "Identity dropped successfully", body = DropIdentityResponse),
        (status = 400, description = "Not currently assuming any identity"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn drop_identity(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<DropIdentityResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let attorney_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let _dropped = state
        .poa_service
        .drop_identity(tenant_id, attorney_id)
        .await?;

    // In a real implementation, we would generate a new JWT for the attorney's own identity
    // For now, we return a placeholder token
    let access_token = format!("original_token_{}", attorney_id);

    Ok(Json(DropIdentityResponse { access_token }))
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
        Some((session, poa)) => Ok(Json(CurrentAssumptionResponse {
            is_assuming: true,
            poa_id: Some(poa.id),
            donor_id: Some(poa.donor_id),
            donor_name: None, // Would be populated from user lookup
            session_id: Some(session.id),
            assumed_at: Some(session.assumed_at),
            scope: None,
        })),
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

    // Parse event type filter
    let event_type = query.event_type.as_deref().and_then(parse_event_type);

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

/// Helper to parse event type string to enum.
fn parse_event_type(s: &str) -> Option<DbPoaEventType> {
    match s.to_lowercase().as_str() {
        "grant_created" => Some(DbPoaEventType::GrantCreated),
        "grant_extended" => Some(DbPoaEventType::GrantExtended),
        "grant_revoked" => Some(DbPoaEventType::GrantRevoked),
        "grant_expired" => Some(DbPoaEventType::GrantExpired),
        "identity_assumed" => Some(DbPoaEventType::IdentityAssumed),
        "identity_dropped" => Some(DbPoaEventType::IdentityDropped),
        "action_performed" => Some(DbPoaEventType::ActionPerformed),
        _ => None,
    }
}
