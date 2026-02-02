//! Admin invitation handlers (F-ADMIN-INVITE).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;

use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::ApiAuthError;
use crate::models::{
    AcceptInvitationRequest, AcceptInvitationResponse, CreateInvitationRequest,
    InvitationListResponse, InvitationResponse, ListInvitationsQuery,
};
use crate::services::AdminInviteService;

/// Shared state for admin invite handlers.
#[derive(Clone)]
pub struct AdminInviteState {
    pub service: AdminInviteService,
}

/// Extract user_id from JWT claims.
fn extract_user_id(claims: &JwtClaims) -> Result<Uuid, ApiAuthError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)
}

/// POST /admin/invitations - Create a new admin invitation.
#[utoipa::path(
    post,
    path = "/admin/invitations",
    tag = "Admin Invitations",
    request_body = CreateInvitationRequest,
    responses(
        (status = 201, description = "Invitation created", body = InvitationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Conflict - user exists or pending invitation"),
        (status = 429, description = "Rate limited"),
    ),
    security(("bearer" = []))
)]
pub async fn create_invitation_handler(
    State(state): State<Arc<AdminInviteState>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateInvitationRequest>,
) -> Result<impl IntoResponse, ApiAuthError> {
    // Validate request
    request.validate().map_err(ApiAuthError::Validation)?;

    let tenant_uuid = *tenant_id.as_uuid();
    let admin_user_id = extract_user_id(&claims)?;

    // Extract request metadata for audit
    let ip_address = None; // Would come from request headers in real impl
    let user_agent = None;

    let invitation = state
        .service
        .create_invitation(
            tenant_uuid,
            &request.email,
            request.role_template_id,
            admin_user_id,
            ip_address,
            user_agent,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(InvitationResponse::from(invitation)),
    ))
}

/// POST /admin/invitations/accept - Accept an invitation and set password (public endpoint).
#[utoipa::path(
    post,
    path = "/admin/invitations/accept",
    tag = "Admin Invitations",
    request_body = AcceptInvitationRequest,
    responses(
        (status = 200, description = "Invitation accepted", body = AcceptInvitationResponse),
        (status = 400, description = "Invalid request"),
        (status = 410, description = "Invitation expired or already used"),
    )
)]
pub async fn accept_invitation_handler(
    State(state): State<Arc<AdminInviteState>>,
    Json(request): Json<AcceptInvitationRequest>,
) -> Result<impl IntoResponse, ApiAuthError> {
    // Validate request
    request.validate().map_err(ApiAuthError::Validation)?;

    // Extract request metadata for audit
    let ip_address = None;
    let user_agent = None;

    let (user, _invitation) = state
        .service
        .accept_invitation(&request.token, &request.password, ip_address, user_agent)
        .await?;

    Ok(Json(AcceptInvitationResponse {
        message: "Account created successfully".to_string(),
        user_id: user.id,
        email: user.email,
    }))
}

/// POST /admin/invitations/{id}/resend - Resend an invitation.
#[utoipa::path(
    post,
    path = "/admin/invitations/{id}/resend",
    tag = "Admin Invitations",
    params(
        ("id" = Uuid, Path, description = "Invitation ID")
    ),
    responses(
        (status = 200, description = "Invitation resent", body = InvitationResponse),
        (status = 400, description = "Cannot resend - already accepted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Invitation not found"),
    ),
    security(("bearer" = []))
)]
pub async fn resend_invitation_handler(
    State(state): State<Arc<AdminInviteState>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let admin_user_id = extract_user_id(&claims)?;

    let ip_address = None;
    let user_agent = None;

    let invitation = state
        .service
        .resend_invitation(tenant_uuid, id, admin_user_id, ip_address, user_agent)
        .await?;

    Ok(Json(InvitationResponse::from(invitation)))
}

/// DELETE /admin/invitations/{id} - Cancel an invitation.
#[utoipa::path(
    delete,
    path = "/admin/invitations/{id}",
    tag = "Admin Invitations",
    params(
        ("id" = Uuid, Path, description = "Invitation ID")
    ),
    responses(
        (status = 200, description = "Invitation cancelled", body = InvitationResponse),
        (status = 400, description = "Cannot cancel - already accepted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Invitation not found"),
    ),
    security(("bearer" = []))
)]
pub async fn cancel_invitation_handler(
    State(state): State<Arc<AdminInviteState>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let admin_user_id = extract_user_id(&claims)?;

    let ip_address = None;
    let user_agent = None;

    let invitation = state
        .service
        .cancel_invitation(tenant_uuid, id, admin_user_id, ip_address, user_agent)
        .await?;

    Ok(Json(InvitationResponse::from(invitation)))
}

/// GET /admin/invitations - List invitations.
#[utoipa::path(
    get,
    path = "/admin/invitations",
    tag = "Admin Invitations",
    params(ListInvitationsQuery),
    responses(
        (status = 200, description = "List of invitations", body = InvitationListResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer" = []))
)]
pub async fn list_invitations_handler(
    State(state): State<Arc<AdminInviteState>>,
    Extension(tenant_id): Extension<TenantId>,
    Query(mut query): Query<ListInvitationsQuery>,
) -> Result<impl IntoResponse, ApiAuthError> {
    // Validate and normalize query
    query.validate().map_err(ApiAuthError::Validation)?;

    let tenant_uuid = *tenant_id.as_uuid();

    let (invitations, total) = state
        .service
        .list_invitations(
            tenant_uuid,
            query.status.as_deref(),
            query.email.as_deref(),
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(InvitationListResponse {
        invitations: invitations
            .into_iter()
            .map(InvitationResponse::from)
            .collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}
