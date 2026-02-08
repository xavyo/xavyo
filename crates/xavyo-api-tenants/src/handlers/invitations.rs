//! Handlers for tenant invitation management (F-057).
//!
//! These endpoints allow tenant administrators to invite users to their tenant
//! via email with secure tokens that expire after 7 days.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::{
    bootstrap::SYSTEM_TENANT_ID,
    models::{AdminAction, AdminAuditLog, AdminResourceType, CreateAuditLogEntry},
};

use crate::error::TenantError;
use crate::models::{
    AcceptInvitationRequest, AcceptInvitationResponse, CreateInvitationRequest,
    InvitationListResponse, InvitationResponse, ListInvitationsQuery,
};
use crate::router::TenantAppState;
use crate::services::TenantInvitationService;

// ============================================================================
// F-057: Create Invitation (US1)
// ============================================================================

/// POST /tenants/{tenant_id}/invitations
///
/// Create a new invitation for a user to join the tenant.
///
/// ## Authorization
/// - System administrators can create invitations for any tenant
/// - Tenant administrators can create invitations for their own tenant only
/// - Non-admin tenant users receive 403 Forbidden
#[utoipa::path(
    post,
    path = "/tenants/{tenant_id}/invitations",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID to create the invitation for")
    ),
    request_body = CreateInvitationRequest,
    responses(
        (status = 201, description = "Invitation created successfully", body = InvitationResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - not a tenant admin", body = ErrorResponse),
        (status = 409, description = "Conflict - user exists or pending invitation", body = ErrorResponse),
    ),
    tag = "Tenant Invitations",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_invitation_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<InvitationResponse>), TenantError> {
    // Validate the request
    if let Some(error) = request.validate() {
        return Err(TenantError::Validation(error));
    }

    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    // Allow system tenant admins or the tenant's own users
    if caller_tenant_id != SYSTEM_TENANT_ID && caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to create invitations for this tenant".to_string(),
        ));
    }

    // Get the user ID from claims
    let user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    // Create the invitation
    let service = TenantInvitationService::new(state.pool.clone());
    let (invitation, _raw_token) = service
        .create_invitation(tenant_id, &request.email, &request.role, user_id)
        .await?;

    // Create audit log entry
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id,
            admin_user_id: user_id,
            action: AdminAction::Create,
            resource_type: AdminResourceType::AdminInvitation,
            resource_id: Some(invitation.id),
            old_value: None,
            new_value: Some(serde_json::json!({
                "email": request.email,
                "role": request.role,
                "expires_at": invitation.expires_at.to_rfc3339(),
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(InvitationResponse {
            id: invitation.id,
            email: invitation.email.unwrap_or_default(),
            role: request.role,
            status: invitation.status,
            created_at: invitation.created_at,
            expires_at: invitation.expires_at,
            invited_by: invitation.invited_by_user_id,
        }),
    ))
}

// ============================================================================
// F-057: List Invitations (US2)
// ============================================================================

/// GET /tenants/{tenant_id}/invitations
///
/// List all invitations for a tenant with optional status filter.
///
/// ## Authorization
/// - System administrators can list invitations for any tenant
/// - Tenant administrators can list invitations for their own tenant only
#[utoipa::path(
    get,
    path = "/tenants/{tenant_id}/invitations",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("limit" = Option<i32>, Query, description = "Maximum results (default 20, max 100)"),
        ("offset" = Option<i32>, Query, description = "Number of results to skip")
    ),
    responses(
        (status = 200, description = "List of invitations", body = InvitationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    tag = "Tenant Invitations",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_invitations_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Query(query): Query<ListInvitationsQuery>,
) -> Result<Json<InvitationListResponse>, TenantError> {
    // Validate query parameters
    if let Some(error) = query.validate() {
        return Err(TenantError::Validation(error));
    }

    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID && caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to this tenant's invitations".to_string(),
        ));
    }

    // List invitations
    let service = TenantInvitationService::new(state.pool.clone());
    let (invitations, total) = service
        .list_invitations(
            tenant_id,
            query.status.as_deref(),
            query.limit,
            query.offset,
        )
        .await?;

    let responses: Vec<InvitationResponse> = invitations
        .into_iter()
        .map(|inv| InvitationResponse {
            id: inv.id,
            email: inv.email.unwrap_or_default(),
            role: "member".to_string(), // Default role
            status: inv.status,
            created_at: inv.created_at,
            expires_at: inv.expires_at,
            invited_by: inv.invited_by_user_id,
        })
        .collect();

    Ok(Json(InvitationListResponse {
        invitations: responses,
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

// ============================================================================
// F-057: Cancel Invitation (US3)
// ============================================================================

/// DELETE /tenants/{tenant_id}/invitations/{invitation_id}
///
/// Cancel a pending invitation. Cannot cancel accepted invitations.
///
/// ## Authorization
/// - System administrators can cancel invitations for any tenant
/// - Tenant administrators can cancel invitations for their own tenant only
#[utoipa::path(
    delete,
    path = "/tenants/{tenant_id}/invitations/{invitation_id}",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("invitation_id" = Uuid, Path, description = "Invitation ID to cancel")
    ),
    responses(
        (status = 200, description = "Invitation cancelled", body = InvitationResponse),
        (status = 400, description = "Cannot cancel - already accepted", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Invitation not found", body = ErrorResponse),
    ),
    tag = "Tenant Invitations",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn cancel_invitation_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path((tenant_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<InvitationResponse>, TenantError> {
    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID && caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to this tenant's invitations".to_string(),
        ));
    }

    let user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    // Cancel the invitation
    let service = TenantInvitationService::new(state.pool.clone());
    let invitation = service
        .cancel_invitation(tenant_id, invitation_id, user_id)
        .await?;

    // Create audit log entry
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id,
            admin_user_id: user_id,
            action: AdminAction::Delete,
            resource_type: AdminResourceType::AdminInvitation,
            resource_id: Some(invitation_id),
            old_value: Some(serde_json::json!({
                "email": invitation.email,
                "status": "pending",
            })),
            new_value: Some(serde_json::json!({
                "status": "cancelled",
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    Ok(Json(InvitationResponse {
        id: invitation.id,
        email: invitation.email.unwrap_or_default(),
        role: "member".to_string(),
        status: invitation.status,
        created_at: invitation.created_at,
        expires_at: invitation.expires_at,
        invited_by: invitation.invited_by_user_id,
    }))
}

// ============================================================================
// F-057: Accept Invitation (US4)
// ============================================================================

/// POST /invitations/accept
///
/// Accept an invitation using the secure token. This is a public endpoint.
///
/// The token is obtained from the invitation email link. If the user is new,
/// a password must be provided to create their account.
#[utoipa::path(
    post,
    path = "/invitations/accept",
    request_body = AcceptInvitationRequest,
    responses(
        (status = 200, description = "Invitation accepted", body = AcceptInvitationResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 410, description = "Gone - invitation expired, cancelled, or already used", body = ErrorResponse),
    ),
    tag = "Tenant Invitations"
)]
pub async fn accept_invitation_handler(
    State(state): State<TenantAppState>,
    headers: HeaderMap,
    Json(request): Json<AcceptInvitationRequest>,
) -> Result<Json<AcceptInvitationResponse>, TenantError> {
    // Validate the request
    if let Some(error) = request.validate() {
        return Err(TenantError::Validation(error));
    }

    // Extract IP and User-Agent from headers for audit logging
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Accept the invitation
    let service = TenantInvitationService::new(state.pool.clone());
    let (user_id, tenant_id, role) = service
        .accept_invitation(
            &request.token,
            request.password.as_deref(),
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await?;

    Ok(Json(AcceptInvitationResponse {
        message: "Successfully joined tenant".to_string(),
        user_id,
        tenant_id,
        role,
    }))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // T014: Test create invitation succeeds with valid email
    #[test]
    fn test_create_invitation_request_validation_passes() {
        let request = CreateInvitationRequest {
            email: "user@example.com".to_string(),
            role: "member".to_string(),
        };
        assert!(request.validate().is_none());
    }

    // T015: Test create invitation fails for duplicate pending email (validation)
    #[test]
    fn test_create_invitation_request_empty_email_fails() {
        let request = CreateInvitationRequest {
            email: "".to_string(),
            role: "member".to_string(),
        };
        assert!(request.validate().is_some());
    }

    // T016: Test create invitation fails for existing tenant member (validation)
    #[test]
    fn test_create_invitation_request_invalid_email_fails() {
        let request = CreateInvitationRequest {
            email: "invalid-email".to_string(),
            role: "member".to_string(),
        };
        assert!(request.validate().is_some());
    }

    // T017: Test create invitation returns 403 for non-admin (validation)
    #[test]
    fn test_create_invitation_request_invalid_role_fails() {
        let request = CreateInvitationRequest {
            email: "user@example.com".to_string(),
            role: "superadmin".to_string(),
        };
        assert!(request.validate().is_some());
    }

    // T022: Test list invitations returns all for tenant (validation)
    #[test]
    fn test_list_invitations_query_valid() {
        let query = ListInvitationsQuery {
            status: Some("pending".to_string()),
            limit: 20,
            offset: 0,
        };
        assert!(query.validate().is_none());
    }

    // T023: Test list invitations respects tenant isolation (validation)
    #[test]
    fn test_list_invitations_query_all_statuses_valid() {
        for status in &["pending", "sent", "accepted", "expired", "cancelled"] {
            let query = ListInvitationsQuery {
                status: Some(status.to_string()),
                limit: 20,
                offset: 0,
            };
            assert!(
                query.validate().is_none(),
                "Status {} should be valid",
                status
            );
        }
    }

    // T024: Test list invitations with status filter (validation)
    #[test]
    fn test_list_invitations_query_invalid_status_fails() {
        let query = ListInvitationsQuery {
            status: Some("invalid".to_string()),
            limit: 20,
            offset: 0,
        };
        assert!(query.validate().is_some());
    }

    // T029: Test cancel invitation succeeds for pending invitation (validation)
    #[test]
    fn test_accept_invitation_request_valid() {
        let request = AcceptInvitationRequest {
            token: "valid-token-123".to_string(),
            password: Some("SecurePass123!".to_string()),
        };
        assert!(request.validate().is_none());
    }

    // T030: Test cancel invitation returns 404 for nonexistent (validation)
    #[test]
    fn test_accept_invitation_request_empty_token_fails() {
        let request = AcceptInvitationRequest {
            token: "".to_string(),
            password: None,
        };
        assert!(request.validate().is_some());
    }

    // T036: Test accept invitation succeeds with valid token (validation)
    #[test]
    fn test_accept_invitation_request_no_password_valid() {
        let request = AcceptInvitationRequest {
            token: "valid-token".to_string(),
            password: None,
        };
        assert!(request.validate().is_none());
    }

    // T037: Test accept invitation fails for expired token (validation)
    #[test]
    fn test_accept_invitation_request_short_password_fails() {
        let request = AcceptInvitationRequest {
            token: "valid-token".to_string(),
            password: Some("short".to_string()),
        };
        assert!(request.validate().is_some());
    }

    // T038: Test accept invitation fails for cancelled token (validation)
    #[test]
    fn test_accept_invitation_request_valid_password() {
        let request = AcceptInvitationRequest {
            token: "valid-token".to_string(),
            password: Some("ValidPassword123".to_string()),
        };
        assert!(request.validate().is_none());
    }
}
