//! Handlers for OAuth client management.
//!
//! F-SECRET-ROTATE: These endpoints allow tenants to manage and rotate their OAuth client secrets.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{AdminAction, AdminAuditLog, AdminResourceType, CreateAuditLogEntry};

use crate::error::TenantError;
use crate::models::{
    OAuthClientDetails, OAuthClientListResponse, RotateOAuthSecretRequest,
    RotateOAuthSecretResponse,
};
use crate::router::TenantAppState;

/// POST /tenants/{tenant_id}/oauth-clients/{client_id}/rotate-secret
///
/// Rotate an OAuth client secret, generating a new secret.
///
/// The new secret is returned in plaintext (once only). The old secret
/// is immediately invalidated and all refresh tokens are revoked.
///
/// Note: Unlike API keys, OAuth client secrets do not support a grace period
/// because the `OAuth2` spec requires immediate invalidation of the old secret
/// for security reasons.
#[utoipa::path(
    post,
    path = "/tenants/{tenant_id}/oauth-clients/{client_id}/rotate-secret",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("client_id" = Uuid, Path, description = "OAuth Client internal ID")
    ),
    request_body = RotateOAuthSecretRequest,
    responses(
        (status = 200, description = "OAuth client secret rotated successfully", body = RotateOAuthSecretResponse),
        (status = 400, description = "Validation error - cannot rotate public client", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "OAuth client not found", body = ErrorResponse),
    ),
    tag = "OAuth Clients",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn rotate_oauth_secret_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path((tenant_id, client_id)): Path<(Uuid, Uuid)>,
    Json(_request): Json<RotateOAuthSecretRequest>,
) -> Result<Json<RotateOAuthSecretResponse>, TenantError> {
    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to this tenant's OAuth clients".to_string(),
        ));
    }

    // Only admin/super_admin can rotate OAuth client secrets
    if !claims.has_role("admin") {
        return Err(TenantError::Forbidden(
            "Only administrators can manage OAuth clients".to_string(),
        ));
    }

    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    // Use OAuth2ClientService to regenerate the secret
    // This service is from xavyo-api-oauth and handles all the details
    let oauth_service = xavyo_api_oauth::services::OAuth2ClientService::new(state.pool.clone());

    // First, get the client to verify it exists and capture details for audit
    let client = oauth_service
        .get_client_by_id(tenant_id, client_id)
        .await
        .map_err(|e| match e {
            xavyo_api_oauth::error::OAuthError::ClientNotFound => {
                TenantError::NotFoundWithMessage(format!("OAuth client {client_id} not found"))
            }
            _ => TenantError::Database(e.to_string()),
        })?;

    // Regenerate the secret (this also revokes all refresh tokens)
    let new_secret = oauth_service
        .regenerate_client_secret(tenant_id, client_id)
        .await
        .map_err(|e| match e {
            xavyo_api_oauth::error::OAuthError::ClientNotFound => {
                TenantError::NotFoundWithMessage(format!("OAuth client {client_id} not found"))
            }
            xavyo_api_oauth::error::OAuthError::InvalidClient(msg) => TenantError::Validation(msg),
            _ => TenantError::Database(e.to_string()),
        })?;

    // Audit log - note: we don't log the plaintext secret
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id,
            admin_user_id,
            action: AdminAction::Update,
            resource_type: AdminResourceType::OauthClient,
            resource_id: Some(client_id),
            old_value: Some(serde_json::json!({
                "client_id": client.client_id,
                "name": client.name,
                "secret_rotated": true,
            })),
            new_value: Some(serde_json::json!({
                "client_id": client.client_id,
                "name": client.name,
                "secret_rotated_at": Utc::now(),
                "refresh_tokens_revoked": true,
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        client_id = %client_id,
        client_public_id = %client.client_id,
        admin_user_id = %admin_user_id,
        "OAuth client secret rotated"
    );

    Ok(Json(RotateOAuthSecretResponse {
        client_id,
        public_client_id: client.client_id,
        new_client_secret: new_secret, // Shown only once!
        rotated_at: Utc::now(),
        refresh_tokens_revoked: true,
    }))
}

/// GET /tenants/{tenant_id}/oauth-clients
///
/// List all OAuth clients for a tenant.
#[utoipa::path(
    get,
    path = "/tenants/{tenant_id}/oauth-clients",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "List of OAuth clients", body = OAuthClientListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    tag = "OAuth Clients",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_oauth_clients_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<OAuthClientListResponse>, TenantError> {
    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to this tenant's OAuth clients".to_string(),
        ));
    }

    // Only admin/super_admin can list OAuth clients
    if !claims.has_role("admin") {
        return Err(TenantError::Forbidden(
            "Only administrators can manage OAuth clients".to_string(),
        ));
    }

    let oauth_service = xavyo_api_oauth::services::OAuth2ClientService::new(state.pool.clone());

    let clients = oauth_service
        .list_clients(tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    let oauth_clients: Vec<OAuthClientDetails> = clients
        .into_iter()
        .map(|c| OAuthClientDetails {
            id: c.id,
            client_id: c.client_id,
            name: c.name,
            client_type: format!("{:?}", c.client_type).to_lowercase(),
            redirect_uris: c.redirect_uris,
            grant_types: c.grant_types,
            scopes: c.scopes,
            is_active: c.is_active,
            created_at: c.created_at,
            updated_at: c.updated_at,
        })
        .collect();

    let total = oauth_clients.len();
    Ok(Json(OAuthClientListResponse {
        oauth_clients,
        total,
    }))
}

/// DELETE /tenants/{tenant_id}/oauth-clients/{client_id}
///
/// Deactivate an OAuth client.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant_id}/oauth-clients/{client_id}",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("client_id" = Uuid, Path, description = "OAuth Client internal ID")
    ),
    responses(
        (status = 204, description = "OAuth client deactivated"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "OAuth client not found", body = ErrorResponse),
    ),
    tag = "OAuth Clients",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn deactivate_oauth_client_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path((tenant_id, client_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, TenantError> {
    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to this tenant's OAuth clients".to_string(),
        ));
    }

    // Only admin/super_admin can deactivate OAuth clients
    if !claims.has_role("admin") {
        return Err(TenantError::Forbidden(
            "Only administrators can manage OAuth clients".to_string(),
        ));
    }

    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    let oauth_service = xavyo_api_oauth::services::OAuth2ClientService::new(state.pool.clone());

    // Get client details for audit log before deactivation
    let client = oauth_service
        .get_client_by_id(tenant_id, client_id)
        .await
        .map_err(|e| match e {
            xavyo_api_oauth::error::OAuthError::ClientNotFound => {
                TenantError::NotFoundWithMessage(format!("OAuth client {client_id} not found"))
            }
            _ => TenantError::Database(e.to_string()),
        })?;

    // Deactivate the client
    oauth_service
        .deactivate_client(tenant_id, client_id)
        .await
        .map_err(|e| match e {
            xavyo_api_oauth::error::OAuthError::ClientNotFound => {
                TenantError::NotFoundWithMessage(format!("OAuth client {client_id} not found"))
            }
            _ => TenantError::Database(e.to_string()),
        })?;

    // Audit log
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id,
            admin_user_id,
            action: AdminAction::Delete,
            resource_type: AdminResourceType::OauthClient,
            resource_id: Some(client_id),
            old_value: Some(serde_json::json!({
                "client_id": client.client_id,
                "name": client.name,
                "is_active": client.is_active,
            })),
            new_value: Some(serde_json::json!({
                "is_active": false,
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        client_id = %client_id,
        client_public_id = %client.client_id,
        admin_user_id = %admin_user_id,
        "OAuth client deactivated"
    );

    Ok(StatusCode::NO_CONTENT)
}
