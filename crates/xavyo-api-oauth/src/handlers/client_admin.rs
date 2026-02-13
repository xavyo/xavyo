//! `OAuth2` client admin endpoint handlers.
//!
//! These handlers require admin authentication and provide CRUD operations
//! for managing `OAuth2` clients within a tenant.

use crate::error::OAuthError;
use crate::models::{
    ClientListResponse, ClientResponse, CreateClientRequest, CreateClientResponse,
    UpdateClientRequest,
};
use crate::router::OAuthState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

/// Lists all `OAuth2` clients for the current tenant.
#[utoipa::path(
    get,
    path = "/admin/oauth/clients",
    responses(
        (status = 200, description = "List of OAuth2 clients", body = ClientListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OAuth2 Admin"
)]
pub async fn list_clients_handler(
    State(state): State<OAuthState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<ClientListResponse>, OAuthError> {
    if !claims.has_role("admin") {
        return Err(OAuthError::AccessDenied("Admin role required".into()));
    }
    let tid = *tenant_id.as_uuid();

    let clients = state.client_service.list_clients(tid).await?;
    let total = clients.len() as i64;

    Ok(Json(ClientListResponse { clients, total }))
}

/// Gets a single `OAuth2` client by ID.
#[utoipa::path(
    get,
    path = "/admin/oauth/clients/{id}",
    params(
        ("id" = Uuid, Path, description = "Client ID"),
    ),
    responses(
        (status = 200, description = "OAuth2 client", body = ClientResponse),
        (status = 404, description = "Client not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OAuth2 Admin"
)]
pub async fn get_client_handler(
    State(state): State<OAuthState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<ClientResponse>, OAuthError> {
    if !claims.has_role("admin") {
        return Err(OAuthError::AccessDenied("Admin role required".into()));
    }
    let tid = *tenant_id.as_uuid();

    let client = state.client_service.get_client_by_id(tid, id).await?;

    Ok(Json(client))
}

/// Creates a new `OAuth2` client.
#[utoipa::path(
    post,
    path = "/admin/oauth/clients",
    request_body = CreateClientRequest,
    responses(
        (status = 200, description = "OAuth2 client created", body = CreateClientResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OAuth2 Admin"
)]
pub async fn create_client_handler(
    State(state): State<OAuthState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateClientRequest>,
) -> Result<Json<CreateClientResponse>, OAuthError> {
    if !claims.has_role("admin") {
        return Err(OAuthError::AccessDenied("Admin role required".into()));
    }
    let tid = *tenant_id.as_uuid();

    // Validate the request
    if request.name.is_empty() {
        return Err(OAuthError::InvalidRequest(
            "Client name is required".to_string(),
        ));
    }

    if request.redirect_uris.is_empty()
        && request
            .grant_types
            .contains(&"authorization_code".to_string())
    {
        return Err(OAuthError::InvalidRequest(
            "redirect_uris is required for authorization_code grant".to_string(),
        ));
    }

    if request.grant_types.is_empty() {
        return Err(OAuthError::InvalidRequest(
            "At least one grant_type is required".to_string(),
        ));
    }

    // Validate grant types
    let valid_grant_types = ["authorization_code", "client_credentials", "refresh_token"];
    for grant_type in &request.grant_types {
        if !valid_grant_types.contains(&grant_type.as_str()) {
            return Err(OAuthError::InvalidRequest(format!(
                "Invalid grant_type: {grant_type}"
            )));
        }
    }

    let (client, secret) = state.client_service.create_client(tid, request).await?;

    Ok(Json(CreateClientResponse {
        client,
        client_secret: secret,
    }))
}

/// Updates an existing `OAuth2` client.
#[utoipa::path(
    put,
    path = "/admin/oauth/clients/{id}",
    params(
        ("id" = Uuid, Path, description = "Client ID"),
    ),
    request_body = UpdateClientRequest,
    responses(
        (status = 200, description = "OAuth2 client updated", body = ClientResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Client not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OAuth2 Admin"
)]
pub async fn update_client_handler(
    State(state): State<OAuthState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateClientRequest>,
) -> Result<Json<ClientResponse>, OAuthError> {
    if !claims.has_role("admin") {
        return Err(OAuthError::AccessDenied("Admin role required".into()));
    }
    let tid = *tenant_id.as_uuid();

    // Validate grant types if provided
    if let Some(ref grant_types) = request.grant_types {
        let valid_grant_types = ["authorization_code", "client_credentials", "refresh_token"];
        for grant_type in grant_types {
            if !valid_grant_types.contains(&grant_type.as_str()) {
                return Err(OAuthError::InvalidRequest(format!(
                    "Invalid grant_type: {grant_type}"
                )));
            }
        }
    }

    let client = state.client_service.update_client(tid, id, request).await?;

    Ok(Json(client))
}

/// Deactivates an `OAuth2` client (soft delete).
#[utoipa::path(
    delete,
    path = "/admin/oauth/clients/{id}",
    params(
        ("id" = Uuid, Path, description = "Client ID"),
    ),
    responses(
        (status = 204, description = "OAuth2 client deactivated"),
        (status = 404, description = "Client not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OAuth2 Admin"
)]
pub async fn delete_client_handler(
    State(state): State<OAuthState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, OAuthError> {
    if !claims.has_role("admin") {
        return Err(OAuthError::AccessDenied("Admin role required".into()));
    }
    let tid = *tenant_id.as_uuid();

    state.client_service.delete_client(tid, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Regenerates the client secret for a confidential client.
#[utoipa::path(
    post,
    path = "/admin/oauth/clients/{id}/regenerate-secret",
    params(
        ("id" = Uuid, Path, description = "Client ID"),
    ),
    responses(
        (status = 200, description = "New client secret", body = RegenerateSecretResponse),
        (status = 404, description = "Client not found"),
        (status = 400, description = "Client is not confidential"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OAuth2 Admin"
)]
pub async fn regenerate_secret_handler(
    State(state): State<OAuthState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<RegenerateSecretResponse>, OAuthError> {
    if !claims.has_role("admin") {
        return Err(OAuthError::AccessDenied("Admin role required".into()));
    }
    let tid = *tenant_id.as_uuid();

    let new_secret = state
        .client_service
        .regenerate_client_secret(tid, id)
        .await?;

    Ok(Json(RegenerateSecretResponse {
        client_secret: new_secret,
    }))
}

/// Response for regenerate secret endpoint.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct RegenerateSecretResponse {
    /// The new client secret (only shown once).
    pub client_secret: String,
}
