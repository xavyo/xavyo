//! OAuth2 authorize info and grant handlers for SvelteKit consent flow.

use crate::error::OAuthError;
use crate::models::{
    AuthorizeGrantRequest, AuthorizeGrantResponse, AuthorizeInfoQuery, AuthorizeInfoResponse,
    ClientResponse,
};
use crate::router::OAuthState;
use axum::{
    extract::{Extension, Query, State},
    Json,
};
use xavyo_core::{TenantId, UserId};

/// Validate a client for the authorization code flow.
///
/// Performs the full validation sequence: client exists, is active,
/// redirect_uri matches, scopes are valid, and `authorization_code`
/// grant type is allowed. Returns the validated client and the
/// canonicalized scope string.
async fn validate_authorize_request(
    state: &OAuthState,
    tenant_uuid: uuid::Uuid,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
) -> Result<(ClientResponse, String), OAuthError> {
    let client = state
        .client_service
        .get_client_by_client_id(tenant_uuid, client_id)
        .await?;

    if !client.is_active {
        return Err(OAuthError::InvalidClient(
            "Client is not active".to_string(),
        ));
    }

    state
        .client_service
        .validate_redirect_uri(&client, redirect_uri)?;

    let validated_scope = state.client_service.validate_scopes(&client, scope)?;

    state
        .client_service
        .validate_grant_type(&client, "authorization_code")?;

    Ok((client, validated_scope))
}

/// Returns client info for the consent page.
///
/// The SvelteKit frontend calls this to display the client name and
/// requested scopes on the consent screen before the user approves.
pub async fn authorize_info_handler(
    State(state): State<OAuthState>,
    Extension(tenant_id): Extension<TenantId>,
    Query(query): Query<AuthorizeInfoQuery>,
) -> Result<Json<AuthorizeInfoResponse>, OAuthError> {
    let (client, validated_scope) = validate_authorize_request(
        &state,
        *tenant_id.as_uuid(),
        &query.client_id,
        &query.redirect_uri,
        &query.scope,
    )
    .await?;

    let scopes: Vec<String> = validated_scope
        .split_whitespace()
        .map(String::from)
        .collect();

    Ok(Json(AuthorizeInfoResponse {
        client_name: client.name.clone(),
        client_id: client.client_id,
        scopes,
        redirect_uri: query.redirect_uri,
        client_logo_url: client.logo_url,
        client_description: client.description,
    }))
}

/// Grants an authorization code after user consent.
///
/// The SvelteKit frontend calls this when the user clicks "Allow"
/// on the consent screen. Returns the authorization code and redirect URI.
pub async fn authorize_grant_handler(
    State(state): State<OAuthState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
    Json(request): Json<AuthorizeGrantRequest>,
) -> Result<Json<AuthorizeGrantResponse>, OAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();

    // Validate client + params; get the internal DB UUID for code creation.
    let (client, _validated_scope) = validate_authorize_request(
        &state,
        tenant_uuid,
        &request.client_id,
        &request.redirect_uri,
        &request.scope,
    )
    .await?;

    let code = state
        .authorization_service
        .create_authorization_code(
            tenant_uuid,
            client.id, // Internal UUID, not the public client_id string
            *user_id.as_uuid(),
            &request.redirect_uri,
            &request.scope,
            &request.code_challenge,
            &request.code_challenge_method,
            request.nonce.as_deref(),
        )
        .await?;

    Ok(Json(AuthorizeGrantResponse {
        authorization_code: code,
        state: request.state,
        redirect_uri: request.redirect_uri,
    }))
}
