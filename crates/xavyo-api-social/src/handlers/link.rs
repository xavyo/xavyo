//! Account linking handlers.

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use tracing::info;

use crate::error::{ProviderType, SocialError, SocialResult};
use crate::extractors::AuthenticatedUser;
use crate::models::{ConnectionsListResponse, LinkAccountRequest, SocialConnectionResponse};
use crate::providers::SocialProvider;
use crate::services::OAuthService;
use crate::SocialState;

/// Link a social account to the current user.
///
/// Requires the user to be authenticated.
#[utoipa::path(
    post,
    path = "/auth/social/link/{provider}",
    params(
        ("provider" = String, Path, description = "Social provider to link"),
    ),
    request_body = LinkAccountRequest,
    responses(
        (status = 200, description = "Account linked", body = SocialConnectionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 409, description = "Account already linked to another user"),
    ),
    security(("bearerAuth" = [])),
    tag = "Account Linking"
)]
pub async fn link_account(
    State(state): State<SocialState>,
    user: AuthenticatedUser,
    Path(provider): Path<String>,
    Json(request): Json<LinkAccountRequest>,
) -> SocialResult<Json<SocialConnectionResponse>> {
    let provider_type: ProviderType = provider.parse()?;
    let user_id = user.user_id;
    let tenant_id = user.tenant_id;

    info!(
        user_id = %user_id,
        provider = %provider_type,
        "Linking social account"
    );

    // Validate state
    let claims = state.oauth_service.validate_state(&request.state)?;

    // Verify this linking flow was initiated for this user and tenant
    if claims.user_id != Some(user_id) {
        return Err(SocialError::InvalidState {
            reason: "State was not created for this user".to_string(),
        });
    }
    if claims.tenant_id != tenant_id {
        return Err(SocialError::InvalidState {
            reason: "State was not created for this tenant".to_string(),
        });
    }

    // Get provider configuration
    let config = state
        .tenant_provider_service
        .get_enabled_provider(tenant_id, provider_type)
        .await?
        .ok_or(SocialError::ProviderUnavailable {
            provider: provider_type,
        })?;

    // Build redirect URI
    let redirect_uri = format!(
        "{}/api/v1/auth/social/{}/callback",
        state.base_url, provider_type
    );

    // Exchange code for tokens (similar to callback)
    let (tokens, user_info) = match provider_type {
        ProviderType::Google => {
            let p =
                crate::providers::ProviderFactory::google(config.client_id, config.client_secret);
            let tokens = p
                .exchange_code(&request.code, &claims.pkce_verifier, &redirect_uri)
                .await?;
            let user_info = p
                .fetch_user_info(&tokens.access_token, tokens.id_token.as_deref())
                .await?;
            (tokens, user_info)
        }
        ProviderType::Microsoft => {
            let azure_tenant = config
                .additional_config
                .as_ref()
                .and_then(|c| c.get("azure_tenant"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let p = crate::providers::ProviderFactory::microsoft(
                config.client_id,
                config.client_secret,
                azure_tenant,
            );
            let tokens = p
                .exchange_code(&request.code, &claims.pkce_verifier, &redirect_uri)
                .await?;
            let user_info = p
                .fetch_user_info(&tokens.access_token, tokens.id_token.as_deref())
                .await?;
            (tokens, user_info)
        }
        ProviderType::Apple => {
            let additional = config
                .additional_config
                .ok_or(SocialError::ConfigurationError {
                    message: "Apple requires additional config".to_string(),
                })?;
            let team_id = additional
                .get("team_id")
                .and_then(|v| v.as_str())
                .ok_or(SocialError::ConfigurationError {
                    message: "Apple config missing team_id".to_string(),
                })?
                .to_string();
            let key_id = additional
                .get("key_id")
                .and_then(|v| v.as_str())
                .ok_or(SocialError::ConfigurationError {
                    message: "Apple config missing key_id".to_string(),
                })?
                .to_string();
            let private_key = additional
                .get("private_key")
                .and_then(|v| v.as_str())
                .ok_or(SocialError::ConfigurationError {
                    message: "Apple config missing private_key".to_string(),
                })?
                .to_string();

            let p = crate::providers::ProviderFactory::apple(
                config.client_id,
                team_id,
                key_id,
                private_key,
            )?;
            let tokens = p
                .exchange_code(&request.code, &claims.pkce_verifier, &redirect_uri)
                .await?;
            let user_info = p
                .fetch_user_info(&tokens.access_token, tokens.id_token.as_deref())
                .await?;
            (tokens, user_info)
        }
        ProviderType::Github => {
            let p =
                crate::providers::ProviderFactory::github(config.client_id, config.client_secret);
            let tokens = p
                .exchange_code(&request.code, &claims.pkce_verifier, &redirect_uri)
                .await?;
            let user_info = p
                .fetch_user_info(&tokens.access_token, tokens.id_token.as_deref())
                .await?;
            (tokens, user_info)
        }
    };

    // Link the account
    let connection_id = state
        .connection_service
        .link_to_existing_user(
            tenant_id,
            user_id,
            provider_type,
            &user_info,
            Some(&tokens.access_token),
            tokens.refresh_token.as_deref(),
            tokens.expires_in,
        )
        .await?;

    info!(
        user_id = %user_id,
        connection_id = %connection_id,
        provider = %provider_type,
        "Successfully linked social account"
    );

    // Return connection info
    let display_name = user_info.display_name();
    Ok(Json(SocialConnectionResponse {
        id: connection_id,
        provider: provider_type.to_string(),
        email: user_info.email,
        display_name: Some(display_name),
        is_private_email: user_info.is_private_email,
        created_at: chrono::Utc::now(),
    }))
}

/// Initiate account linking flow for an authenticated user.
///
/// Redirects to the provider's authorization page with `user_id` in state.
#[utoipa::path(
    get,
    path = "/auth/social/link/{provider}/authorize",
    params(
        ("provider" = String, Path, description = "Social provider to link"),
    ),
    responses(
        (status = 302, description = "Redirect to provider authorization page"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Provider not enabled"),
    ),
    security(("bearerAuth" = [])),
    tag = "Account Linking"
)]
pub async fn initiate_link(
    State(state): State<SocialState>,
    user: AuthenticatedUser,
    Path(provider): Path<String>,
) -> Result<Response, SocialError> {
    let provider_type: ProviderType = provider.parse()?;
    let user_id = user.user_id;
    let tenant_id = user.tenant_id;

    info!(
        user_id = %user_id,
        provider = %provider_type,
        "Initiating account linking"
    );

    // Get provider configuration
    let config = state
        .tenant_provider_service
        .get_enabled_provider(tenant_id, provider_type)
        .await?
        .ok_or(SocialError::ProviderUnavailable {
            provider: provider_type,
        })?;

    // Generate PKCE
    let pkce = OAuthService::generate_pkce();

    // Create state with user_id for linking
    let state_token = state.oauth_service.create_state(
        tenant_id,
        provider_type,
        &pkce.verifier,
        Some("/settings".to_string()), // Redirect back to settings after linking
        Some(user_id),
    )?;

    // Build redirect URI
    let redirect_uri = format!(
        "{}/api/v1/auth/social/{}/callback",
        state.base_url, provider_type
    );

    // Get authorization URL
    let auth_url = match provider_type {
        ProviderType::Google => {
            let p =
                crate::providers::ProviderFactory::google(config.client_id, config.client_secret);
            p.authorization_url(&state_token, &pkce.challenge, &redirect_uri)
        }
        ProviderType::Microsoft => {
            let azure_tenant = config
                .additional_config
                .as_ref()
                .and_then(|c| c.get("azure_tenant"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let p = crate::providers::ProviderFactory::microsoft(
                config.client_id,
                config.client_secret,
                azure_tenant,
            );
            p.authorization_url(&state_token, &pkce.challenge, &redirect_uri)
        }
        ProviderType::Apple => {
            let additional = config
                .additional_config
                .ok_or(SocialError::ConfigurationError {
                    message: "Apple requires additional config".to_string(),
                })?;
            let team_id = additional
                .get("team_id")
                .and_then(|v| v.as_str())
                .ok_or(SocialError::ConfigurationError {
                    message: "Apple config missing team_id".to_string(),
                })?
                .to_string();
            let key_id = additional
                .get("key_id")
                .and_then(|v| v.as_str())
                .ok_or(SocialError::ConfigurationError {
                    message: "Apple config missing key_id".to_string(),
                })?
                .to_string();
            let private_key = additional
                .get("private_key")
                .and_then(|v| v.as_str())
                .ok_or(SocialError::ConfigurationError {
                    message: "Apple config missing private_key".to_string(),
                })?
                .to_string();

            let p = crate::providers::ProviderFactory::apple(
                config.client_id,
                team_id,
                key_id,
                private_key,
            )?;
            p.authorization_url(&state_token, &pkce.challenge, &redirect_uri)
        }
        ProviderType::Github => {
            let p =
                crate::providers::ProviderFactory::github(config.client_id, config.client_secret);
            p.authorization_url(&state_token, &pkce.challenge, &redirect_uri)
        }
    };

    Ok(Redirect::temporary(&auth_url).into_response())
}

/// List all social connections for the current user.
#[utoipa::path(
    get,
    path = "/auth/social/connections",
    responses(
        (status = 200, description = "List of connections", body = ConnectionsListResponse),
        (status = 401, description = "Not authenticated"),
    ),
    security(("bearerAuth" = [])),
    tag = "Account Linking"
)]
pub async fn list_connections(
    State(state): State<SocialState>,
    user: AuthenticatedUser,
) -> SocialResult<Json<ConnectionsListResponse>> {
    let user_id = user.user_id;
    let tenant_id = user.tenant_id;

    let connections = state
        .connection_service
        .get_user_connections(tenant_id, user_id)
        .await?;

    let responses: Vec<SocialConnectionResponse> = connections
        .into_iter()
        .map(|c| SocialConnectionResponse {
            id: c.id,
            provider: c.provider,
            email: c.email,
            display_name: c.display_name,
            is_private_email: c.is_private_email,
            created_at: c.created_at,
        })
        .collect();

    Ok(Json(ConnectionsListResponse {
        connections: responses,
    }))
}
