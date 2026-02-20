//! Authorization handlers for initiating OAuth flows.

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use tracing::info;

use crate::error::{ProviderType, SocialError, SocialResult};
use crate::extractors::TenantId;
use crate::models::{AuthorizeQuery, AvailableProvider, AvailableProvidersResponse};
use crate::providers::{ProviderFactory, SocialProvider};
use crate::services::OAuthService;
use crate::SocialState;

/// Initiate the OAuth authorization flow.
///
/// Redirects the user to the social provider's authorization page.
#[utoipa::path(
    get,
    path = "/auth/social/{provider}/authorize",
    params(
        ("provider" = String, Path, description = "Social provider (google, microsoft, apple)"),
        ("redirect_after" = Option<String>, Query, description = "URL to redirect after login"),
    ),
    responses(
        (status = 302, description = "Redirect to provider authorization page"),
        (status = 400, description = "Invalid provider"),
        (status = 404, description = "Provider not enabled"),
    ),
    tag = "Social Authentication"
)]
pub async fn authorize(
    State(state): State<SocialState>,
    TenantId(tenant_id): TenantId,
    Path(provider): Path<String>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, SocialError> {
    let provider_type: ProviderType = provider.parse()?;

    info!(
        tenant_id = %tenant_id,
        provider = %provider_type,
        "Initiating social login"
    );

    // Get provider configuration
    let config = state
        .tenant_provider_service
        .get_enabled_provider(tenant_id, provider_type)
        .await?
        .ok_or(SocialError::ProviderUnavailable {
            provider: provider_type,
        })?;

    // Generate PKCE challenge
    let pkce = OAuthService::generate_pkce();

    // Generate OIDC nonce for providers that support it (defense-in-depth against ID token replay)
    let oidc_nonce = OAuthService::generate_oidc_nonce(provider_type);

    // Create signed state
    let state_token = state.oauth_service.create_state(
        tenant_id,
        provider_type,
        &pkce.verifier,
        query.redirect_after,
        None, // No user_id for initial login
        oidc_nonce.clone(),
    )?;

    // Build redirect URI
    let redirect_uri = format!(
        "{}/api/v1/auth/social/{}/callback",
        state.base_url, provider_type
    );

    // Create provider instance and get authorization URL
    let nonce_ref = oidc_nonce.as_deref();
    let auth_url = match provider_type {
        ProviderType::Google => {
            let p = ProviderFactory::google(config.client_id, config.client_secret);
            p.authorization_url(&state_token, &pkce.challenge, &redirect_uri, nonce_ref)
        }
        ProviderType::Microsoft => {
            let azure_tenant = config
                .additional_config
                .as_ref()
                .and_then(|c| c.get("azure_tenant"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let p =
                ProviderFactory::microsoft(config.client_id, config.client_secret, azure_tenant)?;
            p.authorization_url(&state_token, &pkce.challenge, &redirect_uri, nonce_ref)
        }
        ProviderType::Apple => {
            let additional = config
                .additional_config
                .ok_or(SocialError::ConfigurationError {
                    message: "Apple requires team_id, key_id, and private_key in additional_config"
                        .to_string(),
                })?;
            let team_id = additional
                .get("team_id")
                .and_then(|v| v.as_str())
                .ok_or(SocialError::ConfigurationError {
                    message: "Missing team_id in Apple config".to_string(),
                })?
                .to_string();
            let key_id = additional
                .get("key_id")
                .and_then(|v| v.as_str())
                .ok_or(SocialError::ConfigurationError {
                    message: "Missing key_id in Apple config".to_string(),
                })?
                .to_string();
            let private_key = additional
                .get("private_key")
                .and_then(|v| v.as_str())
                .ok_or(SocialError::ConfigurationError {
                    message: "Missing private_key in Apple config".to_string(),
                })?
                .to_string();

            let p = ProviderFactory::apple(config.client_id, team_id, key_id, private_key)?;
            p.authorization_url(&state_token, &pkce.challenge, &redirect_uri, nonce_ref)
        }
        ProviderType::Github => {
            let p = ProviderFactory::github(config.client_id, config.client_secret);
            p.authorization_url(&state_token, &pkce.challenge, &redirect_uri, nonce_ref)
        }
    };

    Ok(Redirect::temporary(&auth_url).into_response())
}

/// Get available social providers for the login page.
#[utoipa::path(
    get,
    path = "/auth/social/available",
    responses(
        (status = 200, description = "List of available providers", body = AvailableProvidersResponse),
    ),
    tag = "Social Authentication"
)]
pub async fn available_providers(
    State(state): State<SocialState>,
    TenantId(tenant_id): TenantId,
) -> SocialResult<Json<AvailableProvidersResponse>> {
    let enabled_providers = state
        .tenant_provider_service
        .list_enabled_providers(tenant_id)
        .await?;

    let providers: Vec<AvailableProvider> = enabled_providers
        .into_iter()
        .map(|p| AvailableProvider::new(p, &state.base_url))
        .collect();

    Ok(Json(AvailableProvidersResponse { providers }))
}
