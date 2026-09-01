//! Callback handlers for processing OAuth responses.

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
    Form,
};
use tracing::{info, warn};

use crate::error::{ProviderType, SocialError};
use crate::models::{AppleCallbackForm, AppleUserInfo, OAuthCallbackQuery};
use crate::providers::{ProviderFactory, SocialProvider, SocialUserInfo};
use crate::services::ConnectionResult;
use crate::SocialState;

/// Advertised user profile fields from a social provider userinfo payload.
pub fn social_profile_fields(
    info: &SocialUserInfo,
) -> (String, Option<String>, Option<String>, Option<String>) {
    let nonempty = |s: Option<&str>| {
        s.map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    (
        info.display_name(),
        nonempty(info.given_name.as_deref()),
        nonempty(info.family_name.as_deref()),
        nonempty(info.picture.as_deref()),
    )
}

/// Sanitize redirect_after to prevent open redirects.
/// Only allows relative paths starting with `/` (rejects `//`, `://`, `\`).
fn sanitize_redirect_after(redirect: &str) -> Option<&str> {
    let trimmed = redirect.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Must start with /
    if !trimmed.starts_with('/') {
        return None;
    }
    // Reject protocol-relative URLs (//evil.com) and backslash tricks
    if trimmed.starts_with("//") || trimmed.starts_with("/\\") || trimmed.contains("://") {
        return None;
    }
    Some(trimmed)
}

/// Handle OAuth callback from provider (GET for Google/Microsoft).
#[utoipa::path(
    get,
    path = "/auth/social/{provider}/callback",
    params(
        ("provider" = String, Path, description = "Social provider"),
        ("code" = Option<String>, Query, description = "Authorization code"),
        ("state" = String, Query, description = "CSRF state parameter"),
        ("error" = Option<String>, Query, description = "Error code if failed"),
    ),
    responses(
        (status = 302, description = "Redirect to app with tokens or linking page"),
        (status = 400, description = "Invalid callback"),
    ),
    tag = "Social Authentication"
)]
pub async fn callback_get(
    State(state): State<SocialState>,
    Path(provider): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Response, SocialError> {
    let provider_type: ProviderType = provider.parse()?;

    // SECURITY (M3): Validate parameter lengths to prevent abuse.
    // OAuth authorization codes are typically <512 chars; state tokens <2048 chars.
    if query.state.len() > 2048 {
        return Err(SocialError::InvalidCallback {
            reason: "State parameter too long".to_string(),
        });
    }
    if let Some(ref code) = query.code {
        if code.len() > 512 {
            return Err(SocialError::InvalidCallback {
                reason: "Authorization code too long".to_string(),
            });
        }
    }

    // Check for error from provider
    if let Some(error) = &query.error {
        // SECURITY: Use Debug format (?) for provider-controlled fields to prevent log injection
        // via ANSI codes or newline characters. Truncate to prevent log bloat.
        let error_bounded: String = error.chars().take(256).collect();
        let desc_bounded: Option<String> = query
            .error_description
            .as_ref()
            .map(|d| d.chars().take(1024).collect());
        warn!(
            provider = %provider_type,
            error = ?error_bounded,
            description = ?desc_bounded,
            "OAuth provider returned error"
        );
        return Ok(redirect_to_error(&state.frontend_url, &error_bounded));
    }

    let code = query.code.ok_or(SocialError::InvalidCallback {
        reason: "Missing authorization code".to_string(),
    })?;

    process_callback(state, provider_type, &code, &query.state, None).await
}

/// Handle Apple callback (POST with `form_post`).
#[utoipa::path(
    post,
    path = "/auth/social/apple/callback",
    request_body = AppleCallbackForm,
    responses(
        (status = 302, description = "Redirect to app with tokens or linking page"),
        (status = 400, description = "Invalid callback"),
    ),
    tag = "Social Authentication"
)]
pub async fn callback_apple_post(
    State(state): State<SocialState>,
    Form(form): Form<AppleCallbackForm>,
) -> Result<Response, SocialError> {
    // SECURITY (M3): Validate parameter lengths (same limits as GET callback)
    if form.state.len() > 2048 {
        return Err(SocialError::InvalidCallback {
            reason: "State parameter too long".to_string(),
        });
    }
    if let Some(ref code) = form.code {
        if code.len() > 512 {
            return Err(SocialError::InvalidCallback {
                reason: "Authorization code too long".to_string(),
            });
        }
    }

    // Check for error — sanitize before logging (same as GET callback)
    if let Some(error) = &form.error {
        let error_bounded: String = error.chars().take(256).collect();
        warn!(error = ?error_bounded, "Apple Sign In returned error");
        return Ok(redirect_to_error(&state.frontend_url, &error_bounded));
    }

    let code = form.code.ok_or(SocialError::InvalidCallback {
        reason: "Missing authorization code".to_string(),
    })?;

    // Parse user info from first login (Apple only provides this once)
    let apple_user = form
        .user
        .as_ref()
        .and_then(|u| serde_json::from_str::<AppleUserInfo>(u).ok());

    process_callback(state, ProviderType::Apple, &code, &form.state, apple_user).await
}

/// Process the OAuth callback and handle user creation/login.
async fn process_callback(
    state: SocialState,
    provider_type: ProviderType,
    code: &str,
    state_token: &str,
    apple_user: Option<AppleUserInfo>,
) -> Result<Response, SocialError> {
    // Validate state
    let claims = state.oauth_service.validate_state(state_token)?;

    // Verify provider matches
    if claims.provider != provider_type.to_string() {
        return Err(SocialError::InvalidState {
            reason: "Provider mismatch".to_string(),
        });
    }

    let tenant_id = claims.tenant_id;

    info!(
        tenant_id = %tenant_id,
        provider = %provider_type,
        "Processing social login callback"
    );

    // Get provider configuration
    let config = state
        .tenant_provider_service
        .get_enabled_provider(tenant_id, provider_type)
        .await?
        .ok_or(SocialError::ProviderUnavailable {
            provider: provider_type,
        })?;

    // Extract values needed for ID token verification before config is consumed
    let client_id_for_verify = config.client_id.clone();
    let azure_tenant_for_verify = config
        .additional_config
        .as_ref()
        .and_then(|c| c.get("azure_tenant"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Build redirect URI
    let redirect_uri = format!(
        "{}/api/v1/auth/social/{}/callback",
        state.base_url, provider_type
    );

    // Exchange code for tokens and get user info
    let (tokens, mut user_info) = match provider_type {
        ProviderType::Google => {
            let p = ProviderFactory::google(config.client_id, config.client_secret);
            let tokens = p
                .exchange_code(code, &claims.pkce_verifier, &redirect_uri)
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
            let p =
                ProviderFactory::microsoft(config.client_id, config.client_secret, azure_tenant)?;
            let tokens = p
                .exchange_code(code, &claims.pkce_verifier, &redirect_uri)
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

            let p = ProviderFactory::apple(config.client_id, team_id, key_id, private_key)?;
            let tokens = p
                .exchange_code(code, &claims.pkce_verifier, &redirect_uri)
                .await?;
            let mut user_info = p
                .fetch_user_info(&tokens.access_token, tokens.id_token.as_deref())
                .await?;

            // Merge Apple user info from form (first login only)
            if let Some(apple_user) = apple_user {
                if let Some(name) = apple_user.name {
                    user_info.given_name = name.first_name;
                    user_info.family_name = name.last_name;
                    if user_info.name.is_none() {
                        user_info.name = Some(
                            format!(
                                "{} {}",
                                user_info.given_name.as_deref().unwrap_or(""),
                                user_info.family_name.as_deref().unwrap_or("")
                            )
                            .trim()
                            .to_string(),
                        );
                    }
                }
            }

            (tokens, user_info)
        }
        ProviderType::Github => {
            let p = ProviderFactory::github(config.client_id, config.client_secret);
            let tokens = p
                .exchange_code(code, &claims.pkce_verifier, &redirect_uri)
                .await?;
            let user_info = p
                .fetch_user_info(&tokens.access_token, tokens.id_token.as_deref())
                .await?;
            (tokens, user_info)
        }
    };

    // Defense-in-depth: Verify ID token signature for OIDC providers.
    // GitHub has no ID token. All OIDC providers (Google, Microsoft, Apple) are verified.
    if let Some(ref id_token) = tokens.id_token {
        let verify_params: Option<(String, String)> = match provider_type {
            ProviderType::Google => Some((
                "https://www.googleapis.com/oauth2/v3/certs".to_string(),
                "https://accounts.google.com".to_string(),
            )),
            ProviderType::Microsoft => {
                let t = azure_tenant_for_verify.as_deref().unwrap_or("common");
                Some((
                    format!("https://login.microsoftonline.com/{t}/discovery/v2.0/keys"),
                    format!("https://login.microsoftonline.com/{t}/v2.0"),
                ))
            }
            ProviderType::Apple => Some((
                "https://appleid.apple.com/auth/keys".to_string(),
                "https://appleid.apple.com".to_string(),
            )),
            _ => None,
        };

        if let Some((jwks_uri, issuer)) = verify_params {
            match state
                .id_token_verifier
                .verify(id_token, &jwks_uri, &issuer, &client_id_for_verify)
                .await
            {
                Ok(verified_claims) => {
                    // Cross-check: verified sub must match userinfo sub
                    if verified_claims.sub != user_info.provider_user_id {
                        warn!(
                            provider = %provider_type,
                            id_token_sub = %verified_claims.sub,
                            userinfo_sub = %user_info.provider_user_id,
                            "ID token sub mismatch — possible token substitution"
                        );
                        return Err(SocialError::IdTokenVerificationFailed {
                            provider: provider_type,
                            reason: "Subject mismatch between ID token and userinfo".to_string(),
                        });
                    }

                    // OIDC nonce validation: verify the nonce in the ID token matches what we sent
                    if let Some(ref expected_nonce) = claims.oidc_nonce {
                        if verified_claims.nonce.as_deref() != Some(expected_nonce.as_str()) {
                            warn!(
                                provider = %provider_type,
                                "OIDC nonce mismatch — possible replay attack"
                            );
                            return Err(SocialError::NonceMismatch {
                                provider: provider_type,
                            });
                        }
                    }

                    // Propagate email_verified from JWKS-verified ID token.
                    // The ID token is signed by the provider's private key, making
                    // it more authoritative than the userinfo endpoint's default.
                    // Only upgrade false→true (never downgrade true→false).
                    if verified_claims.email_verified == Some(true) {
                        user_info.email_verified = Some(true);
                    }

                    info!(provider = %provider_type, "ID token verified successfully");
                }
                Err(SocialError::JwksFetchFailed { provider, reason }) => {
                    warn!(
                        provider = %provider,
                        reason = %reason,
                        "JWKS fetch failed, continuing without ID token verification"
                    );
                    // Defense-in-depth: don't block login for infrastructure issues
                }
                Err(e) => return Err(e),
            }
        }
    }

    info!(
        provider = %provider_type,
        provider_user_id = %user_info.provider_user_id,
        "Retrieved user info from provider"
    );

    // Check if this is an account linking flow (user_id in state)
    if let Some(user_id) = claims.user_id {
        // Linking to existing user
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
            "Linked social account to existing user"
        );

        // Redirect back to settings with success (sanitized to prevent open redirect)
        let safe_path = claims
            .redirect_after
            .as_deref()
            .and_then(sanitize_redirect_after)
            .unwrap_or("/settings");
        let redirect_url = format!("{}{safe_path}", state.frontend_url);
        return Ok(
            Redirect::temporary(&format!("{redirect_url}?linked={provider_type}")).into_response(),
        );
    }

    // Check connection status
    match state
        .connection_service
        .check_connection(tenant_id, provider_type, &user_info)
        .await?
    {
        ConnectionResult::Existing {
            connection_id,
            user_id,
        } => {
            // SECURITY: Verify user account is active before issuing tokens.
            // Without this, suspended/deactivated users could bypass access control
            // by authenticating via social login (the suspension_check_middleware only
            // runs on requests that already have a JWT, not on initial token issuance).
            let user =
                xavyo_db::models::User::find_by_id_in_tenant(&state.pool, tenant_id, user_id)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to look up user for social login");
                        SocialError::InternalError {
                            message: "User lookup failed".to_string(),
                        }
                    })?
                    .ok_or_else(|| SocialError::InternalError {
                        message: "User not found for existing connection".to_string(),
                    })?;

            social_login_allowed(user.is_active, user.is_locked())?;

            // Existing user - update tokens and log in
            state
                .connection_service
                .update_connection(
                    tenant_id,
                    connection_id,
                    Some(&tokens.access_token),
                    tokens.refresh_token.as_deref(),
                    tokens.expires_in,
                )
                .await?;

            let (display_name, first_name, last_name, avatar_url) =
                social_profile_fields(&user_info);
            let display_name = if user_info.name.is_some()
                || user_info.given_name.is_some()
                || user_info.family_name.is_some()
            {
                Some(display_name)
            } else {
                None
            };
            if let Err(e) = xavyo_db::models::User::update_profile(
                &state.pool,
                tenant_id,
                user_id,
                display_name,
                first_name,
                last_name,
                avatar_url,
            )
            .await
            {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "Failed to sync social profile names; continuing login"
                );
            }

            info!(user_id = %user_id, "Returning user logged in via social");

            // Issue xavyo tokens and redirect
            let jwt_tokens = state.auth_service.issue_tokens(user_id, tenant_id).await?;
            Ok(redirect_with_tokens(
                &state.frontend_url,
                &claims.redirect_after,
                &jwt_tokens,
            ))
        }

        ConnectionResult::EmailCollision {
            existing_user_id,
            email: _,
        } => {
            // Security: Only allow email-based linking if the provider has
            // verified the email. An unverified email from a provider could
            // be attacker-controlled, enabling account takeover via email
            // collision.
            if user_info.email_verified != Some(true) {
                warn!(
                    provider = %provider_type,
                    "Email collision with unverified email - creating new account without email to prevent takeover"
                );

                let (display_name, first_name, last_name, avatar_url) =
                    social_profile_fields(&user_info);
                // Create new user WITHOUT the unverified email
                let user_id = state
                    .auth_service
                    .create_social_user(
                        tenant_id,
                        None, // Do not use unverified email
                        display_name.as_str(),
                        false,
                        first_name.as_deref(),
                        last_name.as_deref(),
                        avatar_url.as_deref(),
                    )
                    .await?;

                // Create social connection (still stores the unverified email in the connection record)
                let connection_id = state
                    .connection_service
                    .create_connection(
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
                    "Created new user via social login (email collision with unverified email)"
                );

                let jwt_tokens = state.auth_service.issue_tokens(user_id, tenant_id).await?;
                return Ok(redirect_with_tokens(
                    &state.frontend_url,
                    &claims.redirect_after,
                    &jwt_tokens,
                ));
            }

            // Email exists and is verified - redirect to linking page
            // M2: Don't include email in URL to prevent email enumeration
            info!(
                existing_user_id = %existing_user_id,
                provider = %provider_type,
                "Email collision detected with verified email, prompting for account linking"
            );

            let redirect_url = format!(
                "{}/link-account?provider={}",
                state.frontend_url, provider_type,
            );
            Ok(Redirect::temporary(&redirect_url).into_response())
        }

        ConnectionResult::NewUser => {
            // F116: Determine email_verified status
            // Only mark as verified if provider explicitly says so
            let email_verified = user_info.email_verified.unwrap_or(false);

            let (display_name, first_name, last_name, avatar_url) =
                social_profile_fields(&user_info);
            // Create new user with correct email_verified status
            let user_id = state
                .auth_service
                .create_social_user(
                    tenant_id,
                    user_info.email.as_deref(),
                    display_name.as_str(),
                    email_verified,
                    first_name.as_deref(),
                    last_name.as_deref(),
                    avatar_url.as_deref(),
                )
                .await?;

            // Create social connection
            let connection_id = state
                .connection_service
                .create_connection(
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
                "Created new user via social login"
            );

            // Issue xavyo tokens and redirect
            let jwt_tokens = state.auth_service.issue_tokens(user_id, tenant_id).await?;
            Ok(redirect_with_tokens(
                &state.frontend_url,
                &claims.redirect_after,
                &jwt_tokens,
            ))
        }
    }
}

/// Redirect to frontend with error.
///
/// The error string is sanitized: only alphanumeric, underscore, and space
/// characters are allowed, and it is truncated to 100 characters to prevent
/// injection of arbitrary content from provider error responses.
fn redirect_to_error(frontend_url: &str, error: &str) -> Response {
    let sanitized: String = error
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == ' ')
        .take(100)
        .collect();
    let url = format!(
        "{}/login?error={}",
        frontend_url,
        urlencoding::encode(&sanitized)
    );
    Redirect::temporary(&url).into_response()
}

/// Redirect to frontend with tokens.
///
/// Uses URL fragment (#) instead of query params (?) for security:
/// - Fragments are not sent to server in HTTP requests
/// - Fragments are not included in Referrer headers
/// - Fragments are not logged in server access logs
fn redirect_with_tokens(
    frontend_url: &str,
    redirect_after: &Option<String>,
    tokens: &JwtTokens,
) -> Response {
    let safe_path = redirect_after
        .as_deref()
        .and_then(sanitize_redirect_after)
        .unwrap_or("/");
    let base = format!("{frontend_url}{safe_path}");

    // Use fragment (#) instead of query (?) for token security
    let url = format!(
        "{}#access_token={}&refresh_token={}&token_type=Bearer&expires_in={}",
        base,
        urlencoding::encode(&tokens.access_token),
        urlencoding::encode(&tokens.refresh_token),
        tokens.expires_in
    );
    Redirect::temporary(&url).into_response()
}

/// JWT tokens from auth service.
pub struct JwtTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

// R9: Custom Debug to prevent token leakage in logs
impl std::fmt::Debug for JwtTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtTokens")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Inactive or locked accounts must not receive JWTs from social login.
pub fn social_login_allowed(is_active: bool, is_locked: bool) -> Result<(), SocialError> {
    if !is_active {
        tracing::warn!("Rejected social login for deactivated user");
        return Err(SocialError::AccountInactive);
    }
    if is_locked {
        tracing::warn!("Rejected social login for locked user");
        return Err(SocialError::AccountLocked);
    }
    Ok(())
}

/// Email lookup failures or a missing user must refuse social JWT issuance.
pub fn social_email_from_lookup<E: std::fmt::Display>(
    result: Result<Option<String>, E>,
) -> Result<String, SocialError> {
    match result {
        Ok(Some(email)) => Ok(email),
        Ok(None) => Err(SocialError::InternalError {
            message: "User email not found".to_string(),
        }),
        Err(e) => {
            tracing::error!(error = %e, "Failed to fetch user email during social login");
            Err(SocialError::InternalError {
                message: "Failed to fetch user email".to_string(),
            })
        }
    }
}

/// Role lookup failures must refuse social token issuance, not mint `["user"]`.
pub fn social_roles_from_lookup<E: std::fmt::Display>(
    result: Result<Vec<String>, E>,
) -> Result<Vec<String>, SocialError> {
    result.map_err(|e| {
        tracing::error!(error = %e, "Failed to fetch user roles during social login");
        SocialError::InternalError {
            message: "Failed to fetch user roles".to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn social_login_allows_active_unlocked() {
        assert!(social_login_allowed(true, false).is_ok());
    }

    #[test]
    fn social_login_refuses_inactive() {
        assert!(matches!(
            social_login_allowed(false, false),
            Err(SocialError::AccountInactive)
        ));
    }

    #[test]
    fn social_login_refuses_locked() {
        assert!(matches!(
            social_login_allowed(true, true),
            Err(SocialError::AccountLocked)
        ));
    }

    #[test]
    fn social_roles_from_lookup_does_not_default_to_user() {
        assert_eq!(
            social_roles_from_lookup(Ok::<Vec<String>, &str>(vec!["admin".into()])).unwrap(),
            vec!["admin".to_string()]
        );
        let err = social_roles_from_lookup(Err("db"));
        assert!(
            matches!(err, Err(SocialError::InternalError { ref message }) if message == "Failed to fetch user roles"),
            "got {err:?}"
        );
    }

    #[test]
    fn social_email_from_lookup_does_not_fail_open() {
        assert_eq!(
            social_email_from_lookup(Ok::<_, &str>(Some("a@b.c".into()))).unwrap(),
            "a@b.c"
        );
        assert!(matches!(
            social_email_from_lookup(Ok::<_, &str>(None)),
            Err(SocialError::InternalError { ref message }) if message == "User email not found"
        ));
        assert!(matches!(
            social_email_from_lookup(Err("db")),
            Err(SocialError::InternalError { ref message }) if message == "Failed to fetch user email"
        ));
    }

    #[test]
    fn social_callback_checks_lockout_before_tokens() {
        let src = include_str!("callback.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("social_login_allowed(user.is_active, user.is_locked())"),
            "existing social logins must refuse locked accounts"
        );
    }

    fn sample_info() -> SocialUserInfo {
        SocialUserInfo {
            provider_user_id: "gid-1".to_string(),
            email: Some("ada@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Ada Lovelace".to_string()),
            given_name: Some("Ada".to_string()),
            family_name: Some("Lovelace".to_string()),
            picture: Some("https://example.com/ada.png".to_string()),
            is_private_email: false,
            raw_claims: serde_json::json!({}),
        }
    }

    #[test]
    fn social_profile_fields_fills_advertised_names() {
        let (display, first, last, avatar) = social_profile_fields(&sample_info());
        assert_eq!(display, "Ada Lovelace");
        assert_eq!(first.as_deref(), Some("Ada"));
        assert_eq!(last.as_deref(), Some("Lovelace"));
        assert_eq!(avatar.as_deref(), Some("https://example.com/ada.png"));
    }

    #[test]
    fn social_profile_fields_joins_given_family_when_name_absent() {
        let mut info = sample_info();
        info.name = None;
        let (display, first, last, _) = social_profile_fields(&info);
        assert_eq!(display, "Ada Lovelace");
        assert_eq!(first.as_deref(), Some("Ada"));
        assert_eq!(last.as_deref(), Some("Lovelace"));
    }

    #[test]
    fn social_callback_create_and_sync_persist_profile_fields() {
        let src = include_str!("callback.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("social_profile_fields(&user_info)"),
            "social JIT must map given/family/picture onto the user"
        );
        assert!(
            production.contains("User::update_profile("),
            "existing social login must sync first_name/last_name/avatar"
        );
        assert!(
            production.contains("first_name.as_deref()")
                && production.contains("last_name.as_deref()")
                && production.contains("avatar_url.as_deref()"),
            "create_social_user must receive advertised profile fields"
        );
    }
}
