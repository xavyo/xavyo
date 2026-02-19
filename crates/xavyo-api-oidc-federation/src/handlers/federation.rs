//! Federation handlers for user authentication flow.

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    Extension, Json,
};
use tracing::instrument;
use xavyo_core::TenantId;

use crate::error::{FederationError, FederationResult};
use crate::models::{
    AuthorizeParams, CallbackParams, DiscoverRequest, DiscoverResponse, FederationTokenResponse,
};
use crate::router::FederationState;
use crate::services::InitiateAuthInput;

/// Discover authentication realm for an email address.
///
/// POST /auth/federation/discover
#[utoipa::path(
    post,
    path = "/auth/federation/discover",
    request_body = DiscoverRequest,
    responses(
        (status = 200, description = "Realm discovery result", body = DiscoverResponse),
        (status = 400, description = "Invalid request"),
    ),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn discover_realm(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Json(req): Json<DiscoverRequest>,
) -> FederationResult<Json<DiscoverResponse>> {
    let tenant_id = *tid.as_uuid();

    // M-2: Validate email length to prevent abuse
    if req.email.len() > 254 {
        return Err(FederationError::InvalidEmail(
            "Email address too long".to_string(),
        ));
    }

    tracing::debug!(
        tenant_id = %tenant_id,
        "Discovering authentication realm"
    );

    // Use HRD service to find IdP for email domain
    let result = state.hrd.discover(tenant_id, &req.email).await?;

    let response = match result {
        Some(hrd_result) => DiscoverResponse {
            authentication_method: crate::models::AuthenticationMethod::Federated,
            identity_provider: Some(crate::models::IdentityProviderSummary {
                id: hrd_result.idp_id,
                name: hrd_result.idp_name,
                provider_type: "oidc".to_string(), // Default for OIDC federation
            }),
        },
        None => DiscoverResponse {
            authentication_method: crate::models::AuthenticationMethod::Standard,
            identity_provider: None,
        },
    };

    Ok(Json(response))
}

/// Initiate authorization flow with external `IdP`.
///
/// GET /auth/federation/authorize
#[utoipa::path(
    get,
    path = "/auth/federation/authorize",
    params(AuthorizeParams),
    responses(
        (status = 307, description = "Redirect to external IdP authorization endpoint"),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Identity provider not found"),
    ),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn authorize(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Query(params): Query<AuthorizeParams>,
) -> FederationResult<impl IntoResponse> {
    let tenant_id = *tid.as_uuid();

    tracing::info!(
        tenant_id = %tenant_id,
        idp_id = %params.idp_id,
        "Initiating federated authorization"
    );

    let auth_url = state
        .auth_flow
        .initiate(InitiateAuthInput {
            tenant_id,
            idp_id: params.idp_id,
            redirect_uri: params.redirect_uri,
            email: None, // Could be passed as login_hint
        })
        .await?;

    // Audit log
    tracing::info!(
        tenant_id = %tenant_id,
        idp_id = %params.idp_id,
        session_id = %auth_url.session_id,
        "Federation auth initiated"
    );

    Ok(Redirect::temporary(&auth_url.url))
}

/// Handle callback from external `IdP`.
///
/// GET /auth/federation/callback
#[utoipa::path(
    get,
    path = "/auth/federation/callback",
    params(CallbackParams),
    responses(
        (status = 200, description = "Token response after successful federation", body = FederationTokenResponse),
        (status = 307, description = "Redirect with access token fragment"),
        (status = 400, description = "Invalid callback or IdP error"),
    ),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn callback(
    State(state): State<FederationState>,
    Query(params): Query<CallbackParams>,
) -> FederationResult<impl IntoResponse> {
    // SECURITY: Validate callback parameter lengths to prevent DoS/abuse.
    // State is a CSRF token (~64 chars), code is an authorization code (~128 chars).
    if params.state.len() > 512 {
        return Err(FederationError::InvalidCallback(
            "State parameter too long".to_string(),
        ));
    }
    if let Some(ref code) = params.code {
        if code.len() > 2048 {
            return Err(FederationError::InvalidCallback(
                "Authorization code too long".to_string(),
            ));
        }
    }

    // Check for error response from IdP
    if let Some(error) = &params.error {
        // SECURITY: Bound error/error_description lengths to prevent log injection/bloat.
        let error_bounded: String = error.chars().take(256).collect();
        let description = params
            .error_description
            .as_deref()
            .unwrap_or("Unknown error");
        let description_bounded: String = description.chars().take(1024).collect();
        tracing::warn!(
            error = %error_bounded,
            description = %description_bounded,
            "IdP returned error"
        );
        return Err(FederationError::IdpError {
            error: error_bounded,
            description: description_bounded,
        });
    }

    // Validate code is present
    let code = params.code.as_ref().ok_or_else(|| {
        FederationError::InvalidCallback("Missing authorization code".to_string())
    })?;

    // Exchange code for tokens
    let token_result = state.auth_flow.callback(&params.state, code).await?;

    // Claims already verified (signature, expiry, nonce, audience) by auth_flow.callback()
    // SECURITY: Do not log email (PII) at INFO level
    tracing::info!(
        tenant_id = %token_result.session.tenant_id,
        idp_id = %token_result.session.identity_provider_id,
        subject = %token_result.claims.sub,
        "Token exchange and verification successful"
    );

    // Provision/sync user
    let (user, _link) = state
        .provisioning
        .provision_or_sync(
            token_result.session.tenant_id,
            token_result.session.identity_provider_id,
            &token_result.claims,
        )
        .await?;

    // Generate Xavyo JWT for the user
    let roles = xavyo_db::UserRole::get_user_roles(&state.pool, user.id)
        .await
        .map_err(|e| {
            tracing::error!(user_id = %user.id, error = %e, "Failed to fetch user roles");
            FederationError::Internal("Failed to fetch user roles".to_string())
        })?;
    let xavyo_tokens = state
        .token_issuer
        .issue_tokens(user.id, token_result.session.tenant_id, roles, None)
        .await?;

    // Audit log
    tracing::info!(
        tenant_id = %token_result.session.tenant_id,
        user_id = %user.id,
        idp_id = %token_result.session.identity_provider_id,
        "Federation login successful"
    );

    // Get the redirect URI from session
    let redirect_uri = token_result.session.redirect_uri;

    // Build response based on redirect_uri
    // If the redirect_uri contains a path (e.g., callback page), redirect with token
    // Otherwise return JSON response
    if redirect_uri.starts_with("http") {
        // H2: Validate redirect URI (defense in depth against open redirects)
        // Use proper URL parsing to prevent prefix bypass (e.g., example.com.evil.com)
        let redirect_safe = if let (Ok(redirect_url), Ok(base_url)) = (
            url::Url::parse(&redirect_uri),
            url::Url::parse(state.auth_flow.callback_base_url()),
        ) {
            redirect_url.scheme() == base_url.scheme()
                && redirect_url.host_str() == base_url.host_str()
                && redirect_url.port() == base_url.port()
        } else {
            false
        };
        if !redirect_safe {
            tracing::warn!(
                redirect_uri = %redirect_uri,
                "Blocked potential open redirect in federation callback"
            );
            return Ok(CallbackResponse::Json(Json(FederationTokenResponse {
                access_token: xavyo_tokens.access_token,
                token_type: "Bearer".to_string(),
                expires_in: xavyo_tokens.expires_in,
                refresh_token: xavyo_tokens.refresh_token,
            })));
        }
        // Redirect with token as fragment (safer than query params)
        let redirect_url = format!(
            "{}#access_token={}&token_type=Bearer&expires_in={}",
            redirect_uri, xavyo_tokens.access_token, xavyo_tokens.expires_in
        );
        Ok(CallbackResponse::Redirect(Redirect::temporary(
            &redirect_url,
        )))
    } else {
        Ok(CallbackResponse::Json(Json(FederationTokenResponse {
            access_token: xavyo_tokens.access_token,
            token_type: "Bearer".to_string(),
            expires_in: xavyo_tokens.expires_in,
            refresh_token: xavyo_tokens.refresh_token,
        })))
    }
}

/// Callback response can be either a redirect or JSON.
enum CallbackResponse {
    Redirect(Redirect),
    Json(Json<FederationTokenResponse>),
}

impl IntoResponse for CallbackResponse {
    fn into_response(self) -> axum::response::Response {
        match self {
            CallbackResponse::Redirect(r) => r.into_response(),
            CallbackResponse::Json(j) => j.into_response(),
        }
    }
}

/// Handle logout from federation (optional).
///
/// POST /auth/federation/logout
#[utoipa::path(
    post,
    path = "/auth/federation/logout",
    responses(
        (status = 204, description = "Federation session cleanup completed"),
    ),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn logout(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
) -> FederationResult<impl IntoResponse> {
    let tenant_id = *tid.as_uuid();

    // Clean up any pending sessions for this tenant
    // Note: Actual logout should be handled by the main auth system
    // This is for cleaning up any orphaned federation sessions
    let cleaned = state.auth_flow.cleanup_expired_sessions().await?;

    tracing::info!(
        tenant_id = %tenant_id,
        cleaned_sessions = %cleaned,
        "Federation logout cleanup"
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}
