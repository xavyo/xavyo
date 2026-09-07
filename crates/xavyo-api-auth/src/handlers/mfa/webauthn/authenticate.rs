//! `WebAuthn` authentication handlers.
//!
//! Handles the two-step `WebAuthn` authentication process for MFA.

use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};
use xavyo_auth::JwtClaims;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

use crate::{error::ApiAuthError, models::TokenResponse, router::AuthState, services::AuthContext};

/// Response containing `WebAuthn` authentication options.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthenticationOptionsResponse {
    /// The authentication options to pass to `navigator.credentials.get()`.
    /// This is the `WebAuthn` `PublicKeyCredentialRequestOptions` structure.
    #[serde(flatten)]
    #[schema(value_type = Object)]
    pub options: RequestChallengeResponse,
}

/// Request to finish `WebAuthn` authentication.
/// Contains the authenticator's response from `navigator.credentials.get()`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct FinishAuthenticationRequest {
    /// The credential assertion response from the authenticator.
    /// This is the `WebAuthn` `PublicKeyCredential` structure returned by `navigator.credentials.get()`.
    #[serde(flatten)]
    #[schema(value_type = Object)]
    pub credential: PublicKeyCredential,
}

/// POST /auth/mfa/webauthn/authenticate/start
///
/// Start `WebAuthn` authentication for MFA.
/// Requires a valid partial token from the login flow.
/// Returns challenge and allowed credentials for `navigator.credentials.get()`.
#[utoipa::path(
    post,
    path = "/auth/mfa/webauthn/authenticate/start",
    responses(
        (status = 200, description = "Authentication options returned", body = AuthenticationOptionsResponse),
        (status = 400, description = "No WebAuthn credentials registered for this user"),
        (status = 401, description = "Invalid or expired partial token"),
        (status = 429, description = "Too many failed attempts"),
    ),
    tag = "WebAuthn MFA"
)]
pub async fn start_webauthn_authentication(
    State(state): State<AuthState>,
    Extension(claims): Extension<JwtClaims>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
) -> Result<(StatusCode, Json<AuthenticationOptionsResponse>), ApiAuthError> {
    // Identity comes from the partial (mfa_verification) token. The UserId/TenantId
    // request extensions are not populated for partial tokens, so read the claims
    // directly — mirroring verify_totp.
    if claims.purpose.as_deref() != Some("mfa_verification") {
        return Err(ApiAuthError::PartialTokenInvalid);
    }
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::PartialTokenInvalid)?;
    let tenant_id = claims.tid.ok_or(ApiAuthError::PartialTokenInvalid)?;

    // Start authentication ceremony
    let options = state
        .webauthn_service
        .start_authentication(user_id, tenant_id, ip_address, user_agent)
        .await?;

    info!(user_id = %user_id, "WebAuthn authentication started");

    Ok((
        StatusCode::OK,
        Json(AuthenticationOptionsResponse { options }),
    ))
}

/// POST /auth/mfa/webauthn/authenticate/finish
///
/// Complete `WebAuthn` authentication for MFA.
/// Verifies the authenticator assertion and returns full tokens on success.
#[utoipa::path(
    post,
    path = "/auth/mfa/webauthn/authenticate/finish",
    request_body = FinishAuthenticationRequest,
    responses(
        (status = 200, description = "Authentication successful, tokens issued", body = TokenResponse),
        (status = 400, description = "Invalid authenticator response or verification failed"),
        (status = 401, description = "Invalid or expired partial token"),
        (status = 404, description = "Credential not found or challenge expired"),
        (status = 429, description = "Too many failed attempts"),
    ),
    tag = "WebAuthn MFA"
)]
pub async fn finish_webauthn_authentication(
    State(state): State<AuthState>,
    Extension(claims): Extension<JwtClaims>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    publisher: Option<Extension<EventPublisher>>,
    Json(request): Json<FinishAuthenticationRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), ApiAuthError> {
    // This endpoint completes the login MFA challenge, so it must run against a
    // partial (mfa_verification) token — mirroring the TOTP/recovery verify paths.
    // Identity comes from the token claims (UserId/TenantId extensions are not
    // populated for partial tokens).
    if claims.purpose.as_deref() != Some("mfa_verification") {
        return Err(ApiAuthError::PartialTokenInvalid);
    }

    let uid = Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::PartialTokenInvalid)?;
    let tid = claims.tid.ok_or(ApiAuthError::PartialTokenInvalid)?;

    // Finish the authenticator assertion ceremony.
    let credential_id = state
        .webauthn_service
        .finish_authentication(
            uid,
            tid,
            &request.credential,
            ip_address,
            user_agent.clone(),
        )
        .await?;

    // Issue a full session (mirrors verify_totp): password + WebAuthn = MFA.
    // SECURITY: fail closed if the role fetch fails rather than issuing a
    // downgraded token.
    let user = xavyo_db::User::find_by_id_in_tenant(&state.pool, tid, uid)
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::InvalidCredentials)?;
    let roles = xavyo_db::UserRole::get_user_roles(&state.pool, uid, tid)
        .await
        .map_err(|e| {
            tracing::error!(user_id = %uid, error = %e, "Failed to fetch user roles during WebAuthn MFA verification");
            ApiAuthError::Internal("Failed to fetch user roles".to_string())
        })?;
    let tokens = state
        .token_service
        .create_tokens(
            user.user_id(),
            user.tenant_id(),
            roles,
            Some(user.email.clone()),
            Some(AuthContext::webauthn()),
            user_agent,
            ip_address,
        )
        .await?;

    info!(
        user_id = %uid,
        credential_id = %credential_id,
        "WebAuthn MFA verification successful, tokens issued"
    );

    // F085: Publish auth.mfa.verified webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "auth.mfa.verified".to_string(),
            tenant_id: tid,
            actor_id: Some(uid),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": uid,
                "factor_type": "webauthn",
            }),
        });
    }

    Ok((
        StatusCode::OK,
        Json(TokenResponse::new(tokens.0, tokens.1, tokens.2)),
    ))
}
