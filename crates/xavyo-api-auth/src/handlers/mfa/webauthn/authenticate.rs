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
use xavyo_core::UserId;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

use crate::{error::ApiAuthError, router::AuthState};

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

/// Response after successful `WebAuthn` authentication.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthenticationSuccessResponse {
    /// Success message.
    pub message: String,
    /// The credential ID that was used.
    pub credential_id: String,
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
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
) -> Result<(StatusCode, Json<AuthenticationOptionsResponse>), ApiAuthError> {
    // Start authentication ceremony
    let options = state
        .webauthn_service
        .start_authentication(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            ip_address,
            user_agent,
        )
        .await?;

    info!(
        user_id = %user_id.as_uuid(),
        "WebAuthn authentication started"
    );

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
        (status = 200, description = "Authentication successful", body = AuthenticationSuccessResponse),
        (status = 400, description = "Invalid authenticator response or verification failed"),
        (status = 401, description = "Invalid or expired partial token"),
        (status = 404, description = "Credential not found or challenge expired"),
        (status = 429, description = "Too many failed attempts"),
    ),
    tag = "WebAuthn MFA"
)]
pub async fn finish_webauthn_authentication(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    publisher: Option<Extension<EventPublisher>>,
    Json(request): Json<FinishAuthenticationRequest>,
) -> Result<(StatusCode, Json<AuthenticationSuccessResponse>), ApiAuthError> {
    // Finish authentication ceremony
    let credential_id = state
        .webauthn_service
        .finish_authentication(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            &request.credential,
            ip_address,
            user_agent,
        )
        .await?;

    info!(
        user_id = %user_id.as_uuid(),
        credential_id = %credential_id,
        "WebAuthn authentication successful"
    );

    // F085: Publish auth.mfa.verified webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "auth.mfa.verified".to_string(),
            tenant_id: *tenant_id.as_uuid(),
            actor_id: Some(*user_id.as_uuid()),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": user_id.as_uuid(),
                "factor_type": "webauthn",
            }),
        });
    }

    Ok((
        StatusCode::OK,
        Json(AuthenticationSuccessResponse {
            message: "Authentication successful".to_string(),
            credential_id: credential_id.to_string(),
        }),
    ))
}
