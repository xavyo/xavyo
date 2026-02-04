//! `WebAuthn` registration handlers.
//!
//! Handles the two-step `WebAuthn` credential registration process.

use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};
use xavyo_core::UserId;
use xavyo_db::CredentialInfo;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

use crate::{error::ApiAuthError, router::AuthState};

/// Request to start `WebAuthn` registration.
#[derive(Debug, Deserialize, ToSchema)]
pub struct StartRegistrationRequest {
    /// Optional friendly name for the credential (e.g., "`MacBook` Touch ID").
    #[schema(example = "MacBook Touch ID")]
    pub name: Option<String>,
}

/// Response containing `WebAuthn` registration options.
#[derive(Debug, Serialize, ToSchema)]
pub struct RegistrationOptionsResponse {
    /// The registration options to pass to `navigator.credentials.create()`.
    /// This is the `WebAuthn` `PublicKeyCredentialCreationOptions` structure.
    #[serde(flatten)]
    #[schema(value_type = Object)]
    pub options: CreationChallengeResponse,
}

/// Request to finish `WebAuthn` registration.
/// Contains the authenticator's response from `navigator.credentials.create()`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct FinishRegistrationRequest {
    /// The credential creation response from the authenticator.
    /// This is the `WebAuthn` `PublicKeyCredential` structure returned by `navigator.credentials.create()`.
    #[serde(flatten)]
    #[schema(value_type = Object)]
    pub credential: RegisterPublicKeyCredential,
}

/// Response after successful credential registration.
#[derive(Debug, Serialize, ToSchema)]
pub struct RegistrationResponse {
    /// The registered credential information.
    pub credential: CredentialInfo,
    /// Success message.
    pub message: String,
}

/// POST /auth/mfa/webauthn/register/start
///
/// Start `WebAuthn` credential registration for the authenticated user.
/// Returns challenge and options for the browser's `navigator.credentials.create()` call.
#[utoipa::path(
    post,
    path = "/auth/mfa/webauthn/register/start",
    request_body = StartRegistrationRequest,
    responses(
        (status = 200, description = "Registration options returned", body = RegistrationOptionsResponse),
        (status = 400, description = "Max credentials reached or WebAuthn disabled"),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "WebAuthn MFA"
)]
pub async fn start_webauthn_registration(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    Json(request): Json<StartRegistrationRequest>,
) -> Result<(StatusCode, Json<RegistrationOptionsResponse>), ApiAuthError> {
    // Get user info for registration (include tenant_id for defense-in-depth)
    let user =
        xavyo_db::User::find_by_id_in_tenant(&state.pool, *tenant_id.as_uuid(), *user_id.as_uuid())
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::InvalidCredentials)?;

    // Start registration ceremony
    let options = state
        .webauthn_service
        .start_registration(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            &user.email,
            user.display_name.as_deref().unwrap_or(&user.email),
            request.name,
            ip_address,
            user_agent,
        )
        .await?;

    info!(
        user_id = %user_id.as_uuid(),
        "WebAuthn registration started"
    );

    Ok((
        StatusCode::OK,
        Json(RegistrationOptionsResponse { options }),
    ))
}

/// POST /auth/mfa/webauthn/register/finish
///
/// Complete `WebAuthn` credential registration.
/// Verifies the authenticator response and stores the credential.
#[utoipa::path(
    post,
    path = "/auth/mfa/webauthn/register/finish",
    request_body = FinishRegistrationRequest,
    responses(
        (status = 201, description = "Credential registered successfully", body = RegistrationResponse),
        (status = 400, description = "Invalid authenticator response or verification failed"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "No pending registration found or challenge expired"),
        (status = 409, description = "Credential already registered"),
    ),
    tag = "WebAuthn MFA"
)]
pub async fn finish_webauthn_registration(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    publisher: Option<Extension<EventPublisher>>,
    Json(request): Json<FinishRegistrationRequest>,
) -> Result<(StatusCode, Json<RegistrationResponse>), ApiAuthError> {
    // Finish registration ceremony
    let credential = state
        .webauthn_service
        .finish_registration(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            &request.credential,
            ip_address,
            user_agent,
        )
        .await?;

    info!(
        user_id = %user_id.as_uuid(),
        credential_id = %credential.id,
        credential_name = %credential.name,
        "WebAuthn credential registered"
    );

    // F085: Publish auth.mfa.enrolled webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "auth.mfa.enrolled".to_string(),
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
        StatusCode::CREATED,
        Json(RegistrationResponse {
            credential,
            message: "Credential registered successfully".to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_registration_request_default_name() {
        let json = r#"{}"#;
        let request: StartRegistrationRequest = serde_json::from_str(json).unwrap();
        assert!(request.name.is_none());
    }

    #[test]
    fn test_start_registration_request_with_name() {
        let json = r#"{"name": "My YubiKey"}"#;
        let request: StartRegistrationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.name, Some("My YubiKey".to_string()));
    }
}
