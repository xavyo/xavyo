//! `WebAuthn` credential management handlers.
//!
//! Endpoints for listing, renaming, and deleting `WebAuthn` credentials.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_core::UserId;
use xavyo_db::CredentialInfo;

use crate::{error::ApiAuthError, router::AuthState};

/// Response containing a list of credentials.
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialListResponse {
    /// List of registered `WebAuthn` credentials.
    pub credentials: Vec<CredentialInfo>,
    /// Total count of credentials.
    pub count: usize,
}

/// Request to update a credential (rename).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCredentialRequest {
    /// New name for the credential (1-100 characters).
    #[schema(example = "Office YubiKey")]
    pub name: String,
}

/// Response after credential update.
#[derive(Debug, Serialize, ToSchema)]
pub struct UpdateCredentialResponse {
    /// The updated credential information.
    pub credential: CredentialInfo,
    /// Success message.
    pub message: String,
}

/// GET /auth/mfa/webauthn/credentials
///
/// List all `WebAuthn` credentials for the authenticated user.
#[utoipa::path(
    get,
    path = "/auth/mfa/webauthn/credentials",
    responses(
        (status = 200, description = "List of credentials", body = CredentialListResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "WebAuthn MFA"
)]
pub async fn list_webauthn_credentials(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
) -> Result<Json<CredentialListResponse>, ApiAuthError> {
    let credentials = state
        .webauthn_service
        .list_credentials(*user_id.as_uuid(), *tenant_id.as_uuid())
        .await?;

    let count = credentials.len();

    Ok(Json(CredentialListResponse { credentials, count }))
}

/// PATCH /`auth/mfa/webauthn/credentials/{credential_id`}
///
/// Update (rename) a `WebAuthn` credential.
#[utoipa::path(
    patch,
    path = "/auth/mfa/webauthn/credentials/{credential_id}",
    params(
        ("credential_id" = Uuid, Path, description = "Credential ID to update")
    ),
    request_body = UpdateCredentialRequest,
    responses(
        (status = 200, description = "Credential updated", body = UpdateCredentialResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Credential not found"),
    ),
    tag = "WebAuthn MFA"
)]
pub async fn update_webauthn_credential(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    Path(credential_id): Path<Uuid>,
    Json(request): Json<UpdateCredentialRequest>,
) -> Result<Json<UpdateCredentialResponse>, ApiAuthError> {
    // Validate name length
    if request.name.is_empty() || request.name.len() > 100 {
        return Err(ApiAuthError::Validation(
            "Name must be between 1 and 100 characters".to_string(),
        ));
    }

    let credential = state
        .webauthn_service
        .rename_credential(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            credential_id,
            &request.name,
            ip_address,
            user_agent,
        )
        .await?;

    info!(
        user_id = %user_id.as_uuid(),
        credential_id = %credential_id,
        new_name = %request.name,
        "WebAuthn credential renamed"
    );

    Ok(Json(UpdateCredentialResponse {
        credential,
        message: "Credential updated successfully".to_string(),
    }))
}

/// DELETE /`auth/mfa/webauthn/credentials/{credential_id`}
///
/// Delete a `WebAuthn` credential.
#[utoipa::path(
    delete,
    path = "/auth/mfa/webauthn/credentials/{credential_id}",
    params(
        ("credential_id" = Uuid, Path, description = "Credential ID to delete")
    ),
    responses(
        (status = 204, description = "Credential deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Credential not found"),
        (status = 409, description = "Cannot delete last MFA method when tenant requires MFA"),
    ),
    tag = "WebAuthn MFA"
)]
pub async fn delete_webauthn_credential(
    State(state): State<AuthState>,
    Extension(user_id): Extension<UserId>,
    Extension(tenant_id): Extension<xavyo_core::TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, ApiAuthError> {
    state
        .webauthn_service
        .delete_credential(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            credential_id,
            ip_address,
            user_agent,
        )
        .await?;

    info!(
        user_id = %user_id.as_uuid(),
        credential_id = %credential_id,
        "WebAuthn credential deleted"
    );

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_credential_request() {
        let json = r#"{"name": "My New Key Name"}"#;
        let request: UpdateCredentialRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.name, "My New Key Name");
    }
}
