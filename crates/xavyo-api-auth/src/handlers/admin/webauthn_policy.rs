//! `WebAuthn` policy management handlers.
//!
//! Endpoints for managing tenant `WebAuthn` policy and admin credential management.

use axum::{extract::Path, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::{set_tenant_context, TenantWebAuthnPolicy, UpsertWebAuthnPolicy};

use crate::error::ApiAuthError;
use crate::services::WebAuthnService;

/// Response for `WebAuthn` policy endpoints.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebAuthnPolicyResponse {
    /// The tenant this policy applies to.
    pub tenant_id: Uuid,
    /// Whether `WebAuthn` is enabled for this tenant.
    pub webauthn_enabled: bool,
    /// Whether attestation is required for credential registration.
    pub require_attestation: bool,
    /// User verification requirement (discouraged, preferred, required).
    pub user_verification: String,
    /// Allowed authenticator types (null = all allowed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_authenticator_types: Option<Vec<String>>,
    /// Maximum number of credentials per user.
    pub max_credentials_per_user: i32,
}

impl From<TenantWebAuthnPolicy> for WebAuthnPolicyResponse {
    fn from(policy: TenantWebAuthnPolicy) -> Self {
        Self {
            tenant_id: policy.tenant_id,
            webauthn_enabled: policy.webauthn_enabled,
            require_attestation: policy.require_attestation,
            user_verification: policy.user_verification.clone(),
            allowed_authenticator_types: policy.allowed_authenticator_types.clone(),
            max_credentials_per_user: policy.max_credentials_per_user,
        }
    }
}

/// Request to update `WebAuthn` policy.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWebAuthnPolicyRequest {
    /// Whether `WebAuthn` is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webauthn_enabled: Option<bool>,
    /// Whether attestation is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_attestation: Option<bool>,
    /// User verification requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    /// Allowed authenticator types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_authenticator_types: Option<Vec<String>>,
    /// Maximum credentials per user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_credentials_per_user: Option<i32>,
}

/// GET /admin/tenants/:tenant_id/webauthn-policy
///
/// Get the `WebAuthn` policy for a tenant.
#[utoipa::path(
    get,
    path = "/admin/tenants/{tenant_id}/webauthn-policy",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "WebAuthn policy returned", body = WebAuthnPolicyResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    tag = "Admin - WebAuthn Policy"
)]
pub async fn get_webauthn_policy(
    Extension(pool): Extension<PgPool>,
    Extension(tenant_id): Extension<TenantId>,
    Path(path_tenant_id): Path<Uuid>,
) -> Result<(StatusCode, Json<WebAuthnPolicyResponse>), ApiAuthError> {
    // Verify tenant access (admins can only manage their own tenant unless super_admin)
    if *tenant_id.as_uuid() != path_tenant_id {
        return Err(ApiAuthError::PermissionDenied(
            "Cannot access other tenant's policy".to_string(),
        ));
    }

    let mut conn = pool.acquire().await.map_err(ApiAuthError::Database)?;
    set_tenant_context(&mut *conn, tenant_id)
        .await
        .map_err(ApiAuthError::DatabaseInternal)?;

    // Get WebAuthn policy (creates default if not exists)
    let policy = TenantWebAuthnPolicy::get_or_create(&mut *conn, path_tenant_id)
        .await
        .map_err(ApiAuthError::Database)?;

    Ok((StatusCode::OK, Json(policy.into())))
}

/// PUT /admin/tenants/:tenant_id/webauthn-policy
///
/// Update the `WebAuthn` policy for a tenant.
#[utoipa::path(
    put,
    path = "/admin/tenants/{tenant_id}/webauthn-policy",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID")
    ),
    request_body = UpdateWebAuthnPolicyRequest,
    responses(
        (status = 200, description = "WebAuthn policy updated", body = WebAuthnPolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    tag = "Admin - WebAuthn Policy"
)]
pub async fn update_webauthn_policy(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Extension(tenant_id): Extension<TenantId>,
    Path(path_tenant_id): Path<Uuid>,
    Json(request): Json<UpdateWebAuthnPolicyRequest>,
) -> Result<(StatusCode, Json<WebAuthnPolicyResponse>), ApiAuthError> {
    // Verify tenant access
    if *tenant_id.as_uuid() != path_tenant_id {
        return Err(ApiAuthError::PermissionDenied(
            "Cannot access other tenant's policy".to_string(),
        ));
    }

    // Validate user_verification if provided
    if let Some(ref uv) = request.user_verification {
        let valid_values = ["discouraged", "preferred", "required"];
        if !valid_values.contains(&uv.as_str()) {
            return Err(ApiAuthError::Validation(format!(
                "user_verification must be one of: {}",
                valid_values.join(", ")
            )));
        }
    }

    // Validate max_credentials_per_user if provided
    if let Some(max) = request.max_credentials_per_user {
        if !(1..=100).contains(&max) {
            return Err(ApiAuthError::Validation(
                "max_credentials_per_user must be between 1 and 100".to_string(),
            ));
        }
    }

    let mut conn = pool.acquire().await.map_err(ApiAuthError::Database)?;
    set_tenant_context(&mut *conn, tenant_id)
        .await
        .map_err(ApiAuthError::DatabaseInternal)?;

    // Update WebAuthn policy
    let policy = TenantWebAuthnPolicy::update(
        &mut *conn,
        path_tenant_id,
        UpsertWebAuthnPolicy {
            webauthn_enabled: request.webauthn_enabled,
            require_attestation: request.require_attestation,
            user_verification: request.user_verification,
            allowed_authenticator_types: request.allowed_authenticator_types,
            max_credentials_per_user: request.max_credentials_per_user,
        },
    )
    .await
    .map_err(ApiAuthError::Database)?;

    info!(
        tenant_id = %path_tenant_id,
        webauthn_enabled = %policy.webauthn_enabled,
        updated_by = %claims.sub,
        "WebAuthn policy updated"
    );

    Ok((StatusCode::OK, Json(policy.into())))
}

/// Response containing admin view of user credentials.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminCredentialListResponse {
    /// The user these credentials belong to.
    pub user_id: Uuid,
    /// List of registered `WebAuthn` credentials.
    pub credentials: Vec<AdminCredentialInfo>,
    /// Total count of credentials.
    pub count: usize,
}

/// Admin view of a credential.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminCredentialInfo {
    /// Credential ID.
    pub id: Uuid,
    /// User-friendly name.
    pub name: String,
    /// Authenticator type (platform or cross-platform).
    pub authenticator_type: String,
    /// Whether credential supports backup (passkey sync).
    pub backup_eligible: bool,
    /// Whether credential is currently backed up.
    pub backup_state: bool,
    /// When the credential was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the credential was last used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// GET /`admin/users/:user_id/webauthn/credentials`
///
/// Admin endpoint to list a user's `WebAuthn` credentials.
#[utoipa::path(
    get,
    path = "/admin/users/{user_id}/webauthn/credentials",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Credentials returned", body = AdminCredentialListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "User not found"),
    ),
    tag = "Admin - WebAuthn Credentials"
)]
pub async fn admin_list_user_credentials(
    Extension(webauthn_service): Extension<Arc<WebAuthnService>>,
    Extension(claims): Extension<JwtClaims>,
    Extension(tenant_id): Extension<TenantId>,
    Path(target_user_id): Path<Uuid>,
) -> Result<(StatusCode, Json<AdminCredentialListResponse>), ApiAuthError> {
    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| ApiAuthError::PermissionDenied("Invalid admin user ID".to_string()))?;

    let credentials = webauthn_service
        .admin_list_user_credentials(admin_user_id, target_user_id, *tenant_id.as_uuid())
        .await?;

    let count = credentials.len();
    let admin_credentials: Vec<AdminCredentialInfo> = credentials
        .into_iter()
        .map(|c| AdminCredentialInfo {
            id: c.id,
            name: c.name,
            authenticator_type: c.authenticator_type,
            backup_eligible: c.backup_eligible,
            backup_state: c.backup_state,
            created_at: c.created_at,
            last_used_at: c.last_used_at,
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(AdminCredentialListResponse {
            user_id: target_user_id,
            credentials: admin_credentials,
            count,
        }),
    ))
}

/// DELETE /`admin/users/:user_id/webauthn/credentials/:credential_id`
///
/// Admin endpoint to revoke a user's `WebAuthn` credential.
#[utoipa::path(
    delete,
    path = "/admin/users/{user_id}/webauthn/credentials/{credential_id}",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("credential_id" = Uuid, Path, description = "Credential ID")
    ),
    responses(
        (status = 204, description = "Credential revoked"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "Credential not found"),
    ),
    tag = "Admin - WebAuthn Credentials"
)]
pub async fn admin_revoke_credential(
    Extension(webauthn_service): Extension<Arc<WebAuthnService>>,
    Extension(claims): Extension<JwtClaims>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(ip_address): Extension<Option<IpAddr>>,
    Extension(user_agent): Extension<Option<String>>,
    Path((target_user_id, credential_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiAuthError> {
    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| ApiAuthError::PermissionDenied("Invalid admin user ID".to_string()))?;

    webauthn_service
        .admin_revoke_credential(
            admin_user_id,
            target_user_id,
            credential_id,
            *tenant_id.as_uuid(),
            ip_address,
            user_agent,
        )
        .await?;

    info!(
        admin_user_id = %admin_user_id,
        target_user_id = %target_user_id,
        credential_id = %credential_id,
        "Admin revoked WebAuthn credential"
    );

    Ok(StatusCode::NO_CONTENT)
}
