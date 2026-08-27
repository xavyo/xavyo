//! Admin handlers for managing tenant social provider configurations.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::info;

use crate::error::{ProviderType, SocialError, SocialResult};
use crate::extractors::AuthenticatedUser;
use crate::models::{TenantProviderResponse, TenantProvidersListResponse, UpdateProviderRequest};
use crate::SocialState;

/// List all configured social providers for the tenant.
#[utoipa::path(
    get,
    path = "/admin/social-providers",
    responses(
        (status = 200, description = "List of provider configurations", body = TenantProvidersListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Social Login"
)]
pub async fn list_providers(
    State(state): State<SocialState>,
    user: AuthenticatedUser,
) -> SocialResult<Json<TenantProvidersListResponse>> {
    // R9: Use tenant_id from JWT claims (not X-Tenant-ID header) to prevent cross-tenant access
    let tenant_id = user.tenant_id;
    let providers = state
        .tenant_provider_service
        .list_providers(tenant_id)
        .await?;

    Ok(Json(TenantProvidersListResponse { providers }))
}

/// Update or create a social provider configuration.
#[utoipa::path(
    put,
    path = "/admin/social-providers/{provider}",
    params(
        ("provider" = String, Path, description = "Social provider (google, microsoft, apple)"),
    ),
    request_body = UpdateProviderRequest,
    responses(
        (status = 200, description = "Provider configuration updated", body = TenantProviderResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Social Login"
)]
pub async fn update_provider(
    State(state): State<SocialState>,
    user: AuthenticatedUser,
    Path(provider): Path<String>,
    Json(request): Json<UpdateProviderRequest>,
) -> SocialResult<Json<TenantProviderResponse>> {
    // R9: Use tenant_id from JWT claims (not X-Tenant-ID header) to prevent cross-tenant access
    let tenant_id = user.tenant_id;
    let provider_type: ProviderType = provider.parse()?;

    info!(
        tenant_id = %tenant_id,
        provider = %provider_type,
        enabled = request.enabled,
        "Updating social provider configuration"
    );

    let client_secret = social_update_secret(request.enabled, request.client_secret.as_deref())?;

    let response = state
        .tenant_provider_service
        .update_provider(
            tenant_id,
            provider_type,
            request.enabled,
            &request.client_id,
            client_secret,
            request.additional_config,
            request.scopes,
        )
        .await?;

    info!(
        tenant_id = %tenant_id,
        provider = %provider_type,
        "Social provider configuration updated"
    );

    Ok(Json(response))
}

/// Disable a social provider.
#[utoipa::path(
    delete,
    path = "/admin/social-providers/{provider}",
    params(
        ("provider" = String, Path, description = "Social provider to disable"),
    ),
    responses(
        (status = 204, description = "Provider disabled"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Social Login"
)]
pub async fn disable_provider(
    State(state): State<SocialState>,
    user: AuthenticatedUser,
    Path(provider): Path<String>,
) -> Result<impl IntoResponse, SocialError> {
    // R9: Use tenant_id from JWT claims (not X-Tenant-ID header) to prevent cross-tenant access
    let tenant_id = user.tenant_id;
    let provider_type: ProviderType = provider.parse()?;

    info!(
        tenant_id = %tenant_id,
        provider = %provider_type,
        "Disabling social provider"
    );

    state
        .tenant_provider_service
        .disable_provider(tenant_id, provider_type)
        .await?;

    info!(
        tenant_id = %tenant_id,
        provider = %provider_type,
        "Social provider disabled"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Secret is required when enabling. Disabling without a secret must keep the stored secret.
fn social_update_secret(enabled: bool, secret: Option<&str>) -> SocialResult<Option<&str>> {
    let secret = secret.map(str::trim).filter(|s| !s.is_empty());
    if enabled && secret.is_none() {
        return Err(SocialError::ConfigurationError {
            message: "client_secret is required when enabling a provider".to_string(),
        });
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_without_secret_does_not_send_empty() {
        assert!(social_update_secret(true, None).is_err());
        assert_eq!(
            social_update_secret(true, Some("s3cret")).unwrap(),
            Some("s3cret")
        );
        assert_eq!(social_update_secret(false, None).unwrap(), None);
        assert_eq!(social_update_secret(false, Some("")).unwrap(), None);
        assert_eq!(
            social_update_secret(false, Some("keep")).unwrap(),
            Some("keep")
        );
        let src = include_str!("admin.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("social_update_secret(") && !production.contains("unwrap_or(\"\")"),
            "disabling a social provider must not overwrite the secret with empty"
        );
    }
}
