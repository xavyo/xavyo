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

    // Client secret is required when enabling
    let client_secret = if request.enabled {
        request
            .client_secret
            .as_deref()
            .ok_or(SocialError::ConfigurationError {
                message: "client_secret is required when enabling a provider".to_string(),
            })?
    } else {
        request.client_secret.as_deref().unwrap_or("")
    };

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
