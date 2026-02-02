//! Identity Provider configuration handlers for Workload Identity Federation (F121).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::providers::ProviderConfig;
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    CloudProviderType, CreateIdentityProviderConfig, IdentityProviderConfig,
    IdentityProviderConfigFilter, IdpHealthStatus, UpdateIdentityProviderConfig,
};

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Extract user_id from JWT claims (uses sub field).
fn extract_user_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiAgentsError::MissingUser)
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request to create an identity provider configuration.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateIdentityProviderRequest {
    /// Provider type (aws, gcp, azure, kubernetes).
    pub provider_type: CloudProviderType,
    /// Display name for the provider.
    pub name: String,
    /// Provider-specific configuration.
    pub configuration: ProviderConfig,
    /// Whether the provider is active.
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_true() -> bool {
    true
}

/// Request to update an identity provider configuration.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateIdentityProviderRequest {
    /// Display name for the provider.
    pub name: Option<String>,
    /// Provider-specific configuration.
    pub configuration: Option<ProviderConfig>,
    /// Whether the provider is active.
    pub is_active: Option<bool>,
}

/// Query parameters for listing identity providers.
#[derive(Debug, Default, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListIdentityProvidersQuery {
    /// Filter by provider type.
    pub provider_type: Option<CloudProviderType>,
    /// Filter by active status.
    pub is_active: Option<bool>,
}

/// Query parameters for deleting an identity provider.
#[derive(Debug, Default, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct DeleteIdentityProviderQuery {
    /// If true, cascade delete all associated role mappings (T044).
    #[serde(default)]
    pub cascade: bool,
}

/// Response for an identity provider configuration.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IdentityProviderResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider_type: CloudProviderType,
    pub name: String,
    pub is_active: bool,
    pub last_health_check: Option<chrono::DateTime<chrono::Utc>>,
    pub health_status: IdpHealthStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<IdentityProviderConfig> for IdentityProviderResponse {
    fn from(config: IdentityProviderConfig) -> Self {
        Self {
            id: config.id,
            tenant_id: config.tenant_id,
            provider_type: config
                .provider_type
                .parse()
                .unwrap_or(CloudProviderType::Aws),
            name: config.name,
            is_active: config.is_active,
            last_health_check: config.last_health_check,
            health_status: config.health_status.parse().unwrap_or_default(),
            created_at: config.created_at,
            updated_at: config.updated_at,
        }
    }
}

/// Response for a health check.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HealthCheckResponse {
    pub provider_config_id: Uuid,
    pub status: IdpHealthStatus,
    pub latency_ms: Option<i32>,
    pub message: Option<String>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /identity-providers - Create a new identity provider configuration.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/identity-providers",
    tag = "Identity Providers",
    operation_id = "createIdentityProvider",
    request_body = CreateIdentityProviderRequest,
    responses(
        (status = 201, description = "Identity provider created", body = IdentityProviderResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "Duplicate provider name")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_identity_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateIdentityProviderRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;

    // Validate the configuration
    state
        .identity_provider_service
        .validate_provider_config(&request.configuration)?;

    // Encrypt the configuration for storage
    let config_json = serde_json::to_string(&request.configuration)
        .map_err(|e| ApiAgentsError::InvalidProviderConfig(e.to_string()))?;

    // For now, store unencrypted (in production, use encryption service)
    let create_request = CreateIdentityProviderConfig {
        provider_type: request.provider_type,
        name: request.name,
        configuration: config_json,
        is_active: request.is_active,
    };

    let provider = state
        .identity_provider_service
        .create_provider(
            tenant_id,
            user_id,
            &create_request,
            &create_request.configuration,
        )
        .await?;

    // Invalidate federation service cache
    state
        .identity_federation_service
        .invalidate_provider_cache(provider.id)
        .await;

    Ok((
        StatusCode::CREATED,
        Json(IdentityProviderResponse::from(provider)),
    ))
}

/// GET /identity-providers - List identity provider configurations.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/identity-providers",
    tag = "Identity Providers",
    operation_id = "listIdentityProviders",
    params(ListIdentityProvidersQuery),
    responses(
        (status = 200, description = "List of identity providers", body = Vec<IdentityProviderResponse>),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_identity_providers(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListIdentityProvidersQuery>,
) -> Result<Json<Vec<IdentityProviderResponse>>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let filter = IdentityProviderConfigFilter {
        provider_type: query.provider_type,
        is_active: query.is_active,
    };

    let providers = state
        .identity_provider_service
        .list_providers(tenant_id, &filter)
        .await?;

    let response: Vec<IdentityProviderResponse> = providers.into_iter().map(Into::into).collect();

    Ok(Json(response))
}

/// GET /identity-providers/{id} - Get identity provider configuration by ID.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/identity-providers/{id}",
    tag = "Identity Providers",
    operation_id = "getIdentityProvider",
    params(
        ("id" = Uuid, Path, description = "Identity provider ID")
    ),
    responses(
        (status = 200, description = "Identity provider configuration", body = IdentityProviderResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Identity provider not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_identity_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<IdentityProviderResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let provider = state
        .identity_provider_service
        .get_provider(tenant_id, id)
        .await?;

    Ok(Json(IdentityProviderResponse::from(provider)))
}

/// PATCH /identity-providers/{id} - Update identity provider configuration.
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/identity-providers/{id}",
    tag = "Identity Providers",
    operation_id = "updateIdentityProvider",
    params(
        ("id" = Uuid, Path, description = "Identity provider ID")
    ),
    request_body = UpdateIdentityProviderRequest,
    responses(
        (status = 200, description = "Identity provider updated", body = IdentityProviderResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Identity provider not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn update_identity_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateIdentityProviderRequest>,
) -> Result<Json<IdentityProviderResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;

    // Validate configuration if provided
    let encrypted_config = if let Some(ref config) = request.configuration {
        state
            .identity_provider_service
            .validate_provider_config(config)?;

        let config_json = serde_json::to_string(config)
            .map_err(|e| ApiAgentsError::InvalidProviderConfig(e.to_string()))?;

        Some(config_json)
    } else {
        None
    };

    let update_request = UpdateIdentityProviderConfig {
        name: request.name,
        configuration: encrypted_config.clone(),
        is_active: request.is_active,
    };

    let provider = state
        .identity_provider_service
        .update_provider(
            tenant_id,
            user_id,
            id,
            &update_request,
            encrypted_config.as_deref(),
        )
        .await?;

    // Invalidate federation service cache
    state
        .identity_federation_service
        .invalidate_provider_cache(id)
        .await;

    Ok(Json(IdentityProviderResponse::from(provider)))
}

/// DELETE /identity-providers/{id} - Delete identity provider configuration.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/identity-providers/{id}",
    tag = "Identity Providers",
    operation_id = "deleteIdentityProvider",
    params(
        ("id" = Uuid, Path, description = "Identity provider ID"),
        DeleteIdentityProviderQuery
    ),
    responses(
        (status = 204, description = "Identity provider deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Identity provider not found"),
        (status = 409, description = "Provider has active role mappings (use ?cascade=true to delete)")
    ),
    security(("bearerAuth" = []))
))]
pub async fn delete_identity_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<DeleteIdentityProviderQuery>,
) -> Result<StatusCode, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims)?;

    // Use cascade delete if requested (T044)
    state
        .identity_provider_service
        .delete_provider_with_cascade(tenant_id, user_id, id, query.cascade)
        .await?;

    // Invalidate federation service cache
    state
        .identity_federation_service
        .invalidate_provider_cache(id)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /identity-providers/{id}/health - Check identity provider health.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/identity-providers/{id}/health",
    tag = "Identity Providers",
    operation_id = "checkIdentityProviderHealth",
    params(
        ("id" = Uuid, Path, description = "Identity provider ID")
    ),
    responses(
        (status = 200, description = "Health check result", body = HealthCheckResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Identity provider not found"),
        (status = 503, description = "Provider unreachable")
    ),
    security(("bearerAuth" = []))
))]
pub async fn check_identity_provider_health(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<HealthCheckResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Verify provider exists
    let provider = state
        .identity_provider_service
        .get_provider(tenant_id, id)
        .await?;

    // Perform health check via federation service
    let start = std::time::Instant::now();
    let result = state
        .identity_federation_service
        .check_provider_health(tenant_id, id)
        .await;
    let latency_ms = start.elapsed().as_millis() as i32;

    let (status, message) = match result {
        Ok(()) => (IdpHealthStatus::Healthy, None),
        Err(e) => (IdpHealthStatus::Unhealthy, Some(e.to_string())),
    };

    // Update the health status in the database
    state
        .identity_provider_service
        .update_health_status(tenant_id, id, status, Some(latency_ms), message.as_deref())
        .await?;

    Ok(Json(HealthCheckResponse {
        provider_config_id: provider.id,
        status,
        latency_ms: Some(latency_ms),
        message,
        checked_at: chrono::Utc::now(),
    }))
}
