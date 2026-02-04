//! HTTP handlers for secret provider configuration management (F120).
//!
//! Endpoints for managing external secret providers (`OpenBao`, Infisical, AWS)
//! including CRUD operations and health checks.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::secret_provider_config::SecretProviderConfigFilter;

use crate::error::ApiAgentsError;
use crate::router::AgentsState;
use crate::services::secret_provider_service::{CreateProviderRequest, UpdateProviderRequest};

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenantId)
}

/// Query parameters for listing providers.
#[derive(Debug, Default, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListProvidersQuery {
    /// Filter by provider type (openbao, infisical, internal, aws).
    pub provider_type: Option<String>,
    /// Filter by status (active, inactive, error).
    pub status: Option<String>,
    /// Search by name prefix.
    pub name_prefix: Option<String>,
    /// Maximum number of results (default: 50, max: 100).
    pub limit: Option<i64>,
    /// Offset for pagination (default: 0).
    pub offset: Option<i64>,
}

/// Create a new secret provider configuration.
///
/// POST /providers
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/providers",
    request_body = CreateProviderRequest,
    responses(
        (status = 201, description = "Provider created", body = ProviderResponse),
        (status = 400, description = "Invalid request"),
        (status = 409, description = "Provider name already exists"),
    ),
    tag = "Secret Providers"
))]
pub async fn create_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(input): Json<CreateProviderRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .secret_provider_service
        .create_provider(tenant_id, input)
        .await?;

    Ok((StatusCode::CREATED, Json(response)))
}

/// List secret provider configurations.
///
/// GET /providers
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/providers",
    params(ListProvidersQuery),
    responses(
        (status = 200, description = "List of providers", body = ProviderListResponse),
    ),
    tag = "Secret Providers"
))]
pub async fn list_providers(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListProvidersQuery>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let filter = SecretProviderConfigFilter {
        provider_type: query.provider_type,
        status: query.status,
        name_prefix: query.name_prefix,
    };

    let response = state
        .secret_provider_service
        .list_providers(tenant_id, filter, limit, offset)
        .await?;

    Ok(Json(response))
}

/// Get a secret provider configuration by ID.
///
/// GET /providers/:id
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/providers/{id}",
    params(
        ("id" = Uuid, Path, description = "Provider ID")
    ),
    responses(
        (status = 200, description = "Provider details", body = ProviderResponse),
        (status = 404, description = "Provider not found"),
    ),
    tag = "Secret Providers"
))]
pub async fn get_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(provider_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .secret_provider_service
        .get_provider(tenant_id, provider_id)
        .await?;

    Ok(Json(response))
}

/// Update a secret provider configuration.
///
/// PATCH /providers/:id
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/providers/{id}",
    params(
        ("id" = Uuid, Path, description = "Provider ID")
    ),
    request_body = UpdateProviderRequest,
    responses(
        (status = 200, description = "Provider updated", body = ProviderResponse),
        (status = 404, description = "Provider not found"),
        (status = 409, description = "Provider name already exists"),
    ),
    tag = "Secret Providers"
))]
pub async fn update_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(provider_id): Path<Uuid>,
    Json(input): Json<UpdateProviderRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .secret_provider_service
        .update_provider(tenant_id, provider_id, input)
        .await?;

    Ok(Json(response))
}

/// Delete a secret provider configuration.
///
/// DELETE /providers/:id
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/providers/{id}",
    params(
        ("id" = Uuid, Path, description = "Provider ID")
    ),
    responses(
        (status = 204, description = "Provider deleted"),
        (status = 404, description = "Provider not found"),
    ),
    tag = "Secret Providers"
))]
pub async fn delete_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(provider_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state
        .secret_provider_service
        .delete_provider(tenant_id, provider_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Activate a secret provider.
///
/// POST /providers/:id/activate
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/providers/{id}/activate",
    params(
        ("id" = Uuid, Path, description = "Provider ID")
    ),
    responses(
        (status = 200, description = "Provider activated", body = ProviderResponse),
        (status = 404, description = "Provider not found"),
    ),
    tag = "Secret Providers"
))]
pub async fn activate_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(provider_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .secret_provider_service
        .activate_provider(tenant_id, provider_id)
        .await?;

    Ok(Json(response))
}

/// Deactivate a secret provider.
///
/// POST /providers/:id/deactivate
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/providers/{id}/deactivate",
    params(
        ("id" = Uuid, Path, description = "Provider ID")
    ),
    responses(
        (status = 200, description = "Provider deactivated", body = ProviderResponse),
        (status = 404, description = "Provider not found"),
    ),
    tag = "Secret Providers"
))]
pub async fn deactivate_provider(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(provider_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .secret_provider_service
        .deactivate_provider(tenant_id, provider_id)
        .await?;

    Ok(Json(response))
}

/// Run a health check on a secret provider.
///
/// POST /providers/:id/health
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/providers/{id}/health",
    params(
        ("id" = Uuid, Path, description = "Provider ID")
    ),
    responses(
        (status = 200, description = "Health check result", body = ProviderHealthResult),
        (status = 404, description = "Provider not found"),
    ),
    tag = "Secret Providers"
))]
pub async fn check_provider_health(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(provider_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let result = state
        .secret_provider_service
        .health_check(tenant_id, provider_id)
        .await?;

    Ok(Json(result))
}

// Re-export ProviderHealthResult for OpenAPI schema
#[cfg(feature = "openapi")]
pub use xavyo_db::models::secret_provider_config::ProviderHealthResult;
