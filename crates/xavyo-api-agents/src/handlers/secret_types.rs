//! HTTP handlers for secret type configuration management (F120).
//!
//! Provides endpoints for:
//! - Creating and managing secret type configurations
//! - Listing available secret types
//! - Enabling/disabling secret types

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
#[cfg(feature = "openapi")]
#[allow(unused_imports)]
use xavyo_db::models::secret_type_config::SecretTypeConfiguration;
use xavyo_db::models::secret_type_config::{
    CreateSecretTypeConfiguration, SecretTypeConfigFilter, UpdateSecretTypeConfiguration,
};

use crate::error::ApiAgentsError;
use crate::router::AgentsState;
#[cfg(feature = "openapi")]
#[allow(unused_imports)]
use crate::services::secret_type_service::SecretTypeListResponse;

/// Query parameters for listing secret types.
#[derive(Debug, Deserialize, Default)]
pub struct ListSecretTypesQuery {
    /// Filter by provider type.
    pub provider_type: Option<String>,
    /// Filter by enabled status.
    pub enabled: Option<bool>,
    /// Search by type name prefix.
    pub type_name_prefix: Option<String>,
    /// Maximum results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    100
}

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Create a new secret type configuration.
///
/// POST /secret-types
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/secret-types",
    request_body = CreateSecretTypeConfiguration,
    responses(
        (status = 201, description = "Secret type created", body = SecretTypeConfiguration),
        (status = 400, description = "Invalid request"),
        (status = 409, description = "Secret type already exists"),
    ),
    tag = "Secret Types"
))]
pub async fn create_secret_type(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateSecretTypeConfiguration>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let secret_type = state.secret_type_service.create(tenant_id, request).await?;

    Ok((StatusCode::CREATED, Json(secret_type)))
}

/// List secret type configurations.
///
/// GET /secret-types
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/secret-types",
    responses(
        (status = 200, description = "List of secret types", body = SecretTypeListResponse),
    ),
    params(
        ("provider_type" = Option<String>, Query, description = "Filter by provider type"),
        ("enabled" = Option<bool>, Query, description = "Filter by enabled status"),
        ("type_name_prefix" = Option<String>, Query, description = "Search by type name prefix"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Pagination offset"),
    ),
    tag = "Secret Types"
))]
pub async fn list_secret_types(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSecretTypesQuery>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let filter = SecretTypeConfigFilter {
        provider_type: query.provider_type,
        enabled: query.enabled,
        type_name_prefix: query.type_name_prefix,
    };

    let response = state
        .secret_type_service
        .list(tenant_id, filter, query.limit, query.offset)
        .await?;

    Ok(Json(response))
}

/// Get a secret type configuration by ID.
///
/// GET /secret-types/{id}
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/secret-types/{id}",
    responses(
        (status = 200, description = "Secret type details", body = SecretTypeConfiguration),
        (status = 404, description = "Secret type not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Secret type ID")
    ),
    tag = "Secret Types"
))]
pub async fn get_secret_type(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let secret_type = state.secret_type_service.get(tenant_id, id).await?;

    Ok(Json(secret_type))
}

/// Get a secret type configuration by name.
///
/// GET /secret-types/by-name/{type_name}
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/secret-types/by-name/{type_name}",
    responses(
        (status = 200, description = "Secret type details", body = SecretTypeConfiguration),
        (status = 404, description = "Secret type not found"),
    ),
    params(
        ("type_name" = String, Path, description = "Secret type name")
    ),
    tag = "Secret Types"
))]
pub async fn get_secret_type_by_name(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(type_name): Path<String>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let secret_type = state
        .secret_type_service
        .get_by_name(tenant_id, &type_name)
        .await?;

    Ok(Json(secret_type))
}

/// Update a secret type configuration.
///
/// PATCH /secret-types/{id}
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/secret-types/{id}",
    request_body = UpdateSecretTypeConfiguration,
    responses(
        (status = 200, description = "Secret type updated", body = SecretTypeConfiguration),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Secret type not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Secret type ID")
    ),
    tag = "Secret Types"
))]
pub async fn update_secret_type(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateSecretTypeConfiguration>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let secret_type = state
        .secret_type_service
        .update(tenant_id, id, request)
        .await?;

    Ok(Json(secret_type))
}

/// Delete a secret type configuration.
///
/// DELETE /secret-types/{id}
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/secret-types/{id}",
    responses(
        (status = 204, description = "Secret type deleted"),
        (status = 404, description = "Secret type not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Secret type ID")
    ),
    tag = "Secret Types"
))]
pub async fn delete_secret_type(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state.secret_type_service.delete(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable a secret type configuration.
///
/// POST /secret-types/{id}/enable
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/secret-types/{id}/enable",
    responses(
        (status = 200, description = "Secret type enabled", body = SecretTypeConfiguration),
        (status = 404, description = "Secret type not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Secret type ID")
    ),
    tag = "Secret Types"
))]
pub async fn enable_secret_type(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let secret_type = state.secret_type_service.enable(tenant_id, id).await?;

    Ok(Json(secret_type))
}

/// Disable a secret type configuration.
///
/// POST /secret-types/{id}/disable
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/secret-types/{id}/disable",
    responses(
        (status = 200, description = "Secret type disabled", body = SecretTypeConfiguration),
        (status = 404, description = "Secret type not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Secret type ID")
    ),
    tag = "Secret Types"
))]
pub async fn disable_secret_type(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let secret_type = state.secret_type_service.disable(tenant_id, id).await?;

    Ok(Json(secret_type))
}
