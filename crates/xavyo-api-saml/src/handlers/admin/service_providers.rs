//! Service Provider admin handlers

use crate::error::SamlResult;
use crate::handlers::metadata::SamlState;
use crate::models::{PaginationQuery, ServiceProviderListResponse, ServiceProviderResponse};
use crate::services::SpService;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::models::{CreateServiceProviderRequest, UpdateServiceProviderRequest};

/// List all service providers
#[utoipa::path(
    get,
    path = "/admin/saml/service-providers",
    params(PaginationQuery),
    responses(
        (status = 200, description = "List of service providers", body = ServiceProviderListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML Admin"
)]
pub async fn list_service_providers(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Query(query): Query<PaginationQuery>,
) -> impl IntoResponse {
    match list_service_providers_inner(&state, *tenant_id.as_uuid(), query).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn list_service_providers_inner(
    state: &SamlState,
    tenant_id: Uuid,
    query: PaginationQuery,
) -> SamlResult<ServiceProviderListResponse> {
    let sp_service = SpService::new(state.pool.clone());
    let (sps, total) = sp_service
        .list_sps(tenant_id, query.limit, query.offset, query.enabled)
        .await?;

    Ok(ServiceProviderListResponse {
        items: sps.into_iter().map(ServiceProviderResponse::from).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    })
}

/// Create a new service provider
#[utoipa::path(
    post,
    path = "/admin/saml/service-providers",
    responses(
        (status = 201, description = "Service provider created", body = ServiceProviderResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML Admin"
)]
pub async fn create_service_provider(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Json(req): Json<CreateServiceProviderRequest>,
) -> impl IntoResponse {
    let sp_service = SpService::new(state.pool.clone());

    match sp_service.create_sp(*tenant_id.as_uuid(), req).await {
        Ok(sp) => (StatusCode::CREATED, Json(ServiceProviderResponse::from(sp))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Get a specific service provider
#[utoipa::path(
    get,
    path = "/admin/saml/service-providers/{sp_id}",
    params(
        ("sp_id" = Uuid, Path, description = "Service Provider ID"),
    ),
    responses(
        (status = 200, description = "Service provider details", body = ServiceProviderResponse),
        (status = 404, description = "Service provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML Admin"
)]
pub async fn get_service_provider(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(sp_id): Path<Uuid>,
) -> impl IntoResponse {
    let sp_service = SpService::new(state.pool.clone());

    match sp_service.get_sp(*tenant_id.as_uuid(), sp_id).await {
        Ok(sp) => (StatusCode::OK, Json(ServiceProviderResponse::from(sp))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Update a service provider
#[utoipa::path(
    put,
    path = "/admin/saml/service-providers/{sp_id}",
    params(
        ("sp_id" = Uuid, Path, description = "Service Provider ID"),
    ),
    responses(
        (status = 200, description = "Service provider updated", body = ServiceProviderResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Service provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML Admin"
)]
pub async fn update_service_provider(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(sp_id): Path<Uuid>,
    Json(req): Json<UpdateServiceProviderRequest>,
) -> impl IntoResponse {
    let sp_service = SpService::new(state.pool.clone());

    match sp_service.update_sp(*tenant_id.as_uuid(), sp_id, req).await {
        Ok(sp) => (StatusCode::OK, Json(ServiceProviderResponse::from(sp))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Delete a service provider
#[utoipa::path(
    delete,
    path = "/admin/saml/service-providers/{sp_id}",
    params(
        ("sp_id" = Uuid, Path, description = "Service Provider ID"),
    ),
    responses(
        (status = 204, description = "Service provider deleted"),
        (status = 404, description = "Service provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML Admin"
)]
pub async fn delete_service_provider(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(sp_id): Path<Uuid>,
) -> impl IntoResponse {
    let sp_service = SpService::new(state.pool.clone());

    match sp_service.delete_sp(*tenant_id.as_uuid(), sp_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}
