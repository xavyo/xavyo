//! Admin handlers for identity provider management.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use tracing::instrument;
use uuid::Uuid;
use xavyo_core::TenantId;

use crate::error::FederationResult;
use crate::models::{
    CreateDomainRequest, CreateIdentityProviderRequest, DomainListResponse, DomainResponse,
    IdentityProviderListResponse, IdentityProviderResponse, PaginationParams,
    ToggleIdentityProviderRequest, UpdateIdentityProviderRequest, ValidationResultResponse,
};
use crate::router::FederationState;

/// List identity providers for the tenant.
#[utoipa::path(
    get,
    path = "/admin/federation/identity-providers",
    params(PaginationParams),
    responses(
        (status = 200, description = "List of identity providers", body = IdentityProviderListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn list_identity_providers(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Query(params): Query<PaginationParams>,
) -> FederationResult<Json<IdentityProviderListResponse>> {
    let tenant_id = *tid.as_uuid();
    let clamped_limit = params.clamped_limit();
    let (idps, total) = state
        .idp_config
        .list(tenant_id, params.offset, clamped_limit)
        .await?;

    let mut items = Vec::with_capacity(idps.len());
    for idp in idps {
        let idp_id = idp.id;
        let domains = state.idp_config.get_domains(tenant_id, idp_id).await?;
        let linked_users_count = state
            .idp_config
            .get_linked_users_count(tenant_id, idp_id)
            .await?;
        items.push(IdentityProviderResponse::from_model(
            idp,
            domains,
            linked_users_count,
        ));
    }

    Ok(Json(IdentityProviderListResponse {
        items,
        total,
        offset: params.offset,
        limit: clamped_limit,
    }))
}

/// Create a new identity provider.
#[utoipa::path(
    post,
    path = "/admin/federation/identity-providers",
    request_body = CreateIdentityProviderRequest,
    responses(
        (status = 201, description = "Identity provider created", body = IdentityProviderResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state, req))]
pub async fn create_identity_provider(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Json(req): Json<CreateIdentityProviderRequest>,
) -> FederationResult<impl IntoResponse> {
    let tenant_id = *tid.as_uuid();

    // Audit log
    tracing::info!(
        tenant_id = %tenant_id,
        name = %req.name,
        provider_type = %req.provider_type,
        "Admin creating identity provider"
    );

    let idp = state.idp_config.create(tenant_id, req).await?;
    let domains = state.idp_config.get_domains(tenant_id, idp.id).await?;
    let response = IdentityProviderResponse::from_model(idp, domains, 0);

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get a specific identity provider.
#[utoipa::path(
    get,
    path = "/admin/federation/identity-providers/{idp_id}",
    params(
        ("idp_id" = Uuid, Path, description = "Identity Provider ID"),
    ),
    responses(
        (status = 200, description = "Identity provider details", body = IdentityProviderResponse),
        (status = 404, description = "Identity provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn get_identity_provider(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Path(idp_id): Path<Uuid>,
) -> FederationResult<Json<IdentityProviderResponse>> {
    let tenant_id = *tid.as_uuid();
    let idp = state.idp_config.get(tenant_id, idp_id).await?;
    let domains = state.idp_config.get_domains(tenant_id, idp_id).await?;
    let linked_users_count = state
        .idp_config
        .get_linked_users_count(tenant_id, idp_id)
        .await?;

    Ok(Json(IdentityProviderResponse::from_model(
        idp,
        domains,
        linked_users_count,
    )))
}

/// Update an identity provider.
#[utoipa::path(
    put,
    path = "/admin/federation/identity-providers/{idp_id}",
    params(
        ("idp_id" = Uuid, Path, description = "Identity Provider ID"),
    ),
    request_body = UpdateIdentityProviderRequest,
    responses(
        (status = 200, description = "Identity provider updated", body = IdentityProviderResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Identity provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state, req))]
pub async fn update_identity_provider(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Path(idp_id): Path<Uuid>,
    Json(req): Json<UpdateIdentityProviderRequest>,
) -> FederationResult<Json<IdentityProviderResponse>> {
    let tenant_id = *tid.as_uuid();

    // Audit log
    tracing::info!(
        tenant_id = %tenant_id,
        idp_id = %idp_id,
        "Admin updating identity provider"
    );

    let idp = state.idp_config.update(tenant_id, idp_id, req).await?;
    let domains = state.idp_config.get_domains(tenant_id, idp_id).await?;
    let linked_users_count = state
        .idp_config
        .get_linked_users_count(tenant_id, idp_id)
        .await?;

    Ok(Json(IdentityProviderResponse::from_model(
        idp,
        domains,
        linked_users_count,
    )))
}

/// Delete an identity provider.
#[utoipa::path(
    delete,
    path = "/admin/federation/identity-providers/{idp_id}",
    params(
        ("idp_id" = Uuid, Path, description = "Identity Provider ID"),
    ),
    responses(
        (status = 204, description = "Identity provider deleted"),
        (status = 404, description = "Identity provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn delete_identity_provider(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Path(idp_id): Path<Uuid>,
) -> FederationResult<StatusCode> {
    let tenant_id = *tid.as_uuid();

    // Audit log
    tracing::info!(
        tenant_id = %tenant_id,
        idp_id = %idp_id,
        "Admin deleting identity provider"
    );

    state.idp_config.delete(tenant_id, idp_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Validate an identity provider configuration.
#[utoipa::path(
    post,
    path = "/admin/federation/identity-providers/{idp_id}/validate",
    params(
        ("idp_id" = Uuid, Path, description = "Identity Provider ID"),
    ),
    responses(
        (status = 200, description = "Validation result", body = ValidationResultResponse),
        (status = 404, description = "Identity provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn validate_identity_provider(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Path(idp_id): Path<Uuid>,
) -> FederationResult<Json<ValidationResultResponse>> {
    let tenant_id = *tid.as_uuid();

    // Audit log
    tracing::info!(
        tenant_id = %tenant_id,
        idp_id = %idp_id,
        "Admin validating identity provider"
    );

    let result = state.validation.validate(tenant_id, idp_id).await?;

    Ok(Json(result))
}

/// Toggle identity provider enabled status.
#[utoipa::path(
    post,
    path = "/admin/federation/identity-providers/{idp_id}/toggle",
    params(
        ("idp_id" = Uuid, Path, description = "Identity Provider ID"),
    ),
    request_body = ToggleIdentityProviderRequest,
    responses(
        (status = 200, description = "Identity provider toggled", body = IdentityProviderResponse),
        (status = 404, description = "Identity provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn toggle_identity_provider(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Path(idp_id): Path<Uuid>,
    Json(req): Json<ToggleIdentityProviderRequest>,
) -> FederationResult<Json<IdentityProviderResponse>> {
    let tenant_id = *tid.as_uuid();

    // Audit log
    tracing::info!(
        tenant_id = %tenant_id,
        idp_id = %idp_id,
        is_enabled = %req.is_enabled,
        "Admin toggling identity provider"
    );

    let idp = state
        .idp_config
        .set_enabled(tenant_id, idp_id, req.is_enabled)
        .await?;
    let domains = state.idp_config.get_domains(tenant_id, idp_id).await?;
    let linked_users_count = state
        .idp_config
        .get_linked_users_count(tenant_id, idp_id)
        .await?;

    Ok(Json(IdentityProviderResponse::from_model(
        idp,
        domains,
        linked_users_count,
    )))
}

/// List domains for an identity provider.
#[utoipa::path(
    get,
    path = "/admin/federation/identity-providers/{idp_id}/domains",
    params(
        ("idp_id" = Uuid, Path, description = "Identity Provider ID"),
    ),
    responses(
        (status = 200, description = "List of domains", body = DomainListResponse),
        (status = 404, description = "Identity provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn list_domains(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Path(idp_id): Path<Uuid>,
) -> FederationResult<Json<DomainListResponse>> {
    let tenant_id = *tid.as_uuid();

    // Verify IdP exists
    let _ = state.idp_config.get(tenant_id, idp_id).await?;

    let domains = state.idp_config.get_domains(tenant_id, idp_id).await?;

    Ok(Json(DomainListResponse {
        items: domains.into_iter().map(DomainResponse::from).collect(),
    }))
}

/// Add a domain to an identity provider.
#[utoipa::path(
    post,
    path = "/admin/federation/identity-providers/{idp_id}/domains",
    params(
        ("idp_id" = Uuid, Path, description = "Identity Provider ID"),
    ),
    request_body = CreateDomainRequest,
    responses(
        (status = 201, description = "Domain added", body = DomainResponse),
        (status = 400, description = "Invalid domain"),
        (status = 404, description = "Identity provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn add_domain(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Path(idp_id): Path<Uuid>,
    Json(req): Json<CreateDomainRequest>,
) -> FederationResult<impl IntoResponse> {
    let tenant_id = *tid.as_uuid();

    // Audit log
    tracing::info!(
        tenant_id = %tenant_id,
        idp_id = %idp_id,
        domain = %req.domain,
        "Admin adding domain to identity provider"
    );

    let domain = state
        .idp_config
        .add_domain(tenant_id, idp_id, req.domain, req.priority)
        .await?;

    Ok((StatusCode::CREATED, Json(DomainResponse::from(domain))))
}

/// Remove a domain from an identity provider.
#[utoipa::path(
    delete,
    path = "/admin/federation/identity-providers/{idp_id}/domains/{domain_id}",
    params(
        ("idp_id" = Uuid, Path, description = "Identity Provider ID"),
        ("domain_id" = Uuid, Path, description = "Domain ID"),
    ),
    responses(
        (status = 204, description = "Domain removed"),
        (status = 404, description = "Domain or identity provider not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "OIDC Federation"
)]
#[instrument(skip(state))]
pub async fn remove_domain(
    State(state): State<FederationState>,
    Extension(tid): Extension<TenantId>,
    Path((idp_id, domain_id)): Path<(Uuid, Uuid)>,
) -> FederationResult<StatusCode> {
    let tenant_id = *tid.as_uuid();

    // Audit log
    tracing::info!(
        tenant_id = %tenant_id,
        idp_id = %idp_id,
        domain_id = %domain_id,
        "Admin removing domain from identity provider"
    );

    state
        .idp_config
        .remove_domain(tenant_id, idp_id, domain_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
