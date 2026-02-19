//! NHI Delegation management handlers.
//!
//! Provides REST endpoints for managing NHI delegation grants:
//! - Create, list, get, revoke delegation grants
//! - Query grants by principal (outgoing) or actor (incoming)

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::nhi_delegation_grant::{CreateNhiDelegationGrant, NhiDelegationGrant};

use crate::error::NhiApiError;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateDelegationRequest {
    pub principal_id: Uuid,
    pub principal_type: String,
    pub actor_nhi_id: Uuid,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub allowed_resource_types: Vec<String>,
    pub max_delegation_depth: Option<i32>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListDelegationsQuery {
    pub principal_id: Option<Uuid>,
    pub actor_nhi_id: Option<Uuid>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeRequest {
    pub revoked_by: Option<Uuid>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PaginatedDelegationResponse {
    pub data: Vec<NhiDelegationGrant>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeResponse {
    pub revoked: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /nhi/delegations -- Create a delegation grant.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/delegations",
    request_body = CreateDelegationRequest,
    responses(
        (status = 201, description = "Delegation grant created", body = NhiDelegationGrant),
        (status = 403, description = "Forbidden"),
    ),
    tag = "NHI Delegation"
))]
pub async fn create_delegation_grant(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateDelegationRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let is_admin = claims.has_role("admin") || claims.has_role("super_admin");

    if !is_admin {
        // Non-admin: only allowed for self-delegation if the tenant permits it
        let caller_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| NhiApiError::BadRequest("invalid caller subject".into()))?;

        let is_self_delegation =
            request.principal_type == "user" && request.principal_id == caller_id;

        if !is_self_delegation {
            return Err(NhiApiError::Forbidden);
        }

        // Check tenant-level allow_self_delegation flag
        if !check_self_delegation_allowed(&state.pool, tenant_uuid).await? {
            return Err(NhiApiError::Forbidden);
        }
    }

    // S8: Validate principal_type against DB CHECK constraint values
    if !matches!(request.principal_type.as_str(), "user" | "nhi") {
        return Err(NhiApiError::BadRequest(
            "principal_type must be 'user' or 'nhi'".into(),
        ));
    }

    // S7: Validate input bounds on scopes and resource_types
    const MAX_SCOPES: usize = 50;
    const MAX_RESOURCE_TYPES: usize = 50;
    const MAX_SCOPE_LENGTH: usize = 256;

    if request.allowed_scopes.len() > MAX_SCOPES {
        return Err(NhiApiError::BadRequest(format!(
            "allowed_scopes exceeds maximum of {MAX_SCOPES} entries"
        )));
    }
    if request.allowed_resource_types.len() > MAX_RESOURCE_TYPES {
        return Err(NhiApiError::BadRequest(format!(
            "allowed_resource_types exceeds maximum of {MAX_RESOURCE_TYPES} entries"
        )));
    }
    for scope in &request.allowed_scopes {
        if scope.len() > MAX_SCOPE_LENGTH || scope.is_empty() {
            return Err(NhiApiError::BadRequest(format!(
                "each scope must be 1-{MAX_SCOPE_LENGTH} characters"
            )));
        }
    }
    for rt in &request.allowed_resource_types {
        if rt.len() > MAX_SCOPE_LENGTH || rt.is_empty() {
            return Err(NhiApiError::BadRequest(format!(
                "each resource_type must be 1-{MAX_SCOPE_LENGTH} characters"
            )));
        }
    }

    // Validate max_delegation_depth if provided (must match DB CHECK: 1..=5)
    if let Some(depth) = request.max_delegation_depth {
        if !(1..=5).contains(&depth) {
            return Err(NhiApiError::BadRequest(
                "max_delegation_depth must be between 1 and 5".into(),
            ));
        }
    }

    // SECURITY: Always set granted_by from the authenticated caller, not from the
    // request body. Trusting client-supplied granted_by enables audit log forgery.
    let caller_id = Uuid::parse_str(&claims.sub).ok();

    let input = CreateNhiDelegationGrant {
        principal_id: request.principal_id,
        principal_type: request.principal_type,
        actor_nhi_id: request.actor_nhi_id,
        allowed_scopes: request.allowed_scopes,
        allowed_resource_types: request.allowed_resource_types,
        max_delegation_depth: request.max_delegation_depth,
        granted_by: caller_id,
        expires_at: request.expires_at,
    };

    let grant = NhiDelegationGrant::grant(&state.pool, tenant_uuid, input).await?;

    // Emit Kafka event (fire-and-forget)
    #[cfg(feature = "kafka")]
    emit_grant_created_event(&state, tenant_uuid, &grant).await;

    Ok((StatusCode::CREATED, Json(grant)))
}

/// Check if the tenant allows self-service delegation.
async fn check_self_delegation_allowed(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<bool, NhiApiError> {
    let result: Option<(bool,)> =
        sqlx::query_as("SELECT allow_self_delegation FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to check allow_self_delegation: {}", e);
                NhiApiError::Internal(format!("database error: {e}"))
            })?;

    Ok(result.is_some_and(|r| r.0))
}

/// GET /nhi/delegations -- List delegation grants with optional filters.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/delegations",
    params(ListDelegationsQuery),
    responses(
        (status = 200, description = "Paginated list of delegation grants", body = PaginatedDelegationResponse),
        (status = 403, description = "Forbidden"),
    ),
    tag = "NHI Delegation"
))]
pub async fn list_delegation_grants(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDelegationsQuery>,
) -> Result<Json<PaginatedDelegationResponse>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let data = if let Some(principal_id) = query.principal_id {
        NhiDelegationGrant::list_by_principal(&state.pool, tenant_uuid, principal_id, limit, offset)
            .await?
    } else if let Some(actor_nhi_id) = query.actor_nhi_id {
        NhiDelegationGrant::list_by_actor(&state.pool, tenant_uuid, actor_nhi_id, limit, offset)
            .await?
    } else {
        // No filter: list by principal with a nil UUID won't return results.
        // For a full listing, we'd need a separate query. Return empty for now
        // or require at least one filter.
        return Err(NhiApiError::BadRequest(
            "Either principal_id or actor_nhi_id query parameter is required".into(),
        ));
    };

    Ok(Json(PaginatedDelegationResponse {
        data,
        limit,
        offset,
    }))
}

/// GET /nhi/delegations/:id -- Get a specific delegation grant.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/delegations/{id}",
    params(
        ("id" = Uuid, Path, description = "Delegation grant ID"),
    ),
    responses(
        (status = 200, description = "Delegation grant details", body = NhiDelegationGrant),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    tag = "NHI Delegation"
))]
pub async fn get_delegation_grant(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<NhiDelegationGrant>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    let grant = NhiDelegationGrant::find_by_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    Ok(Json(grant))
}

/// POST /nhi/delegations/:id/revoke -- Revoke a delegation grant.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/delegations/{id}/revoke",
    params(
        ("id" = Uuid, Path, description = "Delegation grant ID"),
    ),
    request_body = RevokeRequest,
    responses(
        (status = 200, description = "Grant revoked", body = RevokeResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    tag = "NHI Delegation"
))]
pub async fn revoke_delegation_grant(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(_request): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    // SECURITY: Always set revoked_by from the authenticated caller.
    let caller_id = Uuid::parse_str(&claims.sub).ok();

    // Load the grant before revoking so we have the data for the event
    #[cfg(feature = "kafka")]
    let grant_before = NhiDelegationGrant::find_by_id(&state.pool, tenant_uuid, id).await?;

    let revoked = NhiDelegationGrant::revoke(&state.pool, tenant_uuid, id, caller_id).await?;

    // Emit Kafka event (fire-and-forget)
    #[cfg(feature = "kafka")]
    if revoked {
        if let Some(grant) = grant_before {
            emit_grant_revoked_event(&state, tenant_uuid, &grant, caller_id).await;
        }
    }

    Ok(Json(RevokeResponse { revoked }))
}

/// GET /nhi/:id/delegations/incoming -- List grants where this NHI is the actor.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/{id}/delegations/incoming",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID (actor)"),
    ),
    responses(
        (status = 200, description = "Incoming delegation grants", body = PaginatedDelegationResponse),
        (status = 403, description = "Forbidden"),
    ),
    tag = "NHI Delegation"
))]
pub async fn list_incoming_delegations(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Query(query): Query<ListDelegationsQuery>,
) -> Result<Json<PaginatedDelegationResponse>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let data =
        NhiDelegationGrant::list_by_actor(&state.pool, tenant_uuid, nhi_id, limit, offset).await?;

    Ok(Json(PaginatedDelegationResponse {
        data,
        limit,
        offset,
    }))
}

/// GET /nhi/:id/delegations/outgoing -- List grants where this NHI is the principal.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/{id}/delegations/outgoing",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID (principal)"),
    ),
    responses(
        (status = 200, description = "Outgoing delegation grants", body = PaginatedDelegationResponse),
        (status = 403, description = "Forbidden"),
    ),
    tag = "NHI Delegation"
))]
pub async fn list_outgoing_delegations(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Query(query): Query<ListDelegationsQuery>,
) -> Result<Json<PaginatedDelegationResponse>, NhiApiError> {
    if !claims.has_role("admin") && !claims.has_role("super_admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let data =
        NhiDelegationGrant::list_by_principal(&state.pool, tenant_uuid, nhi_id, limit, offset)
            .await?;

    Ok(Json(PaginatedDelegationResponse {
        data,
        limit,
        offset,
    }))
}

// ---------------------------------------------------------------------------
// Event emission (fire-and-forget, following codebase pattern)
// ---------------------------------------------------------------------------

#[cfg(feature = "kafka")]
async fn emit_grant_created_event(state: &NhiState, tenant_id: Uuid, grant: &NhiDelegationGrant) {
    if let Some(ref producer) = state.event_producer {
        let event = xavyo_events::events::nhi_delegation::NhiDelegationGrantCreated {
            grant_id: grant.id,
            tenant_id,
            principal_id: grant.principal_id,
            principal_type: grant.principal_type.clone(),
            actor_nhi_id: grant.actor_nhi_id,
            allowed_scopes: grant.allowed_scopes.clone(),
            allowed_resource_types: grant.allowed_resource_types.clone(),
            max_delegation_depth: grant.max_delegation_depth,
            expires_at: grant.expires_at,
            granted_by: grant.granted_by,
            created_at: grant.created_at,
        };
        if let Err(e) = producer.publish(event, tenant_id, grant.granted_by).await {
            tracing::warn!(error = %e, "Failed to publish NhiDelegationGrantCreated event");
        }
    }
}

#[cfg(feature = "kafka")]
async fn emit_grant_revoked_event(
    state: &NhiState,
    tenant_id: Uuid,
    grant: &NhiDelegationGrant,
    revoked_by: Option<Uuid>,
) {
    if let Some(ref producer) = state.event_producer {
        let event = xavyo_events::events::nhi_delegation::NhiDelegationGrantRevoked {
            grant_id: grant.id,
            tenant_id,
            principal_id: grant.principal_id,
            actor_nhi_id: grant.actor_nhi_id,
            revoked_by,
            revoked_at: chrono::Utc::now(),
        };
        if let Err(e) = producer.publish(event, tenant_id, revoked_by).await {
            tracing::warn!(error = %e, "Failed to publish NhiDelegationGrantRevoked event");
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn nhi_delegation_routes(state: NhiState) -> Router {
    Router::new()
        .route("/delegations", post(create_delegation_grant))
        .route("/delegations", get(list_delegation_grants))
        .route("/delegations/:id", get(get_delegation_grant))
        .route("/delegations/:id/revoke", post(revoke_delegation_grant))
        .route("/:id/delegations/incoming", get(list_incoming_delegations))
        .route("/:id/delegations/outgoing", get(list_outgoing_delegations))
        .with_state(state)
}
