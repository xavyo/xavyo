//! Certificate Authority handlers for CA management (F127).
//!
//! Implements:
//! - POST /certificate-authorities/internal - Create internal CA
//! - POST /certificate-authorities/external - Create external CA
//! - GET /certificate-authorities - List CAs
//! - GET /certificate-authorities/{ca_id} - Get CA details
//! - PATCH /certificate-authorities/{ca_id} - Update CA
//! - DELETE /certificate-authorities/{ca_id} - Delete CA
//! - POST /certificate-authorities/{ca_id}/default - Set as default CA
//! - GET /pki/ca-chain/{ca_id} - Get CA chain

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::router::AgentsState;
use crate::services::ca_service::{
    CreateExternalCaRequest, CreateInternalCaRequest, UpdateCaRequest,
};
use xavyo_auth::JwtClaims;
use xavyo_db::models::certificate_authority::CertificateAuthorityFilter;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Query parameters for listing CAs.
#[derive(Debug, Deserialize)]
pub struct ListCasQuery {
    /// Filter by CA type (internal, `step_ca`, `vault_pki`).
    #[serde(default)]
    pub ca_type: Option<String>,
    /// Filter by active status.
    #[serde(default)]
    pub active_only: Option<bool>,
    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// POST /certificate-authorities/internal - Create an internal CA.
///
/// Creates a new internal CA with a self-signed certificate and private key.
/// The private key is encrypted and stored securely.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/certificate-authorities/internal",
    tag = "Certificate Authorities",
    operation_id = "createInternalCa",
    request_body = CreateInternalCaRequest,
    responses(
        (status = 201, description = "Internal CA created successfully", body = CaResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "CA with this name already exists")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_internal_ca(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateInternalCaRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let ca = state
        .ca_service
        .create_internal_ca(tenant_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(ca)))
}

/// POST /certificate-authorities/external - Create an external CA.
///
/// Registers an external CA (step-ca or Vault PKI) for certificate signing.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/certificate-authorities/external",
    tag = "Certificate Authorities",
    operation_id = "createExternalCa",
    request_body = CreateExternalCaRequest,
    responses(
        (status = 201, description = "External CA registered successfully", body = CaResponse),
        (status = 400, description = "Invalid request or unsupported CA type"),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "CA with this name already exists")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_external_ca(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateExternalCaRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let ca = state
        .ca_service
        .create_external_ca(tenant_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(ca)))
}

/// GET /certificate-authorities - List all CAs.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/certificate-authorities",
    tag = "Certificate Authorities",
    operation_id = "listCas",
    params(
        ("ca_type" = Option<String>, Query, description = "Filter by CA type"),
        ("active_only" = Option<bool>, Query, description = "Only show active CAs"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Pagination offset")
    ),
    responses(
        (status = 200, description = "List of CAs", body = CaListResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_cas(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCasQuery>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let filter = CertificateAuthorityFilter {
        is_active: query.active_only,
        ..Default::default()
    };

    let response = state
        .ca_service
        .list_cas(tenant_id, filter, query.limit, query.offset)
        .await?;

    Ok(Json(response))
}

/// GET /certificate-authorities/{ca_id} - Get a specific CA.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/certificate-authorities/{ca_id}",
    tag = "Certificate Authorities",
    operation_id = "getCa",
    params(
        ("ca_id" = Uuid, Path, description = "Certificate Authority ID")
    ),
    responses(
        (status = 200, description = "CA details", body = CaResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "CA not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_ca(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(ca_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let ca = state.ca_service.get_ca(tenant_id, ca_id).await?;

    Ok(Json(ca))
}

/// PATCH /certificate-authorities/{ca_id} - Update a CA.
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/certificate-authorities/{ca_id}",
    tag = "Certificate Authorities",
    operation_id = "updateCa",
    params(
        ("ca_id" = Uuid, Path, description = "Certificate Authority ID")
    ),
    request_body = UpdateCaRequest,
    responses(
        (status = 200, description = "CA updated successfully", body = CaResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "CA not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn update_ca(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(ca_id): Path<Uuid>,
    Json(request): Json<UpdateCaRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let ca = state
        .ca_service
        .update_ca(tenant_id, ca_id, request)
        .await?;

    Ok(Json(ca))
}

/// DELETE /certificate-authorities/{ca_id} - Delete a CA.
///
/// Soft-deletes a CA. CAs with active certificates cannot be deleted.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/certificate-authorities/{ca_id}",
    tag = "Certificate Authorities",
    operation_id = "deleteCa",
    params(
        ("ca_id" = Uuid, Path, description = "Certificate Authority ID")
    ),
    responses(
        (status = 204, description = "CA deleted successfully"),
        (status = 400, description = "CA has active certificates"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "CA not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn delete_ca(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(ca_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    state.ca_service.delete_ca(tenant_id, ca_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /certificate-authorities/{ca_id}/default - Set a CA as the default.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/certificate-authorities/{ca_id}/default",
    tag = "Certificate Authorities",
    operation_id = "setDefaultCa",
    params(
        ("ca_id" = Uuid, Path, description = "Certificate Authority ID")
    ),
    responses(
        (status = 200, description = "CA set as default", body = CaResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "CA is not active"),
        (status = 404, description = "CA not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn set_default_ca(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(ca_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let ca = state.ca_service.set_default_ca(tenant_id, ca_id).await?;

    Ok(Json(ca))
}

/// GET /pki/ca-chain/{ca_id} - Get the CA certificate chain.
///
/// Returns the CA certificate chain in PEM format for trust store configuration.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/pki/ca-chain/{ca_id}",
    tag = "PKI",
    operation_id = "getCaChain",
    params(
        ("ca_id" = Uuid, Path, description = "Certificate Authority ID")
    ),
    responses(
        (status = 200, description = "CA chain in PEM format", body = CaChainResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "CA not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_ca_chain(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(ca_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let ca = state.ca_service.get_ca(tenant_id, ca_id).await?;

    // Get CA from database to access chain_pem
    let ca_record = xavyo_db::models::certificate_authority::CertificateAuthority::find_by_id(
        &state.pool,
        tenant_id,
        ca_id,
    )
    .await
    .map_err(ApiAgentsError::Database)?
    .ok_or_else(|| ApiAgentsError::CaNotFoundId(ca_id))?;

    // Use chain_pem if available, otherwise fall back to certificate_pem
    // (for internal CAs, the CA certificate itself is the trust anchor)
    let chain_pem = ca_record
        .chain_pem
        .unwrap_or_else(|| ca_record.certificate_pem.clone());

    Ok(Json(CaChainResponse {
        ca_id: ca.id,
        name: ca.name,
        chain_pem,
        subject_dn: ca.subject_dn,
    }))
}

/// CA chain response.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CaChainResponse {
    /// CA ID.
    pub ca_id: Uuid,
    /// CA name.
    pub name: String,
    /// Certificate chain in PEM format.
    pub chain_pem: String,
    /// CA subject DN.
    pub subject_dn: String,
}
