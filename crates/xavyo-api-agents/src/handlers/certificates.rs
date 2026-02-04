//! Certificate handlers for Agent PKI & Certificate Issuance (F127).
//!
//! Implements certificate CRUD operations:
//! - POST /`agents/{agent_id}/certificates` - Issue a new certificate
//! - GET /`agents/{agent_id}/certificates` - List certificates for an agent
//! - GET /`agents/{agent_id}/certificates/{cert_id`} - Get specific certificate
//! - POST /`agents/{agent_id}/certificates/{cert_id}/renew` - Renew certificate
//! - POST /`agents/{agent_id}/certificates/{cert_id}/revoke` - Revoke certificate
//! - GET /certificates - List all certificates (admin)
//! - GET /`certificates/{cert_id`} - Get certificate by ID (admin)
//! - GET /certificates/expiring - List expiring certificates

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
use crate::services::certificate_service::RenewCertificateRequest;
use xavyo_auth::JwtClaims;
use xavyo_db::models::agent_certificate::{AgentCertificateFilter, IssueCertificateRequest};

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// Extract `user_id` from JWT claims.
fn extract_user_id(claims: &JwtClaims) -> Option<Uuid> {
    claims.sub.parse().ok()
}

/// Query parameters for listing certificates.
#[derive(Debug, Deserialize)]
pub struct ListCertificatesQuery {
    /// Filter by CA ID.
    #[serde(default)]
    pub ca_id: Option<Uuid>,
    /// Filter by status (active, revoked, expired).
    #[serde(default)]
    pub status: Option<String>,
    /// Filter certificates expiring within N days.
    #[serde(default)]
    pub expiring_within_days: Option<i32>,
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

/// Query parameters for listing expiring certificates.
#[derive(Debug, Deserialize)]
pub struct ExpiringCertificatesQuery {
    /// List certificates expiring within this many days.
    #[serde(default = "default_expiring_days")]
    pub within_days: i32,
    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_expiring_days() -> i32 {
    30
}

/// POST /`agents/{agent_id}/certificates` - Issue a new certificate for an agent.
///
/// This endpoint issues a new X.509 certificate for the specified AI agent.
/// The certificate and private key are returned only once - the private key
/// is not stored by the system.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{agent_id}/certificates",
    tag = "Certificates",
    operation_id = "issueCertificate",
    params(
        ("agent_id" = Uuid, Path, description = "AI Agent ID")
    ),
    request_body = IssueCertificateRequest,
    responses(
        (status = 201, description = "Certificate issued successfully", body = IssueCertificateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Agent not active or CA disabled"),
        (status = 404, description = "Agent or CA not found"),
        (status = 500, description = "Certificate issuance failed")
    ),
    security(("bearerAuth" = []))
))]
pub async fn issue_certificate(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<IssueCertificateRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims);

    let response = state
        .certificate_service
        .issue_certificate(tenant_id, agent_id, request, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /`agents/{agent_id}/certificates` - List certificates for an agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{agent_id}/certificates",
    tag = "Certificates",
    operation_id = "listAgentCertificates",
    params(
        ("agent_id" = Uuid, Path, description = "AI Agent ID"),
        ("ca_id" = Option<Uuid>, Query, description = "Filter by CA ID"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Pagination offset")
    ),
    responses(
        (status = 200, description = "List of certificates", body = CertificateListResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_agent_certificates(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<ListCertificatesQuery>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .certificate_service
        .list_certificates_for_agent(tenant_id, agent_id, query.limit, query.offset)
        .await?;

    Ok(Json(response))
}

/// GET /`agents/{agent_id}/certificates/{cert_id`} - Get a specific certificate for an agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/agents/{agent_id}/certificates/{cert_id}",
    tag = "Certificates",
    operation_id = "getAgentCertificate",
    params(
        ("agent_id" = Uuid, Path, description = "AI Agent ID"),
        ("cert_id" = Uuid, Path, description = "Certificate ID")
    ),
    responses(
        (status = 200, description = "Certificate details", body = AgentCertificate),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent or certificate not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_agent_certificate(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, cert_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let certificate = state
        .certificate_service
        .get_certificate_for_agent(tenant_id, agent_id, cert_id)
        .await?;

    Ok(Json(certificate))
}

/// GET /certificates - List all certificates for the tenant (admin view).
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/certificates",
    tag = "Certificates",
    operation_id = "listCertificates",
    params(
        ("agent_id" = Option<Uuid>, Query, description = "Filter by agent ID"),
        ("ca_id" = Option<Uuid>, Query, description = "Filter by CA ID"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("expiring_within_days" = Option<i32>, Query, description = "Filter expiring within days"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Pagination offset")
    ),
    responses(
        (status = 200, description = "List of certificates", body = CertificateListResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_certificates(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCertificatesQueryWithAgent>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let filter = AgentCertificateFilter {
        agent_id: query.agent_id,
        ca_id: query.ca_id,
        status: query.status,
        expiring_within_days: query.expiring_within_days,
    };

    let response = state
        .certificate_service
        .list_certificates(tenant_id, filter, query.limit, query.offset)
        .await?;

    Ok(Json(response))
}

/// Query parameters for listing certificates (admin view with `agent_id` filter).
#[derive(Debug, Deserialize)]
pub struct ListCertificatesQueryWithAgent {
    /// Filter by agent ID.
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    /// Filter by CA ID.
    #[serde(default)]
    pub ca_id: Option<Uuid>,
    /// Filter by status (active, revoked, expired).
    #[serde(default)]
    pub status: Option<String>,
    /// Filter certificates expiring within N days.
    #[serde(default)]
    pub expiring_within_days: Option<i32>,
    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

/// GET /`certificates/{cert_id`} - Get a certificate by ID (admin view).
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/certificates/{cert_id}",
    tag = "Certificates",
    operation_id = "getCertificate",
    params(
        ("cert_id" = Uuid, Path, description = "Certificate ID")
    ),
    responses(
        (status = 200, description = "Certificate details", body = AgentCertificate),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Certificate not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_certificate(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(cert_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let certificate = state
        .certificate_service
        .get_certificate(tenant_id, cert_id)
        .await?;

    Ok(Json(certificate))
}

/// GET /certificates/expiring - List certificates expiring soon.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/certificates/expiring",
    tag = "Certificates",
    operation_id = "listExpiringCertificates",
    params(
        ("within_days" = Option<i32>, Query, description = "Days until expiration (default 30)"),
        ("limit" = Option<i64>, Query, description = "Maximum results")
    ),
    responses(
        (status = 200, description = "List of expiring certificates", body = Vec<AgentCertificate>),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_expiring_certificates(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ExpiringCertificatesQuery>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let certificates = state
        .certificate_service
        .list_expiring_certificates(tenant_id, query.within_days, query.limit)
        .await?;

    Ok(Json(certificates))
}

/// Request to revoke a certificate.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeCertificateRequest {
    /// Reason for revocation. Valid values:
    /// - unspecified (default)
    /// - `key_compromise`
    /// - `ca_compromise`
    /// - `affiliation_changed`
    /// - superseded
    /// - `cessation_of_operation`
    /// - `certificate_hold`
    /// - `remove_from_crl`
    /// - `privilege_withdrawn`
    /// - `aa_compromise`
    pub reason: Option<String>,
}

/// POST /`agents/{agent_id}/certificates/{cert_id}/renew` - Renew a certificate.
///
/// Issues a new certificate with the same identity as the original, extending
/// the validity period. The old certificate remains valid until it expires or
/// is explicitly revoked.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{agent_id}/certificates/{cert_id}/renew",
    tag = "Certificates",
    operation_id = "renewCertificate",
    params(
        ("agent_id" = Uuid, Path, description = "AI Agent ID"),
        ("cert_id" = Uuid, Path, description = "Certificate ID to renew")
    ),
    request_body = RenewCertificateRequest,
    responses(
        (status = 201, description = "Certificate renewed successfully", body = IssueCertificateResponse),
        (status = 400, description = "Invalid request or certificate cannot be renewed"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Certificate is revoked or agent not active"),
        (status = 404, description = "Agent or certificate not found"),
        (status = 500, description = "Certificate renewal failed")
    ),
    security(("bearerAuth" = []))
))]
pub async fn renew_certificate(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, cert_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RenewCertificateRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims);

    let response = state
        .certificate_service
        .renew_certificate(tenant_id, agent_id, cert_id, request, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(response)))
}

/// POST /`agents/{agent_id}/certificates/{cert_id}/revoke` - Revoke a certificate.
///
/// Marks a certificate as revoked. Revoked certificates will be rejected by
/// mTLS validation and included in the Certificate Revocation List (CRL).
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{agent_id}/certificates/{cert_id}/revoke",
    tag = "Certificates",
    operation_id = "revokeCertificate",
    params(
        ("agent_id" = Uuid, Path, description = "AI Agent ID"),
        ("cert_id" = Uuid, Path, description = "Certificate ID to revoke")
    ),
    request_body = RevokeCertificateRequest,
    responses(
        (status = 200, description = "Certificate revoked successfully", body = AgentCertificate),
        (status = 400, description = "Certificate already revoked or invalid reason"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent or certificate not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn revoke_certificate(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path((agent_id, cert_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RevokeCertificateRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let user_id = extract_user_id(&claims);

    let reason = request.reason.as_deref().unwrap_or("unspecified");

    let certificate = state
        .certificate_service
        .revoke_certificate(tenant_id, agent_id, cert_id, reason, user_id)
        .await?;

    Ok(Json(certificate))
}
