//! Revocation handlers for CRL and OCSP operations (F127).
//!
//! Implements:
//! - GET /`pki/crl/{ca_id`} - Get CRL for a CA
//! - POST /`pki/ocsp/{ca_id`} - OCSP responder endpoint

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::router::AgentsState;
use crate::services::revocation_service::OcspRequest;
use xavyo_auth::JwtClaims;

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

/// GET /`pki/crl/{ca_id`} - Get CRL for a CA.
///
/// Returns a Certificate Revocation List containing all revoked certificates
/// for the specified Certificate Authority.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/pki/crl/{ca_id}",
    tag = "PKI",
    operation_id = "getCrl",
    params(
        ("ca_id" = Uuid, Path, description = "Certificate Authority ID")
    ),
    responses(
        (status = 200, description = "CRL generated successfully", body = CrlResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "CA not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_crl(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(ca_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let crl = state
        .revocation_service
        .generate_crl(tenant_id, ca_id)
        .await?;

    Ok(Json(crl))
}

/// POST /`pki/ocsp/{ca_id`} - OCSP responder endpoint.
///
/// Checks the revocation status of a certificate using the Online Certificate
/// Status Protocol (OCSP).
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/pki/ocsp/{ca_id}",
    tag = "PKI",
    operation_id = "ocspResponder",
    params(
        ("ca_id" = Uuid, Path, description = "Certificate Authority ID")
    ),
    request_body = OcspRequest,
    responses(
        (status = 200, description = "OCSP response", body = OcspResponse),
        (status = 400, description = "Invalid OCSP request"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "CA not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn ocsp_responder(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(ca_id): Path<Uuid>,
    Json(request): Json<OcspRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .revocation_service
        .handle_ocsp(tenant_id, ca_id, request)
        .await?;

    Ok(Json(response))
}
