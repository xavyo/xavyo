//! IdP Certificate admin handlers

use crate::error::SamlResult;
use crate::handlers::metadata::SamlState;
use crate::models::CertificateListResponse;
use crate::services::SpService;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::models::{CertificateInfo, UploadCertificateRequest};

/// List all IdP certificates
#[utoipa::path(
    get,
    path = "/admin/saml/certificates",
    responses(
        (status = 200, description = "List of certificates", body = CertificateListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML Admin"
)]
pub async fn list_certificates(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
) -> impl IntoResponse {
    match list_certificates_inner(&state, *tenant_id.as_uuid()).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn list_certificates_inner(
    state: &SamlState,
    tenant_id: Uuid,
) -> SamlResult<CertificateListResponse> {
    let sp_service = SpService::new(state.pool.clone());
    let certs = sp_service.list_certificates(tenant_id).await?;

    Ok(CertificateListResponse {
        items: certs.into_iter().map(CertificateInfo::from).collect(),
    })
}

/// Upload a new IdP certificate
#[utoipa::path(
    post,
    path = "/admin/saml/certificates",
    responses(
        (status = 201, description = "Certificate uploaded"),
        (status = 400, description = "Invalid certificate"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML Admin"
)]
pub async fn upload_certificate(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Json(req): Json<UploadCertificateRequest>,
) -> impl IntoResponse {
    let sp_service = SpService::new(state.pool.clone());

    match sp_service
        .upload_certificate(*tenant_id.as_uuid(), req, state.encryption_key.as_ref())
        .await
    {
        Ok(cert) => (StatusCode::CREATED, Json(CertificateInfo::from(cert))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Activate a certificate for signing
#[utoipa::path(
    post,
    path = "/admin/saml/certificates/{cert_id}/activate",
    params(
        ("cert_id" = Uuid, Path, description = "Certificate ID"),
    ),
    responses(
        (status = 200, description = "Certificate activated"),
        (status = 404, description = "Certificate not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML Admin"
)]
pub async fn activate_certificate(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(cert_id): Path<Uuid>,
) -> impl IntoResponse {
    let sp_service = SpService::new(state.pool.clone());

    match sp_service
        .activate_certificate(*tenant_id.as_uuid(), cert_id)
        .await
    {
        Ok(cert) => (StatusCode::OK, Json(CertificateInfo::from(cert))).into_response(),
        Err(e) => e.into_response(),
    }
}
