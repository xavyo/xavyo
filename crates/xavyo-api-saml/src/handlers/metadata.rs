//! SAML Metadata handler

use crate::error::{SamlError, SamlResult};
use crate::services::{MetadataGenerator, SpService};
use crate::session::{SessionStore, SpSessionStore};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;
use utoipa::IntoParams;
use uuid::Uuid;

/// Application state for SAML handlers
#[derive(Clone)]
pub struct SamlState {
    pub pool: PgPool,
    pub base_url: String,
    pub frontend_url: String,
    pub encryption_key: Arc<[u8; 32]>,
    /// Session store for AuthnRequest replay protection.
    pub session_store: Arc<dyn SessionStore>,
    /// SP session store for tracking active SP sessions (SLO).
    pub sp_session_store: Arc<dyn SpSessionStore>,
}

/// Query parameters for metadata endpoint
#[derive(Debug, Deserialize, IntoParams)]
pub struct MetadataQuery {
    pub tenant: Option<String>,
}

/// Return `IdP` metadata XML
#[utoipa::path(
    get,
    path = "/saml/metadata",
    params(MetadataQuery),
    responses(
        (status = 200, description = "IdP metadata XML"),
        (status = 400, description = "Missing or invalid tenant parameter"),
        (status = 500, description = "Failed to generate metadata"),
    ),
    tag = "SAML"
)]
pub async fn get_metadata(
    State(state): State<SamlState>,
    Query(query): Query<MetadataQuery>,
) -> Response {
    let tenant_id = match query.tenant.as_deref() {
        Some(t) if !t.is_empty() => match Uuid::parse_str(t) {
            Ok(id) => id,
            Err(_) => {
                return SamlError::InvalidAuthnRequest(format!("Invalid tenant ID: {t}"))
                    .into_response()
            }
        },
        _ => {
            return SamlError::InvalidAuthnRequest(
                "Missing required 'tenant' query parameter".to_string(),
            )
            .into_response()
        }
    };

    match get_metadata_inner(&state, tenant_id).await {
        Ok(xml) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
            xml,
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn get_metadata_inner(state: &SamlState, tenant_id: Uuid) -> SamlResult<String> {
    let sp_service = SpService::new(state.pool.clone());

    // Build entity ID and SSO URL from base URL and tenant
    let entity_id = format!("{}/saml/metadata?tenant={}", state.base_url, tenant_id);
    let sso_url = format!("{}/saml/sso?tenant={}", state.base_url, tenant_id);

    // Try to get active certificate for signing info
    let credentials = match sp_service.get_active_certificate(tenant_id).await {
        Ok(cert) => {
            let key_pem = sp_service
                .decrypt_private_key(&cert.private_key_encrypted, state.encryption_key.as_ref())?;
            Some(crate::saml::SigningCredentials::from_pem(
                &cert.certificate,
                &key_pem,
            )?)
        }
        Err(_) => None, // No certificate is OK for metadata, just won't include KeyInfo
    };

    let slo_url = format!("{}/saml/slo?tenant={}", state.base_url, tenant_id);
    let generator = MetadataGenerator::new(entity_id, sso_url, credentials, Some(slo_url));
    let xml = generator.generate()?;

    tracing::info!(
        tenant_id = %tenant_id,
        "SAML metadata requested"
    );

    Ok(xml)
}
