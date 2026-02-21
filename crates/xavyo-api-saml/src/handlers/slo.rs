//! SAML Single Logout handlers

use crate::error::{SamlError, SamlResult};
use crate::handlers::metadata::SamlState;
use crate::services::logout_parser;
use crate::services::signature_validator::SignatureValidator;
use crate::services::slo_service::{SloResult, SloService};
use crate::services::SpService;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Form, Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

/// Form data for incoming SLO POST
#[derive(Debug, Deserialize)]
pub struct SloPostForm {
    /// Base64-encoded SAML LogoutRequest
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    /// RelayState (optional)
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// SP sends LogoutRequest to IdP (back-channel or browser POST)
///
/// POST /saml/slo
#[utoipa::path(
    post,
    path = "/saml/slo",
    request_body = SloPostForm,
    responses(
        (status = 200, description = "LogoutResponse"),
        (status = 400, description = "Invalid LogoutRequest"),
    ),
    tag = "SAML SLO"
)]
pub async fn slo_post(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Form(form): Form<SloPostForm>,
) -> Response {
    match handle_slo_post(&state, *tenant_id.as_uuid(), form).await {
        Ok(response) => response,
        Err(e) => {
            tracing::error!(error = %e, "SLO POST failed");
            e.into_response()
        }
    }
}

async fn handle_slo_post(
    state: &SamlState,
    tenant_id: Uuid,
    form: SloPostForm,
) -> SamlResult<Response> {
    let saml_request_b64 = form.saml_request.ok_or_else(|| {
        SamlError::InvalidLogoutRequest("Missing SAMLRequest parameter".to_string())
    })?;

    // Size check before decode
    if saml_request_b64.len() > 512 * 1024 {
        return Err(SamlError::InvalidLogoutRequest(
            "LogoutRequest too large".to_string(),
        ));
    }

    // Base64 decode to get raw XML (needed for signature validation)
    let decoded_bytes = STANDARD
        .decode(&saml_request_b64)
        .map_err(|e| SamlError::InvalidLogoutRequest(format!("Base64 decode failed: {e}")))?;
    let xml = String::from_utf8(decoded_bytes)
        .map_err(|e| SamlError::InvalidLogoutRequest(format!("Invalid UTF-8: {e}")))?;

    // Parse the LogoutRequest XML
    let parsed = logout_parser::parse_logout_request_xml(&xml)?;

    tracing::info!(
        tenant_id = %tenant_id,
        issuer = %parsed.issuer,
        request_id = %parsed.id,
        "SAML LogoutRequest received"
    );

    // Look up the SP by issuer to get certificate and validate_signatures flag
    let sp_service = SpService::new(state.pool.clone());
    let sp = sp_service
        .get_sp_by_entity_id(tenant_id, &parsed.issuer)
        .await?;

    if !sp.enabled {
        return Err(SamlError::DisabledServiceProvider(sp.entity_id.clone()));
    }

    // SECURITY: Validate LogoutRequest signature if SP requires it
    if sp.validate_signatures {
        let sp_cert = sp.certificate.as_deref().ok_or_else(|| {
            SamlError::SignatureValidationFailed(
                "SP requires signature validation but has no certificate configured".to_string(),
            )
        })?;
        SignatureValidator::validate_post_signature(&xml, sp_cert, Some(&parsed.id))?;
        tracing::debug!(
            sp_entity_id = %sp.entity_id,
            "LogoutRequest signature validated"
        );
    } else if xml.contains("<ds:Signature") || xml.contains("<Signature") {
        tracing::warn!(
            sp_entity_id = %sp.entity_id,
            "LogoutRequest contains signature but SP has validate_signatures=false"
        );
    }

    // Process the logout (SP already looked up, pass sp_id directly)
    let slo_service = SloService::new(state.pool.clone());
    let result = slo_service
        .process_sp_logout_for_sp(state, tenant_id, &sp, &parsed)
        .await?;

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %result.user_id,
        "SP-initiated SLO completed"
    );

    // Return the LogoutResponse as form-encoded body for back-channel.
    // SECURITY: URL-encode the base64 value (base64 contains +/= which are
    // significant in form encoding).
    Ok((
        StatusCode::OK,
        [(
            "content-type",
            "application/x-www-form-urlencoded; charset=UTF-8",
        )],
        format!("SAMLResponse={}", urlencoding::encode(&result.response_xml)),
    )
        .into_response())
}

/// IdP-initiated SLO: authenticated user triggers logout of all SPs
///
/// POST /saml/slo/initiate
#[utoipa::path(
    post,
    path = "/saml/slo/initiate",
    responses(
        (status = 200, description = "SLO dispatch result", body = SloResult),
        (status = 401, description = "Not authenticated"),
    ),
    security(("bearerAuth" = [])),
    tag = "SAML SLO"
)]
pub async fn slo_initiate(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<Json<SloResult>, SamlError> {
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| SamlError::NotAuthenticated)?;
    let tid = *tenant_id.as_uuid();

    tracing::info!(
        tenant_id = %tid,
        user_id = %user_id,
        "IdP-initiated SLO requested"
    );

    let slo_service = SloService::new(state.pool.clone());
    let result = slo_service
        .dispatch_logout_to_sps(&state, tid, user_id)
        .await?;

    Ok(Json(result))
}
