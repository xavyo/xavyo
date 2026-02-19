//! SAML SSO handlers for SP-initiated SSO

use crate::error::{SamlError, SamlResult};
use crate::handlers::metadata::SamlState;
use crate::models::group_config::GroupAttributeConfig;
use crate::models::{generate_auto_submit_form, SsoPostForm, SsoRedirectQuery};
use crate::saml::UserAttributes;
use crate::services::{
    AssertionBuilder, GroupService, RequestParser, SignatureValidator, SpService,
};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
    Extension, Form,
};
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::models::User;

/// Signature information for HTTP-Redirect binding
pub struct RedirectSignatureInfo<'a> {
    pub saml_request: &'a str,
    pub relay_state: Option<&'a str>,
    pub sig_alg: Option<&'a str>,
    pub signature: Option<&'a str>,
}

/// SP-initiated SSO via HTTP-Redirect binding
#[utoipa::path(
    get,
    path = "/saml/sso",
    params(SsoRedirectQuery),
    responses(
        (status = 200, description = "SAML Response form"),
        (status = 400, description = "Invalid SAML request"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Service provider not found"),
    ),
    tag = "SAML"
)]
pub async fn sso_redirect(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user): Extension<Option<User>>,
    Query(query): Query<SsoRedirectQuery>,
) -> Response {
    let sig_info = RedirectSignatureInfo {
        saml_request: &query.saml_request,
        relay_state: query.relay_state.as_deref(),
        sig_alg: query.sig_alg.as_deref(),
        signature: query.signature.as_deref(),
    };
    match handle_sso(
        &state,
        *tenant_id.as_uuid(),
        user,
        &query.saml_request,
        query.relay_state.as_deref(),
        BindingType::Redirect(sig_info),
    )
    .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!(error = %e, "SSO redirect failed");
            e.into_response()
        }
    }
}

/// SP-initiated SSO via HTTP-POST binding
#[utoipa::path(
    post,
    path = "/saml/sso",
    request_body = SsoPostForm,
    responses(
        (status = 200, description = "SAML Response form"),
        (status = 400, description = "Invalid SAML request"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Service provider not found"),
    ),
    tag = "SAML"
)]
pub async fn sso_post(
    State(state): State<SamlState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user): Extension<Option<User>>,
    Form(form): Form<SsoPostForm>,
) -> Response {
    match handle_sso(
        &state,
        *tenant_id.as_uuid(),
        user,
        &form.saml_request,
        form.relay_state.as_deref(),
        BindingType::Post,
    )
    .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!(error = %e, "SSO POST failed");
            e.into_response()
        }
    }
}

/// SAML binding type with signature info
pub enum BindingType<'a> {
    Redirect(RedirectSignatureInfo<'a>),
    Post,
}

/// Normalize a URL for comparison (lowercase scheme/host, strip trailing slash)
fn normalize_url(url_str: &str) -> SamlResult<String> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| SamlError::InvalidAuthnRequest(format!("Invalid ACS URL format: {e}")))?;

    let mut normalized = format!(
        "{}://{}",
        parsed.scheme().to_lowercase(),
        parsed.host_str().unwrap_or("").to_lowercase()
    );

    if let Some(port) = parsed.port() {
        normalized.push(':');
        normalized.push_str(&format!("{}", port));
    }

    let path = parsed.path().trim_end_matches('/');
    normalized.push_str(path);

    if let Some(query) = parsed.query() {
        normalized.push('?');
        normalized.push_str(query);
    }

    Ok(normalized)
}

/// Check if an ACS URL matches any of the configured URLs (after normalization)
fn acs_url_matches(acs_url: &str, configured_urls: &[String]) -> SamlResult<bool> {
    let normalized_acs = normalize_url(acs_url)?;

    for configured in configured_urls {
        if let Ok(normalized_configured) = normalize_url(configured) {
            if normalized_acs == normalized_configured {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Handle SSO request (shared logic for both bindings)
async fn handle_sso<'a>(
    state: &SamlState,
    tenant_id: Uuid,
    user: Option<User>,
    saml_request: &str,
    relay_state: Option<&str>,
    binding_type: BindingType<'a>,
) -> SamlResult<Response> {
    // Parse the AuthnRequest
    let (authn_request, decoded_xml) = match &binding_type {
        BindingType::Redirect(_) => {
            let req = RequestParser::parse_redirect(saml_request)?;
            (req, None) // For redirect, we don't need decoded XML for signature validation
        }
        BindingType::Post => {
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, saml_request)
                    .map_err(|e| {
                        SamlError::InvalidAuthnRequest(format!("Base64 decode failed: {e}"))
                    })?;
            let xml = String::from_utf8(decoded)
                .map_err(|e| SamlError::InvalidAuthnRequest(format!("Invalid UTF-8: {e}")))?;
            let req = RequestParser::parse_post(saml_request)?;
            (req, Some(xml))
        }
    };

    tracing::info!(
        tenant_id = %tenant_id,
        sp_entity_id = %authn_request.issuer,
        request_id = %authn_request.id,
        "SAML AuthnRequest received"
    );

    // Look up the SP
    let sp_service = SpService::new(state.pool.clone());
    let sp = sp_service
        .get_sp_by_entity_id(tenant_id, &authn_request.issuer)
        .await?;

    // Check if SP is enabled
    if !sp.enabled {
        return Err(SamlError::DisabledServiceProvider(sp.entity_id));
    }

    // Validate signature if required
    if sp.validate_signatures {
        let sp_cert = sp.certificate.as_ref().ok_or_else(|| {
            SamlError::SignatureValidationFailed(
                "Signature validation required but no SP certificate configured".to_string(),
            )
        })?;

        match &binding_type {
            BindingType::Redirect(sig_info) => {
                // For HTTP-Redirect, signature is in query parameters
                let sig_alg = sig_info.sig_alg.ok_or_else(|| {
                    SamlError::SignatureValidationFailed(
                        "Signature validation required but no SigAlg provided".to_string(),
                    )
                })?;
                let signature = sig_info.signature.ok_or_else(|| {
                    SamlError::SignatureValidationFailed(
                        "Signature validation required but no Signature provided".to_string(),
                    )
                })?;

                SignatureValidator::validate_redirect_signature(
                    sig_info.saml_request,
                    sig_info.relay_state,
                    sig_alg,
                    signature,
                    sp_cert,
                )?;

                tracing::debug!(
                    tenant_id = %tenant_id,
                    sp_entity_id = %sp.entity_id,
                    "AuthnRequest signature validated (HTTP-Redirect)"
                );
            }
            BindingType::Post => {
                // For HTTP-POST, signature is embedded in XML.
                // SECURITY: Require decoded_xml — never silently skip validation.
                let xml = decoded_xml.as_ref().ok_or_else(|| {
                    SamlError::SignatureValidationFailed(
                        "Missing decoded XML for POST binding signature validation".to_string(),
                    )
                })?;
                SignatureValidator::validate_post_signature(xml, sp_cert)?;
                tracing::debug!(
                    tenant_id = %tenant_id,
                    sp_entity_id = %sp.entity_id,
                    "AuthnRequest signature validated (HTTP-POST)"
                );
            }
        }
    }

    // SECURITY: Validate RelayState length.
    // SAML spec recommends 80 bytes but many SPs use longer values.
    // Cap at 1024 bytes to prevent abuse while remaining compatible.
    if let Some(rs) = relay_state {
        if rs.len() > 1024 {
            return Err(SamlError::InvalidAuthnRequest(
                "RelayState exceeds maximum length (1024 bytes)".to_string(),
            ));
        }
    }

    // Validate ACS URL if provided in request
    if let Some(ref acs_url) = authn_request.assertion_consumer_service_url {
        // Normalize and compare URLs to avoid case-sensitivity and trailing slash issues
        if !acs_url_matches(acs_url, &sp.acs_urls)? {
            return Err(SamlError::AcsUrlMismatch {
                expected: sp.acs_urls.clone(),
                actual: acs_url.clone(),
            });
        }
    }

    // Check if user is authenticated
    let user = if let Some(u) = user {
        u
    } else {
        // User not authenticated - would redirect to login
        // For now, return unauthorized
        // TODO: In a full implementation, store the AuthnRequest in session
        // and redirect to login, then resume SSO after authentication
        tracing::info!(
            tenant_id = %tenant_id,
            sp_entity_id = %sp.entity_id,
            "User not authenticated, SSO requires login"
        );
        return Err(SamlError::NotAuthenticated);
    };

    // Build user attributes
    // Note: User model doesn't have display_name, derive from email
    let display_name = user.email.split('@').next().map(String::from);

    // Load user groups with SP-specific configuration
    let sp_group_config = sp.get_group_config();
    let group_config = GroupAttributeConfig {
        attribute_name: sp_group_config.attribute_name,
        value_format: crate::models::group_config::GroupValueFormat::parse(
            &sp_group_config.value_format,
        ),
        filter: sp_group_config
            .filter
            .map(|f| crate::models::group_config::GroupFilter {
                filter_type: match f.filter_type.as_str() {
                    "pattern" => crate::models::group_config::GroupFilterType::Pattern,
                    "allowlist" => crate::models::group_config::GroupFilterType::Allowlist,
                    _ => crate::models::group_config::GroupFilterType::None,
                },
                patterns: f.patterns,
                allowlist: f.allowlist,
            }),
        include_groups: sp_group_config.include_groups,
        omit_empty_groups: sp_group_config.omit_empty_groups,
        dn_base: sp_group_config.dn_base,
    };

    let groups =
        GroupService::load_groups_for_assertion(&state.pool, tenant_id, user.id, &group_config)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    user_id = %user.id,
                    error = %e,
                    "Failed to load user groups, continuing without groups"
                );
                vec![]
            });

    let user_attrs = UserAttributes {
        user_id: user.id.to_string(),
        email: user.email.clone(),
        display_name,
        groups,
        tenant_id: tenant_id.to_string(),
    };

    // Get IdP signing credentials
    let cert = sp_service.get_active_certificate(tenant_id).await?;
    let key_pem = sp_service
        .decrypt_private_key(&cert.private_key_encrypted, state.encryption_key.as_ref())?;
    let credentials = crate::saml::SigningCredentials::from_pem(&cert.certificate, &key_pem)?;

    // Build entity ID
    let idp_entity_id = format!("{}/saml/metadata?tenant={}", state.base_url, tenant_id);

    // Build SAML Response
    let builder = AssertionBuilder::new(idp_entity_id, credentials);
    let saml_response = builder.build_response(
        &sp,
        &user_attrs,
        Some(&authn_request.id),
        None, // session_id - could be user session
    )?;

    // Get ACS URL (prefer request, fall back to first configured)
    let acs_url = authn_request
        .assertion_consumer_service_url
        .as_deref()
        .unwrap_or_else(|| sp.acs_urls.first().map_or("", std::string::String::as_str));

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user.id,
        sp_entity_id = %sp.entity_id,
        acs_url = %acs_url,
        "SAML Response generated"
    );

    // Return auto-submit form
    let html = generate_auto_submit_form(acs_url, &saml_response, relay_state);

    Ok(Html(html).into_response())
}
