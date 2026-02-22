//! SAML SSO handlers for SP-initiated SSO

use crate::error::{SamlError, SamlResult};
use crate::handlers::metadata::SamlState;
use crate::models::group_config::GroupAttributeConfig;
use crate::models::{generate_auto_submit_form, SsoPostForm, SsoRedirectQuery};
use crate::saml::UserAttributes;
use crate::services::{
    AssertionBuilder, GroupService, RequestParser, SignatureValidator, SpService,
};
use crate::session::AuthnRequestSession;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Extension, Form,
};
use uuid::Uuid;
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
    Extension(user): Extension<Option<User>>,
    Query(query): Query<SsoRedirectQuery>,
) -> Response {
    let tenant_id = match parse_tenant_param(query.tenant.as_deref()) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let sig_info = RedirectSignatureInfo {
        saml_request: &query.saml_request,
        relay_state: query.relay_state.as_deref(),
        sig_alg: query.sig_alg.as_deref(),
        signature: query.signature.as_deref(),
    };
    match handle_sso(
        &state,
        tenant_id,
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
    Extension(user): Extension<Option<User>>,
    Query(query_params): Query<SsoPostTenantQuery>,
    Form(form): Form<SsoPostForm>,
) -> Response {
    let tenant_id = match parse_tenant_param(query_params.tenant.as_deref()) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match handle_sso(
        &state,
        tenant_id,
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

/// Query params for SSO POST (tenant is in URL, form data is the SAML request)
#[derive(Debug, serde::Deserialize)]
pub struct SsoPostTenantQuery {
    pub tenant: Option<String>,
}

/// Parse and validate the tenant query parameter
pub(crate) fn parse_tenant_param(tenant: Option<&str>) -> SamlResult<Uuid> {
    let tenant_str = tenant.ok_or_else(|| {
        SamlError::InvalidAuthnRequest("Missing required 'tenant' query parameter".to_string())
    })?;
    Uuid::parse_str(tenant_str)
        .map_err(|e| SamlError::InvalidAuthnRequest(format!("Invalid tenant ID: {e}")))
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
    // SECURITY (H11): For POST binding, decode base64 once and pass the XML directly
    // to parse_xml to avoid double-decode (parse_post did a second decode).
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
            // Parse the already-decoded XML directly (not the base64-encoded form)
            let req = RequestParser::parse_xml_public(&xml)?;
            (req, Some(xml))
        }
    };

    tracing::info!(
        tenant_id = %tenant_id,
        sp_entity_id = %authn_request.issuer,
        request_id = %authn_request.id,
        "SAML AuthnRequest received"
    );

    // Look up the SP first — fail fast if unknown entity ID.
    // This is done before storing the session to avoid orphan session rows
    // when the SP is unknown or disabled.
    let sp_service = SpService::new(state.pool.clone());
    let sp = sp_service
        .get_sp_by_entity_id(tenant_id, &authn_request.issuer)
        .await?;

    // Check if SP is enabled
    if !sp.enabled {
        return Err(SamlError::DisabledServiceProvider(sp.entity_id));
    }

    // Validate signature if required.
    // SECURITY: If validate_signatures is disabled but a signature IS present,
    // log a warning — the SP may have been misconfigured.
    if !sp.validate_signatures {
        let has_signature = match &binding_type {
            BindingType::Redirect(sig_info) => sig_info.signature.is_some(),
            BindingType::Post => decoded_xml
                .as_ref()
                .is_some_and(|xml| xml.contains("<ds:Signature") || xml.contains("<Signature")),
        };
        if has_signature {
            tracing::warn!(
                tenant_id = %tenant_id,
                sp_entity_id = %sp.entity_id,
                "AuthnRequest contains a signature but validate_signatures is disabled — \
                 consider enabling signature validation for this SP"
            );
        }
    }
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
                SignatureValidator::validate_post_signature(xml, sp_cert, Some(&authn_request.id))?;
                tracing::debug!(
                    tenant_id = %tenant_id,
                    sp_entity_id = %sp.entity_id,
                    "AuthnRequest signature validated (HTTP-POST)"
                );
            }
        }
    }

    // C2: Store the AuthnRequest session for replay protection AFTER validation.
    // Only store sessions for requests from known, enabled SPs with valid signatures.
    // If the same request ID is replayed, session store will reject it as duplicate.
    // Use 10-minute TTL for SP-initiated SSO to allow time for user login.
    let session = AuthnRequestSession::with_ttl(
        tenant_id,
        authn_request.id.clone(),
        authn_request.issuer.clone(),
        relay_state.map(String::from),
        600, // 10 minutes to allow time for login
    );
    let session_id = session.id;
    state.session_store.store(session).await.map_err(|e| {
        tracing::warn!(
            tenant_id = %tenant_id,
            request_id = %authn_request.id,
            error = %e,
            "Failed to store AuthnRequest session (possible replay)"
        );
        SamlError::InvalidAuthnRequest(format!("AuthnRequest session error: {e}"))
    })?;

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
        // User not authenticated — redirect to frontend SAML callback page,
        // which will handle login and then call POST /saml/continue to complete SSO.
        tracing::info!(
            tenant_id = %tenant_id,
            sp_entity_id = %sp.entity_id,
            session_id = %session_id,
            "User not authenticated, redirecting to frontend for login"
        );
        let redirect_url = format!(
            "{}/saml/callback?session_id={}",
            state.frontend_url.trim_end_matches('/'),
            session_id,
        );
        return Ok(Redirect::temporary(&redirect_url).into_response());
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

    // Get ACS URL (prefer request, fall back to first configured).
    // SECURITY: Reject if no ACS URL is available — an empty Destination would cause
    // the auto-submit form to POST the assertion back to the IdP's own SSO endpoint.
    let acs_url = authn_request
        .assertion_consumer_service_url
        .as_deref()
        .or_else(|| sp.acs_urls.first().map(std::string::String::as_str))
        .ok_or_else(|| {
            SamlError::AssertionGenerationFailed(
                "No ACS URL in request and none configured for SP".to_string(),
            )
        })?;

    // Build SAML Response — pass the resolved ACS URL so Destination/Recipient match
    let builder = AssertionBuilder::new(idp_entity_id, credentials);
    let output = builder.build_response(
        &sp,
        &user_attrs,
        Some(&authn_request.id),
        None, // session_id - could be user session
        Some(acs_url),
    )?;

    // Record SP session for SLO tracking
    let sp_session = crate::session::SpSession {
        id: Uuid::new_v4(),
        tenant_id,
        user_id: user.id,
        sp_id: sp.id,
        session_index: output.session_index.clone(),
        name_id: output.name_id.clone(),
        name_id_format: output.name_id_format.clone(),
        created_at: chrono::Utc::now(),
        // SP session lasts longer than the assertion — the assertion validity is how
        // long the SAML response is valid, but the user's SP session typically persists
        // for hours. Use the larger of 8 hours or assertion_validity_seconds.
        expires_at: chrono::Utc::now()
            + chrono::Duration::seconds(i64::from(sp.assertion_validity_seconds).max(28800)),
        revoked_at: None,
    };
    if let Err(e) = state.sp_session_store.record(sp_session).await {
        tracing::warn!(
            tenant_id = %tenant_id,
            user_id = %user.id,
            sp_id = %sp.id,
            error = %e,
            "Failed to record SP session for SLO (non-fatal)"
        );
    }

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user.id,
        sp_entity_id = %sp.entity_id,
        acs_url = %acs_url,
        "SAML Response generated"
    );

    // Return auto-submit form
    let html = generate_auto_submit_form(acs_url, &output.encoded_response, relay_state);

    Ok(Html(html).into_response())
}
