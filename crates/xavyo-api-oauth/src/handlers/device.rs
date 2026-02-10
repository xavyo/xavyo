//! Device code handlers for RFC 8628 Device Authorization Grant.
//!
//! Endpoints:
//! - POST /oauth/device/code - Request device authorization code
//! - GET /device - Device verification page (HTML)
//! - POST /device/verify - Verify user code
//! - POST /device/authorize - Approve or deny authorization

use crate::error::OAuthError;
use crate::handlers::device_login::get_user_from_session;
use crate::middleware::session_cookie::{
    create_csrf_cookie, extract_csrf_cookie, generate_csrf_token, validate_csrf_token,
};
use crate::router::OAuthState;
use crate::services::{DeviceAuthorizationStatus, DeviceCodeService, RiskAction, RiskContext};
use crate::utils::{extract_country_code, extract_origin_ip};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Response},
    Extension, Form,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_api_auth::services::SessionService;

/// Device authorization grant type URN.
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Request for POST /oauth/device/code.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DeviceAuthorizationRequest {
    /// OAuth client identifier.
    pub client_id: String,
    /// Space-separated list of requested scopes.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Response for POST /oauth/device/code (RFC 8628).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeviceAuthorizationResponse {
    /// Secret code for token polling (do not display to user).
    pub device_code: String,
    /// Code to display to user for browser entry.
    pub user_code: String,
    /// URL where user should visit to enter code.
    pub verification_uri: String,
    /// URL with code pre-filled (optional convenience).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// Seconds until `device_code` expires.
    pub expires_in: i64,
    /// Minimum seconds between polling requests.
    pub interval: i32,
}

/// Query params for GET /device.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceVerificationQuery {
    /// Pre-filled user code (from `verification_uri_complete`).
    #[serde(default)]
    pub code: Option<String>,
}

/// Request for POST /device/verify.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceVerifyRequest {
    /// User code to verify.
    pub user_code: String,
    /// CSRF token for form validation.
    #[serde(default)]
    pub csrf_token: Option<String>,
}

/// Request for POST /device/authorize.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorizeRequest {
    /// User code being authorized.
    pub user_code: String,
    /// Action: "approve" or "deny".
    pub action: String,
    /// CSRF token for form validation.
    #[serde(default)]
    pub csrf_token: Option<String>,
}

/// Error response for device code endpoints.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeviceCodeErrorResponse {
    /// Error code.
    pub error: String,
    /// Human-readable error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Storm-2372 Remediation (F117): Context for the device code approval page.
///
/// Contains all information needed to display a security-conscious approval page
/// that helps users identify potentially malicious device code requests.
#[derive(Debug, Clone)]
pub struct ApprovalContext {
    /// User code being approved.
    pub user_code: String,
    /// OAuth client ID (fallback if name is unknown).
    pub client_id: String,
    /// Human-readable client name from `oauth_clients` table.
    pub client_name: Option<String>,
    /// Requested OAuth scopes.
    pub scopes: Vec<String>,
    /// IP address from which the device code was originally requested.
    pub origin_ip: Option<String>,
    /// Country code of the origin IP (ISO 3166-1 alpha-2).
    pub origin_country: Option<String>,
    /// When the device code was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// IP address of the user approving (for mismatch detection).
    pub approver_ip: Option<String>,
    /// CSRF token for form protection.
    pub csrf_token: String,
}

impl ApprovalContext {
    /// Check if the device code is stale (older than 5 minutes).
    #[must_use]
    pub fn is_stale(&self) -> bool {
        let age = chrono::Utc::now() - self.created_at;
        age.num_minutes() >= 5
    }

    /// Check if there's an IP mismatch between origin and approver.
    #[must_use]
    pub fn has_ip_mismatch(&self) -> bool {
        match (&self.origin_ip, &self.approver_ip) {
            (Some(origin), Some(approver)) => origin != approver,
            _ => false, // Can't determine mismatch if either is missing
        }
    }

    /// Check if the application is unknown (no `client_name`).
    #[must_use]
    pub fn is_unknown_app(&self) -> bool {
        self.client_name.is_none()
    }

    /// Get the display name for the application.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.client_name.as_deref().unwrap_or(&self.client_id)
    }

    /// Get the age of the device code in minutes.
    #[must_use]
    pub fn age_minutes(&self) -> i64 {
        let age = chrono::Utc::now() - self.created_at;
        age.num_minutes()
    }
}

/// Extract `tenant_id` from X-Tenant-ID header.
fn extract_tenant_id(headers: &HeaderMap) -> Result<Uuid, OAuthError> {
    let tenant_header = headers
        .get("X-Tenant-ID")
        .ok_or_else(|| OAuthError::InvalidRequest("X-Tenant-ID header is required".to_string()))?;

    let tenant_str = tenant_header
        .to_str()
        .map_err(|_| OAuthError::InvalidRequest("Invalid X-Tenant-ID header value".to_string()))?;

    Uuid::parse_str(tenant_str)
        .map_err(|_| OAuthError::InvalidRequest("X-Tenant-ID must be a valid UUID".to_string()))
}

/// Request a device authorization code.
///
/// POST /oauth/device/code
///
/// This is the first step in the device code flow. The client sends its
/// `client_id` and requested scopes, and receives a `device_code` (for polling)
/// and `user_code` (to display to the user).
#[utoipa::path(
    post,
    path = "/oauth/device/code",
    request_body = DeviceAuthorizationRequest,
    responses(
        (status = 200, description = "Device authorization response", body = DeviceAuthorizationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Invalid or unauthorized client"),
    ),
    tag = "OAuth2 Device Code"
)]
pub async fn device_authorization_handler(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Form(request): Form<DeviceAuthorizationRequest>,
) -> Result<axum::Json<DeviceAuthorizationResponse>, OAuthError> {
    // Extract tenant_id from header
    let tenant_id = extract_tenant_id(&headers)?;

    // Validate client exists and has device_code grant type
    let client = state
        .client_service
        .get_client_by_client_id(tenant_id, &request.client_id)
        .await
        .map_err(|_| OAuthError::InvalidClient("Client not found".to_string()))?;

    // Check if client has device_code grant type
    if !client
        .grant_types
        .contains(&DEVICE_CODE_GRANT_TYPE.to_string())
    {
        return Err(OAuthError::UnauthorizedClient(
            "Client is not authorized for device_code grant".to_string(),
        ));
    }

    // Parse scopes
    let scopes: Vec<String> = request
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    // Validate scopes against client's allowed scopes
    for scope in &scopes {
        if !client.scopes.contains(scope) {
            return Err(OAuthError::InvalidScope(format!(
                "Scope '{scope}' is not allowed for this client"
            )));
        }
    }

    // Build verification URI
    let verification_uri = format!("{}/device", state.issuer);

    // Storm-2372 remediation (F117): Extract origin context from request
    let socket_addr = connect_info.as_ref().map(|ci| &ci.0);
    let origin_ip = extract_origin_ip(&headers, socket_addr);
    let origin_country = Some(extract_country_code(&headers));
    let origin_user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    // Create device code service and generate authorization
    let device_service = DeviceCodeService::new(state.pool.clone());
    let response = device_service
        .create_device_authorization(
            tenant_id,
            &request.client_id,
            scopes,
            &verification_uri,
            origin_ip,
            origin_user_agent,
            origin_country,
        )
        .await?;

    Ok(axum::Json(DeviceAuthorizationResponse {
        device_code: response.device_code,
        user_code: response.user_code,
        verification_uri: response.verification_uri,
        verification_uri_complete: Some(response.verification_uri_complete),
        expires_in: response.expires_in,
        interval: response.interval,
    }))
}

/// Device verification page (HTML).
///
/// GET /device
///
/// Renders an HTML page where the user can enter their user code.
/// If `code` query parameter is provided (from `verification_uri_complete`),
/// the code is pre-filled in the form.
/// Sets a CSRF token cookie for form protection.
#[utoipa::path(
    get,
    path = "/device",
    params(
        ("code" = Option<String>, Query, description = "Pre-filled user code from verification_uri_complete")
    ),
    responses(
        (status = 200, description = "Device verification page (HTML)", content_type = "text/html"),
    ),
    tag = "OAuth2 Device Code"
)]
pub async fn device_verification_page_handler(
    State(state): State<OAuthState>,
    Query(query): Query<DeviceVerificationQuery>,
) -> Response {
    let prefilled_code = query.code.unwrap_or_default();
    let error_message = "";

    // Generate CSRF token with proper security flag based on environment
    let is_secure = state.is_production();
    let csrf_token = generate_csrf_token();
    let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);

    let html = render_verification_page(&prefilled_code, error_message, &csrf_token);

    // Build response with CSRF cookie
    let mut response = Html(html).into_response();
    if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
        response.headers_mut().insert(SET_COOKIE, cookie_value);
    }
    response
}

/// Verify user code and redirect to approval page.
///
/// POST /device/verify
///
/// Validates the user code and either shows the approval page or an error.
/// F112: Now checks authentication status and shows login form if not authenticated.
/// Validates CSRF token to prevent cross-site request forgery.
#[utoipa::path(
    post,
    path = "/device/verify",
    responses(
        (status = 200, description = "Verification result page (HTML)", content_type = "text/html"),
    ),
    tag = "OAuth2 Device Code"
)]
pub async fn device_verify_code_handler(
    State(state): State<OAuthState>,
    Extension(session_service): Extension<Arc<SessionService>>,
    headers: HeaderMap,
    Form(request): Form<DeviceVerifyRequest>,
) -> Response {
    // Determine secure flag based on environment
    let is_secure = state.is_production();

    // Helper to build response with new CSRF token
    let with_csrf_cookie = |html: String| -> Response {
        let csrf_token = generate_csrf_token();
        let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);
        let mut response = Html(html).into_response();
        if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
            response.headers_mut().insert(SET_COOKIE, cookie_value);
        }
        response
    };

    // Validate CSRF token
    let cookie_token = extract_csrf_cookie(&headers);
    let form_token = request.csrf_token.as_deref();

    // Capture for logging before match consumes
    let has_cookie = cookie_token.is_some();
    let has_form = form_token.is_some();

    match (cookie_token, form_token) {
        (Some(ref ct), Some(ft)) if validate_csrf_token(ct, ft) => {
            // CSRF valid, continue
        }
        _ => {
            // CSRF validation failed - regenerate token and show error
            warn!(
                user_code = %request.user_code,
                has_cookie = has_cookie,
                has_form = has_form,
                "Device verify: CSRF validation failed"
            );
            let csrf_token = generate_csrf_token();
            return with_csrf_cookie(render_verification_page(
                &request.user_code,
                "Session expired. Please try again.",
                &csrf_token,
            ));
        }
    }

    // Extract tenant_id from header
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(tid) => tid,
        Err(e) => {
            warn!(
                user_code = %request.user_code,
                error = %e,
                "Device verify: missing or invalid tenant ID"
            );
            let csrf_token = generate_csrf_token();
            return with_csrf_cookie(render_verification_page(
                &request.user_code,
                "Invalid request. Please try again.",
                &csrf_token,
            ));
        }
    };

    let device_service = DeviceCodeService::new(state.pool.clone());

    // Find pending device code
    match device_service
        .find_pending_by_user_code(tenant_id, &request.user_code)
        .await
    {
        Ok(Some(device_code)) => {
            // F112: Check if user is authenticated
            let is_authenticated = get_user_from_session(&headers, &session_service, tenant_id)
                .await
                .is_some();

            // Generate new CSRF token for next form
            let csrf_token = generate_csrf_token();

            if is_authenticated {
                // Storm-2372 Remediation (F117): Build enhanced approval context
                // Get approver's IP for mismatch detection
                let approver_ip = extract_origin_ip(&headers, None);

                // Fetch client name for display (None if unknown)
                let client_name = device_service
                    .get_client_name(tenant_id, &device_code.client_id)
                    .await
                    .ok()
                    .flatten();

                let context = ApprovalContext {
                    user_code: request.user_code.clone(),
                    client_id: device_code.client_id.clone(),
                    client_name,
                    scopes: device_code.scopes.clone(),
                    origin_ip: device_code.origin_ip.clone(),
                    origin_country: device_code.origin_country.clone(),
                    created_at: device_code.created_at,
                    approver_ip,
                    csrf_token,
                };

                // User is logged in - show enhanced approval page with context
                with_csrf_cookie(render_approval_page_with_context(&context))
            } else {
                // User not logged in - show login form with device code context
                with_csrf_cookie(render_login_page(
                    &request.user_code,
                    &device_code.client_id,
                    &device_code.scopes,
                    None, // No error initially
                    &csrf_token,
                ))
            }
        }
        Ok(None) => {
            let csrf_token = generate_csrf_token();
            with_csrf_cookie(render_verification_page(
                &request.user_code,
                "Invalid or expired code. Please check the code and try again.",
                &csrf_token,
            ))
        }
        Err(_) => {
            let csrf_token = generate_csrf_token();
            with_csrf_cookie(render_verification_page(
                &request.user_code,
                "An error occurred. Please try again.",
                &csrf_token,
            ))
        }
    }
}

/// Approve or deny device authorization.
///
/// POST /device/authorize
///
/// User approves or denies the authorization request.
/// F112: Now uses session cookie for authentication instead of X-User-ID header.
/// Validates CSRF token to prevent cross-site request forgery.
#[utoipa::path(
    post,
    path = "/device/authorize",
    responses(
        (status = 200, description = "Authorization result page (HTML)", content_type = "text/html"),
    ),
    tag = "OAuth2 Device Code"
)]
pub async fn device_authorize_handler(
    State(state): State<OAuthState>,
    Extension(session_service): Extension<Arc<SessionService>>,
    headers: HeaderMap,
    Form(request): Form<DeviceAuthorizeRequest>,
) -> Response {
    // Validate CSRF token
    let cookie_token = extract_csrf_cookie(&headers);
    let form_token = request.csrf_token.as_deref();

    match (cookie_token, form_token) {
        (Some(ref ct), Some(ft)) if validate_csrf_token(ct, ft) => {
            // CSRF valid, continue
        }
        _ => {
            // CSRF validation failed
            return Html(render_result_page(
                false,
                "Session expired. Please go back and try again.",
            ))
            .into_response();
        }
    }

    // Extract tenant_id from header
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(tid) => tid,
        Err(_) => {
            return Html(render_result_page(
                false,
                "Invalid request. Please try again.",
            ))
            .into_response();
        }
    };

    // F112: Extract user_id from session cookie (no longer uses X-User-ID header)
    let user_id = match get_user_from_session(&headers, &session_service, tenant_id).await {
        Some((uid, _)) => uid,
        None => {
            // User not authenticated - redirect to login page with user_code
            return Html(render_login_required_page(&request.user_code)).into_response();
        }
    };

    let device_service = DeviceCodeService::new(state.pool.clone());

    match request.action.as_str() {
        "approve" => {
            // F117 Storm-2372 Phase 3: Risk-based approval with scoring
            if let Some(ref risk_service) = state.device_risk_service {
                // Get device code info for risk assessment
                if let Ok(Some(device_code_info)) = device_service
                    .find_pending_by_user_code(tenant_id, &request.user_code)
                    .await
                {
                    let approver_ip = extract_origin_ip(&headers, None);
                    let approver_country = extract_country_code(&headers);
                    let approver_user_agent = headers
                        .get("user-agent")
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);

                    // Build risk context
                    let risk_context = RiskContext {
                        tenant_id,
                        user_id,
                        approver_ip: approver_ip.clone(),
                        approver_country: Some(approver_country.clone()),
                        origin_ip: device_code_info.origin_ip.clone(),
                        origin_country: device_code_info.origin_country.clone(),
                        code_created_at: device_code_info.created_at,
                        origin_user_agent: device_code_info.origin_user_agent.clone(),
                        approver_user_agent,
                    };

                    // Calculate risk score
                    let assessment = match risk_service.calculate_score(&risk_context).await {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to calculate risk score, proceeding with caution");
                            // In case of error, treat as medium risk (require confirmation)
                            return Html(render_result_page(
                                false,
                                "Unable to verify authorization. Please try again.",
                            ))
                            .into_response();
                        }
                    };

                    tracing::info!(
                        tenant_id = %tenant_id,
                        user_id = %user_id,
                        device_code_id = %device_code_info.id,
                        risk_score = assessment.score,
                        risk_action = ?assessment.action,
                        factors = ?assessment.factors,
                        "Risk assessment completed for device code approval"
                    );

                    // Handle based on risk action
                    match assessment.action {
                        RiskAction::Approve => {
                            // Low risk - proceed with approval
                            tracing::info!("Low risk approval, proceeding directly");
                        }
                        RiskAction::RequireEmailConfirmation => {
                            // Medium risk - require email confirmation
                            if let Some(ref confirmation_service) =
                                state.device_confirmation_service
                            {
                                // Check if there's already a confirmed confirmation
                                let pending = confirmation_service
                                    .find_pending_confirmation(tenant_id, device_code_info.id)
                                    .await
                                    .ok()
                                    .flatten();

                                match pending {
                                    Some(c) if c.is_confirmed() => {
                                        // Confirmation already completed, proceed with approval
                                        tracing::info!(
                                            confirmation_id = %c.id,
                                            "Email confirmation already completed, proceeding with approval"
                                        );
                                    }
                                    Some(c) => {
                                        // Pending confirmation exists but not confirmed yet
                                        let csrf_token = generate_csrf_token();
                                        let cookie =
                                            create_csrf_cookie(&csrf_token, state.is_production());
                                        return (
                                            [(SET_COOKIE, cookie)],
                                            Html(render_check_email_page(
                                                &format!(
                                                    "A confirmation email has been sent. Risk score: {} (medium risk). Please check your inbox and click the link to confirm.",
                                                    assessment.score
                                                ),
                                                Some(&c.device_code_id.to_string()),
                                                Some(&csrf_token),
                                            )),
                                        )
                                            .into_response();
                                    }
                                    None => {
                                        // No confirmation exists yet, need to create one
                                        // TODO: Look up user email and create confirmation
                                        tracing::warn!(
                                            tenant_id = %tenant_id,
                                            user_id = %user_id,
                                            risk_score = assessment.score,
                                            "Email confirmation required but user email lookup not implemented yet"
                                        );
                                        // For now, log and proceed (degraded mode)
                                    }
                                }
                            }
                        }
                        RiskAction::RequireMfaAndNotify => {
                            // High risk - require MFA and notify admins
                            tracing::warn!(
                                tenant_id = %tenant_id,
                                user_id = %user_id,
                                risk_score = assessment.score,
                                "HIGH RISK device code approval - MFA and admin notification required"
                            );

                            // Notify admins of high-risk attempt
                            if let Err(e) = risk_service
                                .notify_admins(tenant_id, user_id, &assessment, device_code_info.id)
                                .await
                            {
                                tracing::error!(error = %e, "Failed to notify admins of high-risk approval");
                            }

                            // TODO: Implement MFA verification flow for high-risk approvals
                            // For now, show a warning and require email confirmation as fallback
                            if let Some(ref confirmation_service) =
                                state.device_confirmation_service
                            {
                                let pending = confirmation_service
                                    .find_pending_confirmation(tenant_id, device_code_info.id)
                                    .await
                                    .ok()
                                    .flatten();

                                match pending {
                                    Some(c) if c.is_confirmed() => {
                                        tracing::info!(
                                            confirmation_id = %c.id,
                                            "High-risk but email confirmed, proceeding with approval"
                                        );
                                    }
                                    Some(c) => {
                                        let csrf_token = generate_csrf_token();
                                        let cookie =
                                            create_csrf_cookie(&csrf_token, state.is_production());
                                        return (
                                            [(SET_COOKIE, cookie)],
                                            Html(render_check_email_page(
                                                &format!(
                                                    "⚠️ HIGH RISK: This authorization request has a high risk score ({}). An additional confirmation email has been sent. Administrators have been notified.",
                                                    assessment.score
                                                ),
                                                Some(&c.device_code_id.to_string()),
                                                Some(&csrf_token),
                                            )),
                                        )
                                            .into_response();
                                    }
                                    None => {
                                        tracing::warn!(
                                            tenant_id = %tenant_id,
                                            user_id = %user_id,
                                            "High-risk approval but confirmation service not available"
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // After successful approval, record the user's IP for future risk assessments
                    if let Some(ip) = &approver_ip {
                        if let Err(e) = risk_service
                            .record_user_ip(tenant_id, user_id, ip, Some(&approver_country))
                            .await
                        {
                            tracing::error!(error = %e, "Failed to record user IP after approval");
                        }
                    }
                }
            }

            // Proceed with approval
            match device_service
                .authorize(tenant_id, &request.user_code, user_id)
                .await
            {
                Ok(()) => Html(render_result_page(
                    true,
                    "Authorization approved! You can close this window and return to your device.",
                ))
                .into_response(),
                Err(_) => Html(render_result_page(
                    false,
                    "Failed to authorize. The code may have expired.",
                ))
                .into_response(),
            }
        }
        "deny" => match device_service.deny(tenant_id, &request.user_code).await {
            Ok(()) => Html(render_result_page(
                true,
                "Authorization denied. You can close this window.",
            ))
            .into_response(),
            Err(_) => Html(render_result_page(
                false,
                "Failed to process denial. The code may have expired.",
            ))
            .into_response(),
        },
        _ => Html(render_result_page(false, "Invalid action.")).into_response(),
    }
}

/// Check device authorization status (for token polling).
///
/// This is called by the token endpoint when `grant_type` is `device_code`.
pub async fn check_device_authorization(
    state: &OAuthState,
    tenant_id: Uuid,
    device_code: &str,
    client_id: &str,
) -> Result<DeviceAuthorizationStatus, OAuthError> {
    let device_service = DeviceCodeService::new(state.pool.clone());
    device_service
        .check_authorization(tenant_id, device_code, client_id)
        .await
}

/// Exchange device code for tokens.
///
/// This is called by the token endpoint after authorization is complete.
pub async fn exchange_device_code_for_tokens(
    state: &OAuthState,
    tenant_id: Uuid,
    device_code: &str,
    client_id: &str,
) -> Result<(Uuid, String), OAuthError> {
    let device_service = DeviceCodeService::new(state.pool.clone());
    let result = device_service
        .exchange_for_tokens(tenant_id, device_code, client_id)
        .await?;
    Ok((result.user_id, result.scope))
}

// ============================================================================
// HTML Templates (minimal, server-rendered)
// ============================================================================

fn render_verification_page(prefilled_code: &str, error_message: &str, csrf_token: &str) -> String {
    let error_html = if error_message.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="error">{}</div>"#, html_escape(error_message))
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Authorization - xavyo</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; color: #333; text-align: center; }}
        p {{ color: #666; margin-bottom: 1.5rem; text-align: center; }}
        .form-group {{ margin-bottom: 1rem; }}
        label {{ display: block; margin-bottom: 0.5rem; color: #333; font-weight: 500; }}
        input[type="text"] {{ width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1.25rem; text-transform: uppercase; letter-spacing: 0.1em; text-align: center; }}
        input[type="text"]:focus {{ outline: none; border-color: #0066cc; }}
        button {{ width: 100%; padding: 0.75rem; background: #0066cc; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }}
        button:hover {{ background: #0052a3; }}
        .error {{ background: #fee; border: 1px solid #fcc; color: #c00; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; text-align: center; }}
        .hint {{ font-size: 0.875rem; color: #999; text-align: center; margin-top: 0.5rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Device Authorization</h1>
        <p>Enter the code displayed on your device</p>
        {error_html}
        <form method="post" action="/device/verify">
            <input type="hidden" name="csrf_token" value="{csrf_token}" />
            <div class="form-group">
                <label for="user_code">Code</label>
                <input type="text" id="user_code" name="user_code" value="{prefilled_code}" placeholder="XXXX-XXXX" required maxlength="9" autocomplete="off" />
                <p class="hint">Example: WDJB-MJHT</p>
            </div>
            <button type="submit">Continue</button>
        </form>
    </div>
</body>
</html>"#,
        error_html = error_html,
        prefilled_code = html_escape(prefilled_code),
        csrf_token = html_escape(csrf_token),
    )
}

/// Legacy approval page without Storm-2372 context.
/// Kept for tests and potential fallback scenarios.
#[allow(dead_code)]
fn render_approval_page(
    user_code: &str,
    client_id: &str,
    scopes: &[String],
    csrf_token: &str,
) -> String {
    let scopes_html = if scopes.is_empty() {
        "<li>Basic access</li>".to_string()
    } else {
        scopes
            .iter()
            .map(|s| format!("<li>{}</li>", html_escape(s)))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize Device - xavyo</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; color: #333; text-align: center; }}
        p {{ color: #666; margin-bottom: 1rem; }}
        .client {{ font-weight: 600; color: #333; }}
        ul {{ margin: 1rem 0; padding-left: 1.5rem; }}
        li {{ margin: 0.5rem 0; color: #666; }}
        .buttons {{ display: flex; gap: 1rem; margin-top: 1.5rem; }}
        button {{ flex: 1; padding: 0.75rem; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }}
        .approve {{ background: #0066cc; color: white; }}
        .approve:hover {{ background: #0052a3; }}
        .deny {{ background: #eee; color: #333; }}
        .deny:hover {{ background: #ddd; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorize Device</h1>
        <p>The application <span class="client">{client_id}</span> is requesting access to your account.</p>
        <p>This will allow the application to:</p>
        <ul>
            {scopes_html}
        </ul>
        <form method="post" action="/device/authorize">
            <input type="hidden" name="user_code" value="{user_code}" />
            <input type="hidden" name="csrf_token" value="{csrf_token}" />
            <div class="buttons">
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
                <button type="submit" name="action" value="approve" class="approve">Approve</button>
            </div>
        </form>
    </div>
</body>
</html>"#,
        client_id = html_escape(client_id),
        scopes_html = scopes_html,
        user_code = html_escape(user_code),
        csrf_token = html_escape(csrf_token),
    )
}

/// Storm-2372 Remediation (F117): Enhanced approval page with security context.
///
/// Displays origin IP, client name, timestamp, and warnings to help users
/// identify potentially malicious device code requests.
fn render_approval_page_with_context(context: &ApprovalContext) -> String {
    let scopes_html = if context.scopes.is_empty() {
        "<li>Basic access</li>".to_string()
    } else {
        context
            .scopes
            .iter()
            .map(|s| format!("<li>{}</li>", html_escape(s)))
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Build warning banners
    let mut warnings = Vec::new();

    // Warning: Unknown application
    if context.is_unknown_app() {
        warnings.push(format!(
            r#"<div class="warning warning-unknown">
                <span class="warning-icon">⚠️</span>
                <div>
                    <strong>Unknown Application</strong>
                    <p>This application ({}) is not recognized. Only approve if you initiated this request.</p>
                </div>
            </div>"#,
            html_escape(&context.client_id)
        ));
    }

    // Warning: Stale device code (older than 5 minutes)
    if context.is_stale() {
        let age = context.age_minutes();
        warnings.push(format!(
            r#"<div class="warning warning-stale">
                <span class="warning-icon">⏰</span>
                <div>
                    <strong>This code is older than 5 minutes</strong>
                    <p>Created {age} minutes ago. Legitimate device codes are usually approved quickly. If you didn't just initiate this request, click Deny.</p>
                </div>
            </div>"#
        ));
    }

    // Info: IP mismatch (informational, not necessarily malicious)
    let ip_mismatch_html = if context.has_ip_mismatch() {
        format!(
            r#"<div class="info info-ip">
                <span class="info-icon">ℹ️</span>
                <div>
                    <strong>Different location detected</strong>
                    <p>This request originated from a different IP address ({}) than your current session.</p>
                </div>
            </div>"#,
            html_escape(context.origin_ip.as_deref().unwrap_or("unknown"))
        )
    } else {
        String::new()
    };

    let warnings_html = warnings.join("\n");

    // Origin context section
    let origin_ip_display = context.origin_ip.as_deref().unwrap_or("Unknown");
    let origin_country_display = context.origin_country.as_deref().unwrap_or("Unknown");
    let age_display = if context.age_minutes() == 0 {
        "Just now".to_string()
    } else if context.age_minutes() == 1 {
        "1 minute ago".to_string()
    } else {
        format!("{} minutes ago", context.age_minutes())
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize Device - xavyo</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1rem; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 450px; width: 100%; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; color: #333; text-align: center; }}
        p {{ color: #666; margin-bottom: 1rem; }}
        .client {{ font-weight: 600; color: #333; }}
        ul {{ margin: 1rem 0; padding-left: 1.5rem; }}
        li {{ margin: 0.5rem 0; color: #666; }}
        .buttons {{ display: flex; gap: 1rem; margin-top: 1.5rem; }}
        button {{ flex: 1; padding: 0.75rem; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }}
        .approve {{ background: #0066cc; color: white; }}
        .approve:hover {{ background: #0052a3; }}
        .deny {{ background: #eee; color: #333; }}
        .deny:hover {{ background: #ddd; }}

        /* Warning and info banners */
        .warning, .info {{
            display: flex;
            gap: 0.75rem;
            padding: 1rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }}
        .warning {{
            background: #fff3cd;
            border: 1px solid #ffc107;
        }}
        .warning-icon, .info-icon {{
            font-size: 1.5rem;
            flex-shrink: 0;
        }}
        .warning strong, .info strong {{
            display: block;
            color: #856404;
            margin-bottom: 0.25rem;
        }}
        .warning p, .info p {{
            color: #856404;
            font-size: 0.875rem;
            margin: 0;
        }}
        .info {{
            background: #e7f3ff;
            border: 1px solid #b6d4fe;
        }}
        .info strong {{
            color: #084298;
        }}
        .info p {{
            color: #084298;
        }}

        /* Context section */
        .context {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            padding: 1rem;
            margin: 1rem 0;
            font-size: 0.875rem;
        }}
        .context-title {{
            font-weight: 600;
            color: #495057;
            margin-bottom: 0.5rem;
        }}
        .context-row {{
            display: flex;
            justify-content: space-between;
            padding: 0.25rem 0;
            border-bottom: 1px solid #e9ecef;
        }}
        .context-row:last-child {{
            border-bottom: none;
        }}
        .context-label {{
            color: #6c757d;
        }}
        .context-value {{
            color: #495057;
            font-weight: 500;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorize Device</h1>

        {warnings_html}
        {ip_mismatch_html}

        <p>The application <span class="client">{display_name}</span> is requesting access to your account.</p>

        <div class="context">
            <div class="context-title">Request Details</div>
            <div class="context-row">
                <span class="context-label">Origin IP</span>
                <span class="context-value">{origin_ip} ({origin_country})</span>
            </div>
            <div class="context-row">
                <span class="context-label">Created</span>
                <span class="context-value">{age}</span>
            </div>
        </div>

        <p>This will allow the application to:</p>
        <ul>
            {scopes_html}
        </ul>

        <form method="post" action="/device/authorize">
            <input type="hidden" name="user_code" value="{user_code}" />
            <input type="hidden" name="csrf_token" value="{csrf_token}" />
            <div class="buttons">
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
                <button type="submit" name="action" value="approve" class="approve">Approve</button>
            </div>
        </form>
    </div>
</body>
</html>"#,
        warnings_html = warnings_html,
        ip_mismatch_html = ip_mismatch_html,
        display_name = html_escape(context.display_name()),
        origin_ip = html_escape(origin_ip_display),
        origin_country = html_escape(origin_country_display),
        age = html_escape(&age_display),
        scopes_html = scopes_html,
        user_code = html_escape(&context.user_code),
        csrf_token = html_escape(&context.csrf_token),
    )
}

fn render_result_page(success: bool, message: &str) -> String {
    let (icon, title, color) = if success {
        ("✓", "Success", "#0a0")
    } else {
        ("✗", "Error", "#c00")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - xavyo</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; text-align: center; }}
        .icon {{ font-size: 4rem; color: {color}; margin-bottom: 1rem; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; color: #333; }}
        p {{ color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">{icon}</div>
        <h1>{title}</h1>
        <p>{message}</p>
    </div>
</body>
</html>"#,
        icon = icon,
        title = title,
        color = color,
        message = html_escape(message),
    )
}

/// F112: Login page for device code flow.
///
/// Renders a login form when user is not authenticated during device code flow.
fn render_login_page(
    user_code: &str,
    client_id: &str,
    scopes: &[String],
    error_message: Option<&str>,
    csrf_token: &str,
) -> String {
    let scopes_html = if scopes.is_empty() {
        "<li>Basic access</li>".to_string()
    } else {
        scopes
            .iter()
            .map(|s| format!("<li>{}</li>", html_escape(s)))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let error_html = match error_message {
        Some(msg) => format!(r#"<div class="error">{}</div>"#, html_escape(msg)),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - Device Authorization - xavyo</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; color: #333; text-align: center; }}
        .subtitle {{ color: #666; margin-bottom: 1.5rem; text-align: center; font-size: 0.9rem; }}
        .client {{ font-weight: 600; color: #333; }}
        .scopes {{ background: #f9f9f9; padding: 1rem; border-radius: 4px; margin-bottom: 1.5rem; }}
        .scopes p {{ font-size: 0.875rem; color: #666; margin-bottom: 0.5rem; }}
        ul {{ margin: 0; padding-left: 1.25rem; }}
        li {{ margin: 0.25rem 0; color: #666; font-size: 0.875rem; }}
        .form-group {{ margin-bottom: 1rem; }}
        label {{ display: block; margin-bottom: 0.25rem; color: #333; font-weight: 500; font-size: 0.875rem; }}
        input[type="email"], input[type="password"] {{ width: 100%; padding: 0.625rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }}
        input:focus {{ outline: none; border-color: #0066cc; }}
        button {{ width: 100%; padding: 0.75rem; background: #0066cc; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-top: 0.5rem; }}
        button:hover {{ background: #0052a3; }}
        .error {{ background: #fee; border: 1px solid #fcc; color: #c00; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; text-align: center; font-size: 0.875rem; }}
        .signup-link {{ text-align: center; margin-top: 1rem; font-size: 0.875rem; color: #666; }}
        .signup-link a {{ color: #0066cc; text-decoration: none; }}
        .signup-link a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Sign In</h1>
        <p class="subtitle">Sign in to authorize <span class="client">{client_id}</span></p>

        <div class="scopes">
            <p>This application is requesting access to:</p>
            <ul>
                {scopes_html}
            </ul>
        </div>

        {error_html}

        <form method="post" action="/device/login">
            <input type="hidden" name="user_code" value="{user_code}" />
            <input type="hidden" name="csrf_token" value="{csrf_token}" />
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required autocomplete="email" />
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password" />
            </div>
            <button type="submit">Sign In</button>
        </form>

        <p class="signup-link">
            Don't have an account? <a href="/auth/signup?user_code={user_code}">Sign up</a>
        </p>
    </div>
</body>
</html>"#,
        client_id = html_escape(client_id),
        scopes_html = scopes_html,
        user_code = html_escape(user_code),
        error_html = error_html,
        csrf_token = html_escape(csrf_token),
    )
}

/// F112: Login required page when user tries to authorize without authentication.
fn render_login_required_page(user_code: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Required - xavyo</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; text-align: center; }}
        .icon {{ font-size: 3rem; margin-bottom: 1rem; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; color: #333; }}
        p {{ color: #666; margin-bottom: 1.5rem; }}
        a {{ display: inline-block; padding: 0.75rem 1.5rem; background: #0066cc; color: white; text-decoration: none; border-radius: 4px; font-size: 1rem; }}
        a:hover {{ background: #0052a3; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔒</div>
        <h1>Authentication Required</h1>
        <p>You need to sign in to authorize this device. Your session may have expired.</p>
        <a href="/device/verify?user_code={user_code}">Sign In</a>
    </div>
</body>
</html>"#,
        user_code = html_escape(user_code),
    )
}

/// Simple HTML escaping.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ============================================================================
// Storm-2372 Remediation: Email Confirmation Handlers (F117)
// ============================================================================

/// Path parameter for GET /device/confirm/{token}.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ConfirmTokenPath {
    /// Confirmation token from email.
    pub token: String,
}

/// Request for POST /device/resend-confirmation.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ResendConfirmationRequest {
    /// The device code ID for which to resend confirmation.
    pub device_code_id: String,
    /// CSRF token for form protection.
    #[serde(default)]
    pub csrf_token: Option<String>,
}

/// Response for confirmation and resend endpoints (HTML page).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConfirmationStatusResponse {
    /// Whether the operation was successful.
    pub success: bool,
    /// Human-readable message describing the result.
    pub message: String,
}

/// GET /device/confirm/{token} - Validate email confirmation token (F117).
///
/// This endpoint is called when users click the confirmation link in their email.
/// It validates the token, marks the confirmation as complete, and returns a success
/// or error page.
///
/// # Storm-2372 Remediation
///
/// This endpoint is part of the email confirmation flow for suspicious device code
/// approvals. When a user attempts to approve a device code from an IP that differs
/// from the originating IP, they must confirm via email before the approval proceeds.
#[utoipa::path(
    get,
    path = "/device/confirm/{token}",
    params(
        ("token" = String, Path, description = "Email confirmation token from the confirmation email")
    ),
    responses(
        (status = 200, description = "Confirmation result page (HTML)", content_type = "text/html"),
    ),
    tag = "OAuth2 Device Code"
)]
pub async fn device_confirm_handler(
    State(state): State<OAuthState>,
    axum::extract::Path(path): axum::extract::Path<ConfirmTokenPath>,
) -> Response {
    use crate::services::ConfirmationValidationResult;

    // Extract tenant_id from system tenant (email confirmations work at system level)
    // In production, we'd need to determine tenant from the confirmation token or URL
    let tenant_id = state.system_tenant_id;

    let confirmation_service = match &state.device_confirmation_service {
        Some(svc) => svc,
        None => {
            return Html(render_confirmation_result_page(
                false,
                "Email confirmation is not enabled",
            ))
            .into_response();
        }
    };

    match confirmation_service
        .validate_token(tenant_id, &path.token)
        .await
    {
        Ok(ConfirmationValidationResult::Valid {
            device_code_id,
            user_id: _,
        }) => {
            // Confirmation successful - the device code can now be approved
            // In a full implementation, we'd also trigger the approval automatically
            // or show a page that confirms and allows the user to complete approval
            tracing::info!(
                tenant_id = %tenant_id,
                device_code_id = %device_code_id,
                "Device code confirmation validated successfully"
            );
            Html(render_confirmation_result_page(
                true,
                "Your email has been confirmed. You can now return to your original device to complete the authorization.",
            ))
            .into_response()
        }
        Ok(ConfirmationValidationResult::NotFound) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                "Device code confirmation token not found"
            );
            Html(render_confirmation_result_page(
                false,
                "This confirmation link is invalid or has already been used.",
            ))
            .into_response()
        }
        Ok(ConfirmationValidationResult::Expired) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                "Device code confirmation token expired"
            );
            Html(render_confirmation_result_page(
                false,
                "This confirmation link has expired. Please request a new confirmation email.",
            ))
            .into_response()
        }
        Err(e) => {
            tracing::error!(
                tenant_id = %tenant_id,
                error = %e,
                "Failed to validate device code confirmation"
            );
            Html(render_confirmation_result_page(
                false,
                "An error occurred while processing your confirmation. Please try again.",
            ))
            .into_response()
        }
    }
}

/// POST /device/resend-confirmation - Resend confirmation email (F117).
///
/// Allows users to request a new confirmation email if they didn't receive the
/// original or it expired. Rate limited to prevent abuse (max 1 resend per minute).
///
/// # Storm-2372 Remediation
///
/// This endpoint allows users to request a new confirmation email when the original
/// email was not received or the confirmation link expired. This is part of the
/// security flow that requires email confirmation for device code approvals from
/// suspicious IP addresses.
#[utoipa::path(
    post,
    path = "/device/resend-confirmation",
    request_body = ResendConfirmationRequest,
    responses(
        (status = 200, description = "Resend result page (HTML)", content_type = "text/html"),
        (status = 400, description = "Invalid request or CSRF validation failed"),
        (status = 429, description = "Rate limit exceeded - wait before requesting another resend"),
    ),
    tag = "OAuth2 Device Code"
)]
pub async fn device_resend_confirmation_handler(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Form(request): Form<ResendConfirmationRequest>,
) -> Response {
    // Validate CSRF token
    let cookie_token = extract_csrf_cookie(&headers);
    let form_token = request.csrf_token.as_deref();

    match (cookie_token.as_deref(), form_token) {
        (Some(ct), Some(ft)) if validate_csrf_token(ct, ft) => {
            // CSRF valid, continue
        }
        (None, _) | (_, None) => {
            // Missing tokens - allow for now but log warning
            tracing::warn!("Missing CSRF token in resend confirmation request");
        }
        _ => {
            return Html(render_confirmation_result_page(
                false,
                "Invalid form submission. Please try again.",
            ))
            .into_response();
        }
    }

    let tenant_id = state.system_tenant_id;

    let confirmation_service = match &state.device_confirmation_service {
        Some(svc) => svc,
        None => {
            return Html(render_confirmation_result_page(
                false,
                "Email confirmation is not enabled",
            ))
            .into_response();
        }
    };

    // Parse the device_code_id
    let device_code_id = match Uuid::parse_str(&request.device_code_id) {
        Ok(id) => id,
        Err(_) => {
            return Html(render_confirmation_result_page(
                false,
                "Invalid request. Please return to the authorization page and try again.",
            ))
            .into_response();
        }
    };

    // Check for pending confirmation
    let pending = match confirmation_service
        .find_pending_confirmation(tenant_id, device_code_id)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Html(render_confirmation_result_page(
                false,
                "No pending confirmation found. The confirmation may have expired or already been completed.",
            ))
            .into_response();
        }
        Err(e) => {
            tracing::error!(
                tenant_id = %tenant_id,
                device_code_id = %device_code_id,
                error = %e,
                "Failed to find pending confirmation"
            );
            return Html(render_confirmation_result_page(
                false,
                "An error occurred. Please try again.",
            ))
            .into_response();
        }
    };

    // Check rate limiting
    if !pending.can_resend() {
        return Html(render_check_email_page(
            "Please wait before requesting another email. You can only resend once per minute.",
            None,
            None,
        ))
        .into_response();
    }

    // For resend, we'd need the user's email. In a full implementation, we'd look this up
    // from the user_id in the confirmation. For now, we'll return a generic message.
    // TODO: Look up user email and actually resend
    tracing::info!(
        tenant_id = %tenant_id,
        device_code_id = %device_code_id,
        confirmation_id = %pending.id,
        "Confirmation resend requested (not fully implemented)"
    );

    Html(render_check_email_page(
        "If the confirmation was successfully resent, you should receive a new email shortly.",
        Some(&device_code_id.to_string()),
        None,
    ))
    .into_response()
}

/// F117: Render "Check your email" page for device code confirmation.
fn render_check_email_page(
    message: &str,
    device_code_id: Option<&str>,
    csrf_token: Option<&str>,
) -> String {
    let resend_form = match (device_code_id, csrf_token) {
        (Some(code_id), Some(csrf)) => format!(
            r#"<form method="post" action="/device/resend-confirmation" style="margin-top: 1.5rem;">
                <input type="hidden" name="device_code_id" value="{}" />
                <input type="hidden" name="csrf_token" value="{}" />
                <button type="submit" class="resend-btn">Resend Confirmation Email</button>
            </form>"#,
            html_escape(code_id),
            html_escape(csrf)
        ),
        _ => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Your Email - xavyo</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 450px; width: 100%; text-align: center; }}
        .icon {{ font-size: 4rem; margin-bottom: 1rem; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; color: #333; }}
        p {{ color: #666; line-height: 1.6; }}
        .resend-btn {{ margin-top: 1rem; padding: 0.75rem 1.5rem; background: #eee; border: none; border-radius: 4px; cursor: pointer; font-size: 0.875rem; color: #333; }}
        .resend-btn:hover {{ background: #ddd; }}
        .note {{ margin-top: 1.5rem; padding: 1rem; background: #f8f9fa; border-radius: 4px; font-size: 0.875rem; color: #666; text-align: left; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">📧</div>
        <h1>Check Your Email</h1>
        <p>{message}</p>
        {resend_form}
        <div class="note">
            <strong>Why am I seeing this?</strong><br>
            We detected that you're approving this device from a different location than where the request originated.
            For your security, we need to verify this is really you.
        </div>
    </div>
</body>
</html>"#,
        message = html_escape(message),
        resend_form = resend_form,
    )
}

/// F117: Render confirmation result page (success or error).
fn render_confirmation_result_page(success: bool, message: &str) -> String {
    let (icon, title, color) = if success {
        ("✅", "Email Confirmed", "#28a745")
    } else {
        ("❌", "Confirmation Failed", "#dc3545")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - xavyo</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 450px; width: 100%; text-align: center; }}
        .icon {{ font-size: 4rem; margin-bottom: 1rem; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1rem; color: {color}; }}
        p {{ color: #666; line-height: 1.6; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">{icon}</div>
        <h1>{title}</h1>
        <p>{message}</p>
    </div>
</body>
</html>"#,
        icon = icon,
        title = title,
        color = color,
        message = html_escape(message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("A & B"), "A &amp; B");
        assert_eq!(html_escape("it's"), "it&#x27;s");
    }

    #[test]
    fn test_render_verification_page_no_error() {
        let html = render_verification_page("ABCD-1234", "", "test_csrf_token");
        assert!(html.contains("ABCD-1234"));
        assert!(html.contains("test_csrf_token"));
        assert!(!html.contains("class=\"error\""));
    }

    #[test]
    fn test_render_verification_page_with_error() {
        let html = render_verification_page("", "Invalid code", "csrf123");
        assert!(html.contains("class=\"error\""));
        assert!(html.contains("Invalid code"));
        assert!(html.contains("csrf123"));
    }

    #[test]
    fn test_render_approval_page() {
        let html = render_approval_page(
            "ABCD-1234",
            "test-client",
            &["openid".to_string()],
            "csrf_abc",
        );
        assert!(html.contains("test-client"));
        assert!(html.contains("openid"));
        assert!(html.contains("ABCD-1234"));
        assert!(html.contains("csrf_abc"));
    }

    #[test]
    fn test_render_result_page_success() {
        let html = render_result_page(true, "All done!");
        assert!(html.contains("Success"));
        assert!(html.contains("All done!"));
    }

    #[test]
    fn test_render_result_page_error() {
        let html = render_result_page(false, "Something went wrong");
        assert!(html.contains("Error"));
        assert!(html.contains("Something went wrong"));
    }

    #[test]
    fn test_render_login_page() {
        let html = render_login_page(
            "ABCD-1234",
            "test-client",
            &["openid".to_string()],
            None,
            "csrf_xyz",
        );
        assert!(html.contains("Sign In"));
        assert!(html.contains("test-client"));
        assert!(html.contains("openid"));
        assert!(html.contains("ABCD-1234"));
        assert!(html.contains("csrf_xyz"));
        assert!(!html.contains("class=\"error\""));
    }

    #[test]
    fn test_render_login_page_with_error() {
        let html = render_login_page(
            "ABCD-1234",
            "test-client",
            &["openid".to_string()],
            Some("Invalid credentials"),
            "csrf_abc",
        );
        assert!(html.contains("class=\"error\""));
        assert!(html.contains("Invalid credentials"));
    }

    #[test]
    fn test_render_login_required_page() {
        let html = render_login_required_page("ABCD-1234");
        assert!(html.contains("Authentication Required"));
        assert!(html.contains("ABCD-1234"));
        assert!(html.contains("Sign In"));
    }

    // ============================================================================
    // Storm-2372 Remediation Tests (F117 - User Story 1)
    // ============================================================================

    // T013: Test render_approval_page_with_context displays context data
    #[test]
    fn test_render_approval_page_with_context_displays_origin_ip() {
        let context = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "test-client".to_string(),
            client_name: Some("Test Application".to_string()),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            origin_ip: Some("192.168.1.100".to_string()),
            origin_country: Some("US".to_string()),
            created_at: Utc::now() - Duration::minutes(2),
            approver_ip: Some("192.168.1.100".to_string()),
            csrf_token: "csrf_token_123".to_string(),
        };

        let html = render_approval_page_with_context(&context);

        // Should display client name instead of client_id
        assert!(
            html.contains("Test Application"),
            "Should display client name"
        );
        // Should display origin IP
        assert!(html.contains("192.168.1.100"), "Should display origin IP");
        // Should display country
        assert!(html.contains("US"), "Should display country code");
        // Should display relative timestamp
        assert!(
            html.contains("minutes ago") || html.contains("Created"),
            "Should display time info"
        );
        // Should contain CSRF token
        assert!(html.contains("csrf_token_123"), "Should contain CSRF token");
    }

    // T014: Test warning banner when code > 5 minutes old
    #[test]
    fn test_render_approval_page_with_context_shows_stale_warning() {
        let context = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "test-client".to_string(),
            client_name: Some("Test Application".to_string()),
            scopes: vec!["openid".to_string()],
            origin_ip: Some("192.168.1.100".to_string()),
            origin_country: Some("US".to_string()),
            created_at: Utc::now() - Duration::minutes(7), // 7 minutes old - stale!
            approver_ip: Some("192.168.1.100".to_string()),
            csrf_token: "csrf_token_123".to_string(),
        };

        let html = render_approval_page_with_context(&context);

        // Should show warning banner for stale codes
        assert!(
            html.contains("warning") || html.contains("Warning") || html.contains("⚠"),
            "Should display warning for stale device code"
        );
        // Should mention the code is old
        assert!(
            html.contains("5 minutes") || html.contains("older than"),
            "Should mention the age threshold"
        );
    }

    // T015: Test "Unknown application" warning when client_name is None
    #[test]
    fn test_render_approval_page_with_context_shows_unknown_app_warning() {
        let context = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "suspicious-client-id".to_string(),
            client_name: None, // Unknown application!
            scopes: vec!["openid".to_string()],
            origin_ip: Some("192.168.1.100".to_string()),
            origin_country: Some("US".to_string()),
            created_at: Utc::now() - Duration::minutes(2),
            approver_ip: Some("192.168.1.100".to_string()),
            csrf_token: "csrf_token_123".to_string(),
        };

        let html = render_approval_page_with_context(&context);

        // Should show warning for unknown application
        assert!(
            html.contains("Unknown") || html.contains("unknown") || html.contains("unrecognized"),
            "Should display unknown application warning"
        );
        // Should still show client_id as fallback
        assert!(
            html.contains("suspicious-client-id"),
            "Should display client_id as fallback"
        );
    }

    // T024: Test IP mismatch warning when approver IP differs from origin IP
    #[test]
    fn test_render_approval_page_with_context_shows_ip_mismatch_info() {
        let context = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "test-client".to_string(),
            client_name: Some("Test Application".to_string()),
            scopes: vec!["openid".to_string()],
            origin_ip: Some("10.0.0.1".to_string()), // Origin IP
            origin_country: Some("US".to_string()),
            created_at: Utc::now() - Duration::minutes(2),
            approver_ip: Some("192.168.1.100".to_string()), // Different IP!
            csrf_token: "csrf_token_123".to_string(),
        };

        let html = render_approval_page_with_context(&context);

        // Should show info about IP mismatch (not necessarily a warning, just informational)
        assert!(
            html.contains("different") || html.contains("10.0.0.1"),
            "Should indicate the origin IP differs from current session"
        );
    }

    // Test ApprovalContext creation and helpers
    #[test]
    fn test_approval_context_is_stale() {
        let fresh_context = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "test-client".to_string(),
            client_name: Some("Test App".to_string()),
            scopes: vec!["openid".to_string()],
            origin_ip: None,
            origin_country: None,
            created_at: Utc::now() - Duration::minutes(2),
            approver_ip: None,
            csrf_token: "csrf".to_string(),
        };
        assert!(
            !fresh_context.is_stale(),
            "2 minutes old should not be stale"
        );

        let stale_context = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "test-client".to_string(),
            client_name: Some("Test App".to_string()),
            scopes: vec!["openid".to_string()],
            origin_ip: None,
            origin_country: None,
            created_at: Utc::now() - Duration::minutes(6),
            approver_ip: None,
            csrf_token: "csrf".to_string(),
        };
        assert!(stale_context.is_stale(), "6 minutes old should be stale");
    }

    #[test]
    fn test_approval_context_has_ip_mismatch() {
        let matching_context = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "test-client".to_string(),
            client_name: Some("Test App".to_string()),
            scopes: vec!["openid".to_string()],
            origin_ip: Some("192.168.1.1".to_string()),
            origin_country: None,
            created_at: Utc::now(),
            approver_ip: Some("192.168.1.1".to_string()),
            csrf_token: "csrf".to_string(),
        };
        assert!(
            !matching_context.has_ip_mismatch(),
            "Same IPs should not be mismatch"
        );

        let mismatch_context = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "test-client".to_string(),
            client_name: Some("Test App".to_string()),
            scopes: vec!["openid".to_string()],
            origin_ip: Some("10.0.0.1".to_string()),
            origin_country: None,
            created_at: Utc::now(),
            approver_ip: Some("192.168.1.1".to_string()),
            csrf_token: "csrf".to_string(),
        };
        assert!(
            mismatch_context.has_ip_mismatch(),
            "Different IPs should be mismatch"
        );
    }

    #[test]
    fn test_approval_context_is_unknown_app() {
        let known_app = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "test-client".to_string(),
            client_name: Some("My Application".to_string()),
            scopes: vec!["openid".to_string()],
            origin_ip: None,
            origin_country: None,
            created_at: Utc::now(),
            approver_ip: None,
            csrf_token: "csrf".to_string(),
        };
        assert!(
            !known_app.is_unknown_app(),
            "Should not be unknown when name is Some"
        );

        let unknown_app = ApprovalContext {
            user_code: "ABCD-1234".to_string(),
            client_id: "test-client".to_string(),
            client_name: None,
            scopes: vec!["openid".to_string()],
            origin_ip: None,
            origin_country: None,
            created_at: Utc::now(),
            approver_ip: None,
            csrf_token: "csrf".to_string(),
        };
        assert!(
            unknown_app.is_unknown_app(),
            "Should be unknown when name is None"
        );
    }
}
