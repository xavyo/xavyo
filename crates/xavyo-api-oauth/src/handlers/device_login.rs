//! Device code login handlers for F112.
//!
//! Endpoints:
//! - GET /device/login - Display login form during device code flow
//! - POST /device/login - Authenticate user during device code flow (browser form)
//! - GET /device/mfa - Display MFA form during device code flow
//! - POST /device/login/mfa - Complete MFA verification during device login (browser form)
//!
//! These handlers process form submissions from the device verification HTML pages
//! and return HTML redirects or rendered error pages (pure browser flow).

use crate::middleware::session_cookie::{
    create_csrf_cookie, create_session_cookie, extract_csrf_cookie, extract_session_cookie,
    generate_csrf_token, validate_csrf_token,
};
use crate::models::{DeviceLoginErrorResponse, DeviceLoginRequest, DeviceMfaRequest};
use crate::router::OAuthState;
use crate::services::DeviceCodeService;
use axum::{
    extract::{Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Redirect, Response},
    Extension, Form,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use validator::Validate;
use xavyo_api_auth::services::{
    AuditService, AuthService, LockoutService, MfaService, SessionService,
};
use xavyo_core::TenantId;
use xavyo_db::{AuthMethod, FailureReason};

/// Query parameters for GET /device/login.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceLoginQuery {
    /// User code from device flow.
    pub user_code: String,
}

/// Query parameters for GET /device/mfa.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceMfaQuery {
    /// MFA session ID from login response.
    pub session_id: Uuid,
    /// User code from device flow.
    pub user_code: String,
}

/// Extract `tenant_id` from X-Tenant-ID header.
fn extract_tenant_id(headers: &HeaderMap) -> Result<Uuid, DeviceLoginErrorResponse> {
    let tenant_header = headers.get("X-Tenant-ID").ok_or_else(|| {
        DeviceLoginErrorResponse::validation_error("X-Tenant-ID header is required")
    })?;

    let tenant_str = tenant_header.to_str().map_err(|_| {
        DeviceLoginErrorResponse::validation_error("Invalid X-Tenant-ID header value")
    })?;

    Uuid::parse_str(tenant_str)
        .map_err(|_| DeviceLoginErrorResponse::validation_error("X-Tenant-ID must be a valid UUID"))
}

/// Display login form during device code flow.
///
/// GET /device/login?user_code=XXXX-XXXX
///
/// Renders the login form HTML page with CSRF token cookie.
/// This is called when the user needs to authenticate before approving a device.
#[utoipa::path(
    get,
    path = "/device/login",
    params(
        ("user_code" = String, Query, description = "User code from device flow")
    ),
    responses(
        (status = 200, description = "Login form HTML page"),
        (status = 400, description = "Invalid user_code"),
    ),
    tag = "Device Code Flow"
)]
pub async fn device_login_page_handler(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Query(query): Query<DeviceLoginQuery>,
) -> Response {
    // Determine secure flag based on environment
    let is_secure = state.is_production();

    // Extract tenant_id from header
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(tid) => tid,
        Err(e) => {
            warn!(
                user_code = %query.user_code,
                error = %e.error,
                "Device login page: missing or invalid tenant ID"
            );
            let csrf_token = generate_csrf_token();
            let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);
            let html = render_login_page(
                &query.user_code,
                "Unknown",
                &[],
                Some("Invalid request. Please try again."),
                &csrf_token,
            );
            let mut response = Html(html).into_response();
            if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
                response.headers_mut().insert(SET_COOKIE, cookie_value);
            }
            return response;
        }
    };

    // Verify device code exists and is pending
    let device_service = DeviceCodeService::new(state.pool.clone());
    let device_code = match device_service
        .find_pending_by_user_code(tenant_id, &query.user_code)
        .await
    {
        Ok(Some(code)) => code,
        Ok(None) => {
            info!(
                user_code = %query.user_code,
                tenant_id = %tenant_id,
                "Device login page: user code not found or expired"
            );
            let csrf_token = generate_csrf_token();
            let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);
            let html = render_login_page(
                &query.user_code,
                "Unknown",
                &[],
                Some("Device code not found or expired. Please restart the CLI login."),
                &csrf_token,
            );
            let mut response = Html(html).into_response();
            if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
                response.headers_mut().insert(SET_COOKIE, cookie_value);
            }
            return response;
        }
        Err(e) => {
            warn!(error = %e, "Failed to find device code");
            let csrf_token = generate_csrf_token();
            let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);
            let html = render_login_page(
                &query.user_code,
                "Unknown",
                &[],
                Some("An error occurred. Please try again."),
                &csrf_token,
            );
            let mut response = Html(html).into_response();
            if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
                response.headers_mut().insert(SET_COOKIE, cookie_value);
            }
            return response;
        }
    };

    // Generate CSRF token and render login page
    let csrf_token = generate_csrf_token();
    let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);
    let html = render_login_page(
        &query.user_code,
        &device_code.client_id,
        &device_code.scopes,
        None,
        &csrf_token,
    );

    let mut response = Html(html).into_response();
    if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
        response.headers_mut().insert(SET_COOKIE, cookie_value);
    }
    response
}

/// Display MFA form during device code flow.
///
/// GET /device/mfa?session_id=UUID&user_code=XXXX-XXXX
///
/// Renders the MFA verification form HTML page with CSRF token cookie.
/// This is called after successful password authentication when MFA is required.
#[utoipa::path(
    get,
    path = "/device/mfa",
    params(
        ("session_id" = Uuid, Query, description = "MFA session ID from login"),
        ("user_code" = String, Query, description = "User code from device flow")
    ),
    responses(
        (status = 200, description = "MFA form HTML page"),
        (status = 400, description = "Invalid session"),
    ),
    tag = "Device Code Flow"
)]
pub async fn device_mfa_page_handler(
    State(state): State<OAuthState>,
    Query(query): Query<DeviceMfaQuery>,
) -> Response {
    // Determine secure flag based on environment
    let is_secure = state.is_production();

    // Verify MFA session exists and is valid
    match lookup_mfa_session(&state.pool, query.session_id).await {
        Ok(Some((_, _, stored_user_code))) => {
            // Verify user_code matches
            if stored_user_code != query.user_code {
                return Html(render_session_expired_page(&query.user_code)).into_response();
            }

            // Generate CSRF token and render MFA page
            let csrf_token = generate_csrf_token();
            let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);
            let html = render_mfa_page(&query.user_code, &query.session_id, None, &csrf_token);

            let mut response = Html(html).into_response();
            if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
                response.headers_mut().insert(SET_COOKIE, cookie_value);
            }
            response
        }
        Ok(None) => {
            // MFA session not found or expired
            Html(render_session_expired_page(&query.user_code)).into_response()
        }
        Err(e) => {
            warn!(error = %e, "Failed to lookup MFA session");
            Html(render_session_expired_page(&query.user_code)).into_response()
        }
    }
}

/// Handle device code login (browser form submission).
///
/// POST /device/login
///
/// Authenticates a user during the device code flow. This endpoint receives form data
/// from the login HTML page and returns:
/// - On success: HTTP redirect to device authorization page with session cookie
/// - On MFA required: HTTP redirect to MFA verification page
/// - On error: Re-renders login page with error message
///
/// This is a pure browser flow - no JSON responses.
#[utoipa::path(
    post,
    path = "/device/login",
    request_body = DeviceLoginRequest,
    responses(
        (status = 302, description = "Redirect to authorization or MFA page"),
        (status = 200, description = "Login page with error message (HTML)"),
    ),
    tag = "Device Code Flow"
)]
#[allow(clippy::too_many_arguments)]
pub async fn device_login_handler(
    State(state): State<OAuthState>,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(lockout_service): Extension<Arc<LockoutService>>,
    Extension(mfa_service): Extension<Arc<MfaService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    headers: HeaderMap,
    Form(request): Form<DeviceLoginRequest>,
) -> Response {
    // Determine secure flag based on environment
    let is_secure = state.is_production();

    // Helper to render login page with error and new CSRF token
    let render_login_error_with_csrf =
        |user_code: &str, client_id: &str, scopes: &[String], error: &str| {
            let csrf_token = generate_csrf_token();
            let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);
            let html = render_login_page(user_code, client_id, scopes, Some(error), &csrf_token);
            let mut response = Html(html).into_response();
            if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
                response.headers_mut().insert(SET_COOKIE, cookie_value);
            }
            response
        };

    // Validate CSRF token first
    let cookie_token = extract_csrf_cookie(&headers);
    let form_token = request.csrf_token.as_deref();

    match (cookie_token, form_token) {
        (Some(ref ct), Some(ft)) if validate_csrf_token(ct, ft) => {
            // CSRF valid, continue
        }
        _ => {
            // CSRF validation failed
            return render_login_error_with_csrf(
                &request.user_code,
                "Unknown",
                &[],
                "Session expired. Please try again.",
            );
        }
    }

    // Validate request
    if let Err(e) = request.validate() {
        let errors: Vec<String> = e
            .field_errors()
            .values()
            .flat_map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(std::string::ToString::to_string))
            })
            .collect();
        return render_login_error_with_csrf(
            &request.user_code,
            "Unknown",
            &[],
            &errors.join(", "),
        );
    }

    // Extract tenant_id from header
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(tid) => tid,
        Err(_) => {
            return render_login_error_with_csrf(
                &request.user_code,
                "Unknown",
                &[],
                "Invalid request. Please try again.",
            );
        }
    };

    let tenant_id_typed = TenantId::from_uuid(tenant_id);

    // Extract client info for audit
    let ip_address = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok());
    let ip_str = ip_address.map(|ip: std::net::IpAddr| ip.to_string());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Verify device code exists and is pending
    let device_service = DeviceCodeService::new(state.pool.clone());
    let device_code = match device_service
        .find_pending_by_user_code(tenant_id, &request.user_code)
        .await
    {
        Ok(Some(code)) => code,
        Ok(None) => {
            return render_login_error_with_csrf(
                &request.user_code,
                "Unknown",
                &[],
                "Device code not found or expired. Please restart the CLI login.",
            );
        }
        Err(e) => {
            warn!(error = %e, "Failed to find device code");
            return render_login_error_with_csrf(
                &request.user_code,
                "Unknown",
                &[],
                "An error occurred. Please try again.",
            );
        }
    };

    let client_id = device_code.client_id.clone();
    let scopes = device_code.scopes.clone();

    // First, try to get the user to check lockout (if user exists)
    let existing_user = auth_service
        .get_user_by_email(tenant_id_typed, &request.email)
        .await
        .ok()
        .flatten();

    // Check if account is locked (only if user exists)
    if let Some(ref user) = existing_user {
        match lockout_service
            .check_account_locked(user.id, tenant_id)
            .await
        {
            Ok(status) => {
                if status.is_locked {
                    if let Some(locked_until) = status.locked_until {
                        return render_login_error_with_csrf(
                            &request.user_code,
                            &client_id,
                            &scopes,
                            &format!(
                                "Account is locked. Try again after {}.",
                                locked_until.format("%Y-%m-%d %H:%M:%S UTC")
                            ),
                        );
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to check lockout status");
            }
        }
    }

    // Authenticate user
    let user = match auth_service
        .login(tenant_id_typed, &request.email, &request.password)
        .await
    {
        Ok(user) => user,
        Err(xavyo_api_auth::ApiAuthError::InvalidCredentials) => {
            // Record failed attempt if user exists
            if let Some(ref user) = existing_user {
                let _ = lockout_service
                    .record_failed_attempt(
                        user.id,
                        tenant_id,
                        &request.email,
                        ip_str.as_deref(),
                        FailureReason::InvalidPassword,
                    )
                    .await;
            }

            // Audit log
            let _ = audit_service
                .record_login_attempt(
                    tenant_id,
                    xavyo_api_auth::RecordLoginAttemptInput {
                        user_id: existing_user.as_ref().map(|u| u.id),
                        email: request.email.clone(),
                        success: false,
                        failure_reason: Some("invalid_credentials".to_string()),
                        auth_method: AuthMethod::Password,
                        ip_address: ip_str.clone(),
                        user_agent: user_agent.clone(),
                        device_fingerprint: None,
                        geo_country: None,
                        geo_city: None,
                    },
                )
                .await;

            return render_login_error_with_csrf(
                &request.user_code,
                &client_id,
                &scopes,
                "Invalid email or password.",
            );
        }
        Err(xavyo_api_auth::ApiAuthError::AccountInactive) => {
            return render_login_error_with_csrf(
                &request.user_code,
                &client_id,
                &scopes,
                "Account is deactivated. Please contact support.",
            );
        }
        // F111: Handle unverified email explicitly with actionable message
        Err(xavyo_api_auth::ApiAuthError::EmailNotVerified) => {
            return render_login_error_with_csrf(
                &request.user_code,
                &client_id,
                &scopes,
                "Please verify your email address before logging in. Check your inbox for the verification link.",
            );
        }
        Err(e) => {
            warn!(error = %e, "Login failed");
            return render_login_error_with_csrf(
                &request.user_code,
                &client_id,
                &scopes,
                "An error occurred. Please try again.",
            );
        }
    };

    // Check if user's account is active
    if !user.is_active {
        return render_login_error_with_csrf(
            &request.user_code,
            &client_id,
            &scopes,
            "Account is deactivated. Please contact support.",
        );
    }

    // Check if MFA is required
    let mfa_enabled = mfa_service
        .has_mfa_enabled(tenant_id, user.id)
        .await
        .unwrap_or(false);

    if mfa_enabled {
        // Store MFA session in database for later verification
        let mfa_session_id = Uuid::new_v4();

        // Store MFA session (user_id, tenant_id, user_code, expires_at)
        if let Err(e) = store_mfa_session(
            &state.pool,
            mfa_session_id,
            user.id,
            tenant_id,
            &request.user_code,
        )
        .await
        {
            warn!(error = %e, "Failed to store MFA session");
            return render_login_error_with_csrf(
                &request.user_code,
                &client_id,
                &scopes,
                "An error occurred. Please try again.",
            );
        }

        info!(
            user_id = %user.id,
            tenant_id = %tenant_id,
            mfa_session_id = %mfa_session_id,
            "MFA required for device login"
        );

        // Redirect to MFA page with session ID
        let redirect_url = format!(
            "/device/mfa?session_id={}&user_code={}",
            mfa_session_id, request.user_code
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Create session
    let session = match session_service
        .create_session(
            user.id,
            tenant_id,
            None, // No refresh token for device flow session
            user_agent.as_deref(),
            ip_str.as_deref(),
        )
        .await
    {
        Ok(session) => session,
        Err(e) => {
            warn!(error = %e, "Failed to create session");
            return render_login_error_with_csrf(
                &request.user_code,
                &client_id,
                &scopes,
                "Failed to create session. Please try again.",
            );
        }
    };

    // Reset failed attempts on successful login
    let _ = lockout_service
        .reset_failed_attempts(user.id, tenant_id)
        .await;

    // Audit log successful login
    let _ = audit_service
        .record_login_attempt(
            tenant_id,
            xavyo_api_auth::RecordLoginAttemptInput {
                user_id: Some(user.id),
                email: request.email.clone(),
                success: true,
                failure_reason: None,
                auth_method: AuthMethod::Password,
                ip_address: ip_str,
                user_agent,
                device_fingerprint: None,
                geo_country: None,
                geo_city: None,
            },
        )
        .await;

    info!(
        user_id = %user.id,
        session_id = %session.id,
        tenant_id = %tenant_id,
        device_code_id = %device_code.id,
        "Device login successful"
    );

    // Determine if we should use Secure flag (production vs development)
    let is_secure = state.is_production();
    let cookie_value = create_session_cookie(session.id, is_secure);

    // Build redirect response with session cookie
    let redirect_url = format!("/device/authorize?user_code={}", request.user_code);
    let mut response = Redirect::to(&redirect_url).into_response();

    if let Ok(value) = HeaderValue::from_str(&cookie_value) {
        response.headers_mut().insert(SET_COOKIE, value);
    }

    response
}

/// Store MFA session in database for verification.
async fn store_mfa_session(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    user_id: Uuid,
    tenant_id: Uuid,
    user_code: &str,
) -> Result<(), sqlx::Error> {
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

    sqlx::query(
        r"
        INSERT INTO device_mfa_sessions (id, user_id, tenant_id, user_code, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (id) DO UPDATE SET
            user_id = EXCLUDED.user_id,
            tenant_id = EXCLUDED.tenant_id,
            user_code = EXCLUDED.user_code,
            expires_at = EXCLUDED.expires_at
        ",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(tenant_id)
    .bind(user_code)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Look up MFA session from database.
async fn lookup_mfa_session(
    pool: &sqlx::PgPool,
    session_id: Uuid,
) -> Result<Option<(Uuid, Uuid, String)>, sqlx::Error> {
    let result = sqlx::query_as::<_, (Uuid, Uuid, String, chrono::DateTime<chrono::Utc>)>(
        r"
        SELECT user_id, tenant_id, user_code, expires_at
        FROM device_mfa_sessions
        WHERE id = $1
        ",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    match result {
        Some((user_id, tenant_id, user_code, expires_at)) => {
            if expires_at < chrono::Utc::now() {
                // Session expired, delete it
                let _ = sqlx::query("DELETE FROM device_mfa_sessions WHERE id = $1")
                    .bind(session_id)
                    .execute(pool)
                    .await;
                Ok(None)
            } else {
                Ok(Some((user_id, tenant_id, user_code)))
            }
        }
        None => Ok(None),
    }
}

/// Delete MFA session after successful verification.
async fn delete_mfa_session(pool: &sqlx::PgPool, session_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM device_mfa_sessions WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Render login page HTML (for displaying errors).
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

/// Simple HTML escaping.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Handle MFA verification during device login (browser form submission).
///
/// POST /device/login/mfa
///
/// Verifies the TOTP code and completes the device login flow.
/// On success: HTTP redirect to device authorization page with session cookie.
/// On error: Re-renders MFA page with error message.
#[utoipa::path(
    post,
    path = "/device/login/mfa",
    request_body = DeviceMfaRequest,
    responses(
        (status = 302, description = "Redirect to authorization page"),
        (status = 200, description = "MFA page with error message (HTML)"),
    ),
    tag = "Device Code Flow"
)]
#[allow(clippy::too_many_arguments)]
pub async fn device_mfa_handler(
    State(state): State<OAuthState>,
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(mfa_service): Extension<Arc<MfaService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    headers: HeaderMap,
    Form(request): Form<DeviceMfaRequest>,
) -> Response {
    // Determine secure flag based on environment
    let is_secure = state.is_production();

    // Helper to render MFA page with error and new CSRF token
    let render_mfa_error_with_csrf = |user_code: &str, session_id: &Uuid, error: &str| {
        let csrf_token = generate_csrf_token();
        let csrf_cookie = create_csrf_cookie(&csrf_token, is_secure);
        let html = render_mfa_page(user_code, session_id, Some(error), &csrf_token);
        let mut response = Html(html).into_response();
        if let Ok(cookie_value) = HeaderValue::from_str(&csrf_cookie) {
            response.headers_mut().insert(SET_COOKIE, cookie_value);
        }
        response
    };

    // Validate CSRF token first
    let cookie_token = extract_csrf_cookie(&headers);
    let form_token = request.csrf_token.as_deref();

    match (cookie_token, form_token) {
        (Some(ref ct), Some(ft)) if validate_csrf_token(ct, ft) => {
            // CSRF valid, continue
        }
        _ => {
            // CSRF validation failed
            return render_mfa_error_with_csrf(
                &request.user_code,
                &request.mfa_session_id,
                "Session expired. Please try again.",
            );
        }
    }

    // Validate request
    if let Err(e) = request.validate() {
        let errors: Vec<String> = e
            .field_errors()
            .values()
            .flat_map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(std::string::ToString::to_string))
            })
            .collect();
        return render_mfa_error_with_csrf(
            &request.user_code,
            &request.mfa_session_id,
            &errors.join(", "),
        );
    }

    // Look up MFA session
    let (user_id, tenant_id, user_code) =
        match lookup_mfa_session(&state.pool, request.mfa_session_id).await {
            Ok(Some(session)) => session,
            Ok(None) => {
                warn!(
                    mfa_session_id = %request.mfa_session_id,
                    "MFA session not found or expired"
                );
                return Html(render_session_expired_page(&request.user_code)).into_response();
            }
            Err(e) => {
                warn!(error = %e, "Failed to lookup MFA session");
                return render_mfa_error_with_csrf(
                    &request.user_code,
                    &request.mfa_session_id,
                    "An error occurred. Please try again.",
                );
            }
        };

    // Extract client info for MFA verification
    let ip_for_mfa = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok());
    let user_agent_for_mfa = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Verify TOTP code using the correct method
    if let Err(e) = mfa_service
        .verify_login_code(
            user_id,
            tenant_id,
            &request.code,
            ip_for_mfa,
            user_agent_for_mfa.clone(),
        )
        .await
    {
        let error_msg = match &e {
            xavyo_api_auth::ApiAuthError::InvalidTotpCode => {
                "Invalid verification code. Please try again."
            }
            xavyo_api_auth::ApiAuthError::TotpVerificationLocked => {
                "Too many failed attempts. Please try again later."
            }
            xavyo_api_auth::ApiAuthError::MfaNotEnabled => "MFA is not enabled for this account.",
            _ => {
                warn!(error = %e, "TOTP verification failed");
                "Verification failed. Please try again."
            }
        };
        return render_mfa_error_with_csrf(&user_code, &request.mfa_session_id, error_msg);
    }

    // Delete MFA session
    let _ = delete_mfa_session(&state.pool, request.mfa_session_id).await;

    // Extract client info for session
    let ip_str = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Create session
    let session = match session_service
        .create_session(
            user_id,
            tenant_id,
            None,
            user_agent.as_deref(),
            ip_str.as_deref(),
        )
        .await
    {
        Ok(session) => session,
        Err(e) => {
            warn!(error = %e, "Failed to create session");
            return render_mfa_error_with_csrf(
                &user_code,
                &request.mfa_session_id,
                "Failed to create session. Please try again.",
            );
        }
    };

    // Audit log successful MFA
    let _ = audit_service
        .record_login_attempt(
            tenant_id,
            xavyo_api_auth::RecordLoginAttemptInput {
                user_id: Some(user_id),
                email: String::new(), // Email not available in MFA flow
                success: true,
                failure_reason: None,
                auth_method: AuthMethod::Mfa,
                ip_address: ip_str,
                user_agent,
                device_fingerprint: None,
                geo_country: None,
                geo_city: None,
            },
        )
        .await;

    info!(
        user_id = %user_id,
        session_id = %session.id,
        tenant_id = %tenant_id,
        "Device MFA verification successful"
    );

    // Build redirect response with session cookie
    let is_secure = state.is_production();
    let cookie_value = create_session_cookie(session.id, is_secure);

    let redirect_url = format!("/device/authorize?user_code={user_code}");
    let mut response = Redirect::to(&redirect_url).into_response();

    if let Ok(value) = HeaderValue::from_str(&cookie_value) {
        response.headers_mut().insert(SET_COOKIE, value);
    }

    response
}

/// Render MFA verification page HTML.
fn render_mfa_page(
    user_code: &str,
    session_id: &Uuid,
    error_message: Option<&str>,
    csrf_token: &str,
) -> String {
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
    <title>Two-Factor Authentication - xavyo</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; color: #333; text-align: center; }}
        .subtitle {{ color: #666; margin-bottom: 1.5rem; text-align: center; font-size: 0.9rem; }}
        .form-group {{ margin-bottom: 1rem; }}
        label {{ display: block; margin-bottom: 0.25rem; color: #333; font-weight: 500; font-size: 0.875rem; }}
        input[type="text"] {{ width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1.5rem; text-align: center; letter-spacing: 0.25em; }}
        input:focus {{ outline: none; border-color: #0066cc; }}
        button {{ width: 100%; padding: 0.75rem; background: #0066cc; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-top: 0.5rem; }}
        button:hover {{ background: #0052a3; }}
        .error {{ background: #fee; border: 1px solid #fcc; color: #c00; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; text-align: center; font-size: 0.875rem; }}
        .hint {{ font-size: 0.875rem; color: #999; text-align: center; margin-top: 0.5rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Two-Factor Authentication</h1>
        <p class="subtitle">Enter the code from your authenticator app</p>

        {error_html}

        <form method="post" action="/device/login/mfa">
            <input type="hidden" name="user_code" value="{user_code}" />
            <input type="hidden" name="mfa_session_id" value="{session_id}" />
            <input type="hidden" name="csrf_token" value="{csrf_token}" />
            <div class="form-group">
                <label for="code">Verification Code</label>
                <input type="text" id="code" name="code" required maxlength="6" pattern="[0-9]{{6}}" autocomplete="one-time-code" inputmode="numeric" />
                <p class="hint">Enter the 6-digit code</p>
            </div>
            <button type="submit">Verify</button>
        </form>
    </div>
</body>
</html>"#,
        user_code = html_escape(user_code),
        session_id = session_id,
        error_html = error_html,
        csrf_token = html_escape(csrf_token),
    )
}

/// Render session expired page.
fn render_session_expired_page(user_code: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Expired - xavyo</title>
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
        <div class="icon">⏱</div>
        <h1>Session Expired</h1>
        <p>Your verification session has expired. Please sign in again to continue.</p>
        <a href="/device/verify?user_code={user_code}">Sign In Again</a>
    </div>
</body>
</html>"#,
        user_code = html_escape(user_code),
    )
}

/// Get the current user from session cookie.
///
/// Utility function to extract user from session for the device authorize handler.
/// Returns (`user_id`, `tenant_id`) if session is valid and active.
pub async fn get_user_from_session(
    headers: &HeaderMap,
    session_service: &SessionService,
    tenant_id: Uuid,
) -> Option<(Uuid, Uuid)> {
    // Extract session ID from cookie
    let session_id = extract_session_cookie(headers)?;

    // Look up session
    let session = session_service
        .get_session(session_id, tenant_id)
        .await
        .ok()??;

    // Check session is active (revoked_at is None means active)
    if session.revoked_at.is_some() {
        return None;
    }

    // Check session hasn't expired
    if session.expires_at < chrono::Utc::now() {
        return None;
    }

    Some((session.user_id, session.tenant_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tenant_id_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Tenant-ID",
            HeaderValue::from_static("550e8400-e29b-41d4-a716-446655440000"),
        );

        let result = extract_tenant_id(&headers);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
        );
    }

    #[test]
    fn test_extract_tenant_id_missing() {
        let headers = HeaderMap::new();
        let result = extract_tenant_id(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_tenant_id_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Tenant-ID", HeaderValue::from_static("not-a-uuid"));

        let result = extract_tenant_id(&headers);
        assert!(result.is_err());
    }
}
