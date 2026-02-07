//! Login endpoint handler.
//!
//! POST /auth/login - Authenticate user and issue tokens.

use crate::error::ApiAuthError;
use crate::models::{LoginRequest, MfaMethod, MfaRequiredResponse, TokenResponse};
use crate::services::security_audit::{SecurityAudit, SecurityEventType};
use crate::services::{
    AlertService, AuditService, AuthService, DevicePolicyService, DeviceService, LockoutService,
    LoginRiskContext, MfaService, RecordLoginAttemptInput, RiskEnforcementService, SessionService,
    TokenService, WebAuthnService,
};
use axum::extract::FromRequest;
use axum::http::StatusCode;
use axum::{extract::ConnectInfo, Extension, Json};
use serde::Serialize;
use sqlx::PgPool;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use validator::Validate;
use xavyo_core::TenantId;
use xavyo_db::{AuthMethod, FailureReason, UserRole};
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Login response that can be either full tokens or MFA required.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    /// Full tokens when MFA is not required or already verified.
    Success(TokenResponse),
    /// MFA required response with partial token.
    MfaRequired(MfaRequiredResponse),
}

/// Handle user login.
///
/// Authenticates the user with email and password, then either issues
/// access and refresh tokens (if MFA is not enabled) or returns a
/// partial token requiring MFA verification.
#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = TokenResponse),
        (status = 200, description = "MFA required", body = MfaRequiredResponse),
        (status = 401, description = "Invalid credentials or account locked"),
        (status = 403, description = "Account is inactive"),
        (status = 429, description = "Rate limit exceeded"),
    ),
    tag = "Authentication"
)]
#[allow(clippy::too_many_arguments)]
pub async fn login_handler(
    Extension(pool): Extension<PgPool>,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(token_service): Extension<Arc<TokenService>>,
    Extension(mfa_service): Extension<Arc<MfaService>>,
    Extension(webauthn_service): Extension<Arc<WebAuthnService>>,
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(lockout_service): Extension<Arc<LockoutService>>,
    Extension(audit_service): Extension<Arc<AuditService>>,
    Extension(alert_service): Extension<Arc<AlertService>>,
    Extension(device_service): Extension<Arc<DeviceService>>,
    Extension(device_policy_service): Extension<Arc<DevicePolicyService>>,
    Extension(risk_enforcement_service): Extension<Arc<RiskEnforcementService>>,
    Extension(tenant_id): Extension<TenantId>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    raw_request: axum::extract::Request,
) -> Result<(StatusCode, Json<LoginResponse>), ApiAuthError> {
    // F085: Extract optional event publisher from request extensions
    let publisher = raw_request.extensions().get::<EventPublisher>().cloned();

    // Extract headers and body from the raw request
    let (parts, body) = raw_request.into_parts();
    let headers = parts.headers.clone();
    let body_request = axum::http::Request::from_parts(parts, body);
    let Json(request) = Json::<LoginRequest>::from_request(body_request, &())
        .await
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    // Validate request
    request.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .values()
            .flat_map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(std::string::ToString::to_string))
            })
            .collect();
        ApiAuthError::Validation(errors.join(", "))
    })?;

    // Extract client info early for audit logging
    let ip_address: Option<IpAddr> = Some(addr.ip());
    let ip_str = ip_address.map(|ip| ip.to_string());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    // Extract device fingerprint from custom header (SHA-256 hash generated client-side)
    let device_fingerprint = headers
        .get("X-Device-Fingerprint")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Authenticate user (this also handles unknown email with generic error)
    let user = match auth_service
        .login(tenant_id, &request.email, &request.password)
        .await
    {
        Ok(user) => user,
        Err(ApiAuthError::InvalidCredentials) => {
            // Try to find user to record failed attempt
            if let Ok(Some(user)) = auth_service
                .get_user_by_email(tenant_id, &request.email)
                .await
            {
                // Record failed attempt and check lockout (F024)
                let lockout_status = lockout_service
                    .record_failed_attempt(
                        user.id,
                        *tenant_id.as_uuid(),
                        &request.email,
                        ip_str.as_deref(),
                        FailureReason::InvalidPassword,
                    )
                    .await?;

                // Record audit trail (F025) - with device/location tracking
                let _ = audit_service
                    .record_login_attempt(
                        *tenant_id.as_uuid(),
                        RecordLoginAttemptInput {
                            user_id: Some(user.id),
                            email: request.email.clone(),
                            success: false,
                            failure_reason: Some("invalid_password".to_string()),
                            auth_method: AuthMethod::Password,
                            ip_address: ip_str.clone(),
                            user_agent: user_agent.clone(),
                            device_fingerprint: device_fingerprint.clone(),
                            geo_country: None, // TODO: Add geo lookup
                            geo_city: None,
                        },
                    )
                    .await;

                // Check failed attempts threshold for alert (F025)
                let _ = alert_service
                    .check_failed_attempts_threshold(
                        *tenant_id.as_uuid(),
                        user.id,
                        &request.email,
                        ip_str.as_deref(),
                    )
                    .await;

                if lockout_status.is_locked {
                    if let Some(until) = lockout_status.locked_until {
                        return Err(ApiAuthError::AccountLockedUntil(until.to_rfc3339()));
                    }
                    return Err(ApiAuthError::AccountLocked);
                }
            } else {
                // Unknown email - log but don't reveal
                // Best-effort: don't propagate DB errors (e.g. non-existent tenant)
                if let Err(e) = lockout_service
                    .record_login_attempt(
                        *tenant_id.as_uuid(),
                        None,
                        &request.email,
                        ip_str.as_deref(),
                        FailureReason::UnknownEmail,
                    )
                    .await
                {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        error = %e,
                        "Failed to record login attempt for unknown email"
                    );
                }

                // Record audit trail for unknown email (F025)
                let _ = audit_service
                    .record_login_attempt(
                        *tenant_id.as_uuid(),
                        RecordLoginAttemptInput {
                            user_id: None,
                            email: request.email.clone(),
                            success: false,
                            failure_reason: Some("unknown_email".to_string()),
                            auth_method: AuthMethod::Password,
                            ip_address: ip_str.clone(),
                            user_agent: user_agent.clone(),
                            device_fingerprint: device_fingerprint.clone(),
                            geo_country: None,
                            geo_city: None,
                        },
                    )
                    .await;
            }
            // F082-US8: Emit structured security audit event for login failure
            SecurityAudit::emit(
                SecurityEventType::LoginFailed,
                Some(*tenant_id.as_uuid()),
                None,
                ip_str.as_deref(),
                user_agent.as_deref(),
                "failure",
                "Login failed: invalid credentials",
            );
            // F085: Publish auth.login.failed webhook event
            if let Some(ref publisher) = publisher {
                publisher.publish(WebhookEvent {
                    event_id: uuid::Uuid::new_v4(),
                    event_type: "auth.login.failed".to_string(),
                    tenant_id: *tenant_id.as_uuid(),
                    actor_id: None,
                    timestamp: chrono::Utc::now(),
                    data: serde_json::json!({
                        "ip_address": ip_str,
                        "user_agent": user_agent,
                    }),
                });
            }
            return Err(ApiAuthError::InvalidCredentials);
        }
        Err(ApiAuthError::AccountInactive) => {
            // Record the attempt for inactive accounts
            if let Ok(Some(user)) = auth_service
                .get_user_by_email(tenant_id, &request.email)
                .await
            {
                if let Err(e) = lockout_service
                    .record_login_attempt(
                        *tenant_id.as_uuid(),
                        Some(user.id),
                        &request.email,
                        ip_str.as_deref(),
                        FailureReason::AccountInactive,
                    )
                    .await
                {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        error = %e,
                        "Failed to record login attempt for inactive account"
                    );
                }

                // Record audit trail for inactive account (F025)
                let _ = audit_service
                    .record_login_attempt(
                        *tenant_id.as_uuid(),
                        RecordLoginAttemptInput {
                            user_id: Some(user.id),
                            email: request.email.clone(),
                            success: false,
                            failure_reason: Some("account_inactive".to_string()),
                            auth_method: AuthMethod::Password,
                            ip_address: ip_str.clone(),
                            user_agent: user_agent.clone(),
                            device_fingerprint: device_fingerprint.clone(),
                            geo_country: None,
                            geo_city: None,
                        },
                    )
                    .await;
            }
            return Err(ApiAuthError::AccountInactive);
        }
        Err(e) => return Err(e),
    };

    let user_id = user.user_id();
    let tenant_id_val = user.tenant_id();

    // Check if account is locked (handles auto-unlock)
    let lockout_status = lockout_service
        .check_account_locked(*user_id.as_uuid(), *tenant_id_val.as_uuid())
        .await?;

    if lockout_status.is_locked {
        // Record the attempt for locked account (F024)
        lockout_service
            .record_login_attempt(
                *tenant_id_val.as_uuid(),
                Some(*user_id.as_uuid()),
                &request.email,
                ip_str.as_deref(),
                FailureReason::AccountLocked,
            )
            .await?;

        // Record audit trail for locked account (F025)
        let _ = audit_service
            .record_login_attempt(
                *tenant_id_val.as_uuid(),
                RecordLoginAttemptInput {
                    user_id: Some(*user_id.as_uuid()),
                    email: request.email.clone(),
                    success: false,
                    failure_reason: Some("account_locked".to_string()),
                    auth_method: AuthMethod::Password,
                    ip_address: ip_str.clone(),
                    user_agent: user_agent.clone(),
                    device_fingerprint: device_fingerprint.clone(),
                    geo_country: None,
                    geo_city: None,
                },
            )
            .await;

        if let Some(until) = lockout_status.locked_until {
            return Err(ApiAuthError::AccountLockedUntil(until.to_rfc3339()));
        }
        return Err(ApiAuthError::AccountLocked);
    }

    // Check if password is expired
    if user.needs_password_change() {
        // Don't lock out for expired password, but don't allow full access
        // Return password expired response
        return Err(ApiAuthError::PasswordExpired);
    }

    // Reset failed attempts on successful authentication
    lockout_service
        .reset_failed_attempts(*user_id.as_uuid(), *tenant_id_val.as_uuid())
        .await?;

    // Record successful login attempt (F025) - with device/location tracking
    let audit_result = audit_service
        .record_login_attempt(
            *tenant_id_val.as_uuid(),
            RecordLoginAttemptInput {
                user_id: Some(*user_id.as_uuid()),
                email: request.email.clone(),
                success: true,
                failure_reason: None,
                auth_method: AuthMethod::Password,
                ip_address: ip_str.clone(),
                user_agent: user_agent.clone(),
                device_fingerprint: device_fingerprint.clone(),
                geo_country: None, // TODO: Add geo lookup
                geo_city: None,
            },
        )
        .await;

    // Generate alerts for new device/location if detected (F025)
    if let Ok(ref result) = audit_result {
        if result.is_new_device {
            if let Some(ref fingerprint) = device_fingerprint {
                let _ = alert_service
                    .generate_new_device_alert(
                        *tenant_id_val.as_uuid(),
                        *user_id.as_uuid(),
                        fingerprint,
                        ip_str.as_deref(),
                    )
                    .await;
            }
        }
        // New location alerts would go here when geo-lookup is implemented
    }

    // Track device on login (F026)
    let _is_new_device = if let Some(ref fingerprint) = device_fingerprint {
        match device_service
            .update_device_on_login(
                *user_id.as_uuid(),
                *tenant_id_val.as_uuid(),
                fingerprint,
                user_agent.as_deref(),
                ip_str.as_deref(),
                None, // geo_country - TODO: Add geo lookup
                None, // geo_city
            )
            .await
        {
            Ok((_, is_new)) => is_new,
            Err(ApiAuthError::DeviceRevoked) => {
                // Don't fail login for revoked device, just don't track
                tracing::warn!(
                    user_id = %user_id.as_uuid(),
                    "Login from revoked device, continuing without device tracking"
                );
                false
            }
            Err(e) => {
                // Log but don't fail login if device tracking fails
                tracing::warn!("Failed to track device on login: {}", e);
                false
            }
        }
    } else {
        false
    };

    // Risk enforcement evaluation (F073)
    let is_new_device_for_risk = audit_result
        .as_ref()
        .map(|r| r.is_new_device)
        .unwrap_or(false);
    let risk_context = LoginRiskContext {
        ip_address: ip_str.clone(),
        user_agent: user_agent.clone(),
        device_fingerprint: device_fingerprint.clone(),
        geo_country: None, // TODO: Add geo-IP lookup
        geo_city: None,
        geo_lat: None,
        geo_lon: None,
        is_new_device: is_new_device_for_risk,
        is_new_location: false, // TODO: Determine from geo-IP
        login_time: chrono::Utc::now(),
    };

    let risk_decision = match risk_enforcement_service
        .evaluate_login_risk(*tenant_id_val.as_uuid(), *user_id.as_uuid(), &risk_context)
        .await
    {
        Ok(decision) => {
            tracing::info!(
                user_id = %user_id.as_uuid(),
                action = ?decision.action,
                risk_score = decision.risk_score,
                enforced = decision.enforced,
                mode = ?decision.enforcement_mode,
                "Risk enforcement decision"
            );
            decision
        }
        Err(crate::services::RiskEnforcementError::ServiceUnavailable) => {
            return Err(ApiAuthError::RiskServiceUnavailable);
        }
        Err(e) => {
            // Fail-open: log and continue with no action
            tracing::warn!(
                user_id = %user_id.as_uuid(),
                error = %e,
                "Risk evaluation failed, proceeding with fail-open"
            );
            crate::services::EnforcementDecision::skip()
        }
    };

    // Handle risk enforcement decisions
    if risk_decision.is_blocked() {
        return Err(ApiAuthError::AccountRestricted);
    }

    let risk_requires_mfa = risk_decision.requires_mfa();

    // Check TOTP MFA
    let totp_enabled = mfa_service
        .has_mfa_enabled(*user_id.as_uuid(), *tenant_id_val.as_uuid())
        .await?;

    // Check WebAuthn MFA (F032)
    let webauthn_enabled = webauthn_service
        .has_webauthn_enabled(*user_id.as_uuid(), *tenant_id_val.as_uuid())
        .await
        .unwrap_or(false);

    let mfa_enabled = totp_enabled || webauthn_enabled;

    if mfa_enabled || risk_requires_mfa {
        // Check if trusted device can bypass MFA (F026)
        // Risk-enforced MFA cannot be bypassed by trusted devices
        let mut skip_mfa = false;
        if !risk_requires_mfa {
            if let Some(ref fingerprint) = device_fingerprint {
                // Check if tenant allows MFA bypass for trusted devices
                let allow_bypass = device_policy_service
                    .is_mfa_bypass_allowed(*tenant_id_val.as_uuid())
                    .await
                    .unwrap_or(false);

                if allow_bypass {
                    // Check if this device is trusted
                    if let Ok(is_trusted) = device_service
                        .is_device_trusted(
                            *user_id.as_uuid(),
                            *tenant_id_val.as_uuid(),
                            fingerprint,
                        )
                        .await
                    {
                        if is_trusted {
                            tracing::info!(
                                user_id = %user_id.as_uuid(),
                                device_fingerprint = %fingerprint,
                                "MFA bypassed for trusted device"
                            );
                            skip_mfa = true;
                        }
                    }
                }
            }
        }

        if !skip_mfa {
            // MFA is enabled and not bypassed - return partial token with available methods
            let (partial_token, expires_in) =
                token_service.create_partial_token(user_id, tenant_id_val)?;

            // Build list of available MFA methods
            let mut available_methods = Vec::new();
            if totp_enabled {
                available_methods.push(MfaMethod::Totp);
            }
            if webauthn_enabled {
                available_methods.push(MfaMethod::Webauthn);
            }
            // Recovery codes are always available if any MFA is enabled
            available_methods.push(MfaMethod::Recovery);

            let response =
                MfaRequiredResponse::with_methods(partial_token, expires_in, available_methods);
            return Ok((StatusCode::OK, Json(LoginResponse::MfaRequired(response))));
        }
    }

    // MFA not enabled - issue full tokens
    // Fetch user roles from database
    let roles = UserRole::get_user_roles(&pool, *user_id.as_uuid())
        .await
        .unwrap_or_else(|_| vec!["user".to_string()]);

    let (access_token, refresh_token, expires_in) = token_service
        .create_tokens(
            user_id,
            tenant_id_val,
            roles,
            Some(request.email.clone()),
            user_agent.clone(),
            ip_address,
        )
        .await?;

    // Create session entry for tracking
    // The session service handles user_agent parsing and policy enforcement
    if let Err(e) = session_service
        .create_session(
            *user_id.as_uuid(),
            *tenant_id_val.as_uuid(),
            None, // No refresh_token_id linking for now
            user_agent.as_deref(),
            ip_address.map(|ip| ip.to_string()).as_deref(),
        )
        .await
    {
        // Log but don't fail login if session creation fails
        tracing::warn!("Failed to create session entry: {}", e);
    }

    let response = TokenResponse::new(access_token, refresh_token, expires_in);

    // F082-US8: Emit structured security audit event for login success
    SecurityAudit::emit(
        SecurityEventType::LoginSuccess,
        Some(*tenant_id_val.as_uuid()),
        Some(*user_id.as_uuid()),
        ip_str.as_deref(),
        user_agent.as_deref(),
        "success",
        "Login successful",
    );

    // F085: Publish auth.login.success webhook event
    if let Some(ref publisher) = publisher {
        publisher.publish(WebhookEvent {
            event_id: uuid::Uuid::new_v4(),
            event_type: "auth.login.success".to_string(),
            tenant_id: *tenant_id_val.as_uuid(),
            actor_id: Some(*user_id.as_uuid()),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": user_id.as_uuid(),
                "ip_address": ip_str,
                "user_agent": user_agent,
            }),
        });
    }

    Ok((StatusCode::OK, Json(LoginResponse::Success(response))))
}

#[cfg(test)]
mod tests {
    // Handler tests require integration test setup
}
