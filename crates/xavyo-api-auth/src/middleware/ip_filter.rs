//! IP filter middleware (F028).
//!
//! Filters requests based on tenant IP restriction settings.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, warn};
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::ProblemDetails;
use crate::models::IpRestrictionPolicyConfig;
use crate::services::org_policy_service::OrgPolicyService;
use crate::services::IpRestrictionService;

/// Extract client IP address from request headers and connection info.
///
/// Checks in order:
/// 1. X-Forwarded-For header (first IP in chain)
/// 2. X-Real-IP header
/// 3. Peer address from connection
pub fn extract_client_ip(req: &Request<Body>) -> Option<String> {
    // Check X-Forwarded-For header (standard proxy header)
    if let Some(xff) = req.headers().get("X-Forwarded-For") {
        if let Ok(value) = xff.to_str() {
            // X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2
            // The first IP is typically the original client
            if let Some(first_ip) = value.split(',').next() {
                let ip = first_ip.trim();
                // Validate it's a valid IP
                if ip.parse::<IpAddr>().is_ok() {
                    debug!(ip = %ip, "Extracted IP from X-Forwarded-For");
                    return Some(ip.to_string());
                }
            }
        }
    }

    // Check X-Real-IP header (commonly used by nginx)
    if let Some(xri) = req.headers().get("X-Real-IP") {
        if let Ok(value) = xri.to_str() {
            let ip = value.trim();
            if ip.parse::<IpAddr>().is_ok() {
                debug!(ip = %ip, "Extracted IP from X-Real-IP");
                return Some(ip.to_string());
            }
        }
    }

    // Fall back to peer address from connection
    if let Some(connect_info) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        let ip = connect_info.0.ip().to_string();
        debug!(ip = %ip, "Using peer address");
        return Some(ip);
    }

    warn!("Could not determine client IP address");
    None
}

/// IP filter middleware.
///
/// Checks if the request's IP address is allowed based on tenant IP restriction settings.
/// Must be placed after authentication middleware (requires Claims extension).
pub async fn ip_filter_middleware(
    Extension(tenant_id): Extension<TenantId>,
    Extension(ip_service): Extension<Arc<IpRestrictionService>>,
    claims: Option<Extension<JwtClaims>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Extract client IP
    let ip_address = if let Some(ip) = extract_client_ip(&req) {
        ip
    } else {
        // If we can't determine the IP, log and continue (fail-open for IP detection)
        warn!("Could not determine client IP, skipping IP filter");
        return next.run(req).await;
    };

    // Get user info from claims
    let (user_roles, is_super_admin) = if let Some(Extension(claims)) = claims {
        // Extract roles from claims (roles is Vec<String>, not Option)
        let roles = claims.roles.clone();

        // Check if super admin (has specific role or flag)
        let is_super = roles
            .iter()
            .any(|r| r == "super_admin" || r == "superadmin");

        (roles, is_super)
    } else {
        // No claims means unauthenticated request - apply rules without user context
        (vec![], false)
    };

    // Check IP access
    let tenant_uuid = *tenant_id.as_uuid();
    match ip_service
        .check_ip_access(tenant_uuid, &ip_address, &user_roles, is_super_admin)
        .await
    {
        Ok(()) => {
            // IP is allowed, continue to next handler
            next.run(req).await
        }
        Err(crate::error::ApiAuthError::IpBlocked(reason)) => {
            // IP is blocked
            warn!(
                tenant_id = %tenant_uuid,
                ip = %ip_address,
                reason = %reason,
                "IP address blocked"
            );

            let problem = ProblemDetails::new("ip-blocked", "IP Blocked", StatusCode::FORBIDDEN)
                .with_detail(reason);

            (StatusCode::FORBIDDEN, Json(problem)).into_response()
        }
        Err(err) => {
            // Other error (e.g., database error)
            warn!(
                tenant_id = %tenant_uuid,
                ip = %ip_address,
                error = %err,
                "Error checking IP access"
            );

            // Fail-open on errors to avoid blocking all traffic on DB issues
            next.run(req).await
        }
    }
}

/// Check org-level IP restrictions for an authenticated user.
///
/// This function checks if the client IP is allowed by the user's
/// organization-level IP restriction policies. Returns `Ok(())` if allowed,
/// or an error message if blocked.
pub async fn check_org_ip_restriction(
    pool: &sqlx::PgPool,
    tenant_id: uuid::Uuid,
    user_id: uuid::Uuid,
    ip_address: &str,
) -> Result<(), String> {
    let ip: IpAddr = match ip_address.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(()), // Can't parse IP, skip org check
    };

    let org_service = OrgPolicyService::new(Arc::new(pool.clone()));

    let result = org_service
        .get_effective_policy_for_user(
            tenant_id,
            user_id,
            xavyo_db::models::org_security_policy::OrgPolicyType::IpRestriction,
        )
        .await;

    match result {
        Ok((config, sources)) => {
            // Only enforce if we got an actual org policy (not tenant default)
            let has_org_policy = sources.iter().any(|s| {
                !matches!(
                    s,
                    xavyo_db::models::org_security_policy::PolicySource::TenantDefault
                )
            });

            if !has_org_policy {
                return Ok(());
            }

            let ip_config: IpRestrictionPolicyConfig =
                serde_json::from_value(config).unwrap_or_default();

            if !ip_config.has_restrictions() {
                return Ok(());
            }

            if ip_config.is_ip_allowed(ip) {
                Ok(())
            } else {
                match ip_config.action_on_violation.as_str() {
                    "deny" => Err(format!(
                        "IP address {ip_address} is not allowed by organization policy"
                    )),
                    "warn" => {
                        warn!(
                            tenant_id = %tenant_id,
                            user_id = %user_id,
                            ip = %ip_address,
                            "IP address violates org policy (warn mode)"
                        );
                        Ok(())
                    }
                    _ => {
                        // "log" mode - just log and allow
                        debug!(
                            tenant_id = %tenant_id,
                            user_id = %user_id,
                            ip = %ip_address,
                            "IP address logged by org policy"
                        );
                        Ok(())
                    }
                }
            }
        }
        Err(_) => {
            // If org policy resolution fails, allow (fail-open)
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn make_request_with_xff(xff: &str) -> Request<Body> {
        let mut req = Request::new(Body::empty());
        req.headers_mut()
            .insert("X-Forwarded-For", HeaderValue::from_str(xff).unwrap());
        req
    }

    fn make_request_with_xri(xri: &str) -> Request<Body> {
        let mut req = Request::new(Body::empty());
        req.headers_mut()
            .insert("X-Real-IP", HeaderValue::from_str(xri).unwrap());
        req
    }

    #[test]
    fn test_extract_client_ip_xff_single() {
        let req = make_request_with_xff("192.168.1.100");
        assert_eq!(extract_client_ip(&req), Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_client_ip_xff_multiple() {
        let req = make_request_with_xff("192.168.1.100, 10.0.0.1, 172.16.0.1");
        assert_eq!(extract_client_ip(&req), Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_client_ip_xff_with_spaces() {
        let req = make_request_with_xff("  192.168.1.100  , 10.0.0.1");
        assert_eq!(extract_client_ip(&req), Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_client_ip_xri() {
        let req = make_request_with_xri("10.0.0.50");
        assert_eq!(extract_client_ip(&req), Some("10.0.0.50".to_string()));
    }

    #[test]
    fn test_extract_client_ip_xff_takes_precedence() {
        let mut req = Request::new(Body::empty());
        req.headers_mut()
            .insert("X-Forwarded-For", HeaderValue::from_static("192.168.1.100"));
        req.headers_mut()
            .insert("X-Real-IP", HeaderValue::from_static("10.0.0.50"));

        // X-Forwarded-For should take precedence
        assert_eq!(extract_client_ip(&req), Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_client_ip_ipv6() {
        let req = make_request_with_xff("2001:db8::1");
        assert_eq!(extract_client_ip(&req), Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_extract_client_ip_invalid() {
        let req = make_request_with_xff("not-an-ip");
        assert_eq!(extract_client_ip(&req), None);
    }

    #[test]
    fn test_extract_client_ip_empty() {
        let req = Request::new(Body::empty());
        assert_eq!(extract_client_ip(&req), None);
    }
}
