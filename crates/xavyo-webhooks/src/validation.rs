//! URL validation and SSRF protection for webhook delivery endpoints.
//!
//! Validates webhook URLs against:
//! - Protocol requirements (HTTPS in production)
//! - SSRF protections (private/internal IP ranges, cloud metadata endpoints)
//! - Event type validity

use std::net::IpAddr;

use crate::error::WebhookError;
use crate::models::WebhookEventType;

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

/// Validate a webhook delivery URL.
///
/// Checks:
/// 1. URL is parseable
/// 2. Scheme is HTTPS (or HTTP if `allow_http` is true for dev/test)
/// 3. Host is not a private/internal address (SSRF protection)
pub fn validate_webhook_url(url: &str, allow_http: bool) -> Result<(), WebhookError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| WebhookError::InvalidUrl(format!("Invalid URL format: {e}")))?;

    // Validate scheme
    match parsed.scheme() {
        "https" => {}
        "http" if allow_http => {}
        "http" => {
            return Err(WebhookError::InvalidUrl(
                "Webhook URLs must use HTTPS".to_string(),
            ));
        }
        scheme => {
            return Err(WebhookError::InvalidUrl(format!(
                "Unsupported URL scheme: {scheme}"
            )));
        }
    }

    // Extract and validate host
    let host = parsed
        .host_str()
        .ok_or_else(|| WebhookError::InvalidUrl("URL must have a host".to_string()))?;

    validate_host_not_internal(host)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

/// Validate that a host is not a private/internal address.
///
/// Blocks:
/// - Loopback addresses (127.0.0.0/8)
/// - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Link-local (169.254.0.0/16 — AWS/Azure/GCP metadata endpoint)
/// - CGNAT (100.64.0.0/10)
/// - IPv6 loopback and unspecified
/// - Internal hostnames (localhost, *.internal, *.local)
pub fn validate_host_not_internal(host: &str) -> Result<(), WebhookError> {
    // Check if host is a raw IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_internal_ip(&ip) {
            return Err(WebhookError::SsrfDetected(format!(
                "Destination host {host} is a private/internal address"
            )));
        }
    }

    // Block common internal hostnames
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || lower == "metadata.google.internal"
        || lower.ends_with(".internal")
        || lower.ends_with(".local")
    {
        return Err(WebhookError::SsrfDetected(format!(
            "Destination host {host} is a restricted internal hostname"
        )));
    }

    Ok(())
}

/// Check if an IP address belongs to a private/internal range.
fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                // 127.0.0.0/8
                || v4.is_private()          // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()       // 169.254.0.0/16
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ---------------------------------------------------------------------------
// Event type validation
// ---------------------------------------------------------------------------

/// Validate that all event type strings are known `WebhookEventType` variants.
///
/// Returns the first invalid event type found, or Ok(()) if all are valid.
pub fn validate_event_types(event_types: &[String]) -> Result<(), WebhookError> {
    for et in event_types {
        if WebhookEventType::parse(et).is_none() {
            return Err(WebhookError::Validation(format!(
                "Unknown event type: {et}"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- URL validation ---

    #[test]
    fn test_valid_https_url() {
        assert!(validate_webhook_url("https://example.com/webhooks", false).is_ok());
    }

    #[test]
    fn test_valid_https_url_with_port() {
        assert!(validate_webhook_url("https://hooks.example.com:8443/callback", false).is_ok());
    }

    #[test]
    fn test_http_url_rejected_in_production() {
        let result = validate_webhook_url("http://example.com/webhooks", false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebhookError::InvalidUrl(_)));
    }

    #[test]
    fn test_http_url_allowed_in_dev() {
        assert!(validate_webhook_url("http://example.com/webhooks", true).is_ok());
    }

    #[test]
    fn test_invalid_url_format() {
        let result = validate_webhook_url("not-a-url", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_scheme() {
        let result = validate_webhook_url("ftp://example.com/webhooks", false);
        assert!(result.is_err());
    }

    // --- SSRF protection ---

    #[test]
    fn test_ssrf_blocks_loopback() {
        assert!(validate_host_not_internal("127.0.0.1").is_err());
        assert!(validate_host_not_internal("127.0.0.2").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_10() {
        assert!(validate_host_not_internal("10.0.0.1").is_err());
        assert!(validate_host_not_internal("10.255.255.255").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_172() {
        assert!(validate_host_not_internal("172.16.0.1").is_err());
        assert!(validate_host_not_internal("172.31.255.255").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_192() {
        assert!(validate_host_not_internal("192.168.0.1").is_err());
        assert!(validate_host_not_internal("192.168.255.255").is_err());
    }

    #[test]
    fn test_ssrf_blocks_link_local() {
        // AWS/Azure/GCP metadata endpoint
        assert!(validate_host_not_internal("169.254.169.254").is_err());
        assert!(validate_host_not_internal("169.254.0.1").is_err());
    }

    #[test]
    fn test_ssrf_blocks_cgnat() {
        assert!(validate_host_not_internal("100.64.0.1").is_err());
        assert!(validate_host_not_internal("100.127.255.255").is_err());
    }

    #[test]
    fn test_ssrf_blocks_ipv6_loopback() {
        assert!(validate_host_not_internal("::1").is_err());
    }

    #[test]
    fn test_ssrf_blocks_ipv6_unspecified() {
        assert!(validate_host_not_internal("::").is_err());
    }

    #[test]
    fn test_ssrf_blocks_localhost() {
        assert!(validate_host_not_internal("localhost").is_err());
        assert!(validate_host_not_internal("LOCALHOST").is_err());
    }

    #[test]
    fn test_ssrf_blocks_internal_hostnames() {
        assert!(validate_host_not_internal("metadata.google.internal").is_err());
        assert!(validate_host_not_internal("service.internal").is_err());
        assert!(validate_host_not_internal("myhost.local").is_err());
    }

    #[test]
    fn test_ssrf_allows_public_ip() {
        assert!(validate_host_not_internal("8.8.8.8").is_ok());
        assert!(validate_host_not_internal("203.0.113.50").is_ok());
    }

    #[test]
    fn test_ssrf_allows_public_hostname() {
        assert!(validate_host_not_internal("example.com").is_ok());
        assert!(validate_host_not_internal("hooks.myapp.io").is_ok());
    }

    #[test]
    fn test_ssrf_url_integration_private_ip() {
        let result = validate_webhook_url("https://10.0.0.1/webhook", false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebhookError::SsrfDetected(_)));
    }

    #[test]
    fn test_ssrf_url_integration_localhost() {
        let result = validate_webhook_url("https://localhost/webhook", false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WebhookError::SsrfDetected(_)));
    }

    // --- Event type validation ---

    #[test]
    fn test_valid_event_types() {
        let types = vec![
            "user.created".to_string(),
            "auth.login.success".to_string(),
            "role.assigned".to_string(),
        ];
        assert!(validate_event_types(&types).is_ok());
    }

    #[test]
    fn test_invalid_event_type() {
        let types = vec!["user.created".to_string(), "invalid.event.type".to_string()];
        let result = validate_event_types(&types);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid.event.type"));
    }

    #[test]
    fn test_empty_event_types() {
        assert!(validate_event_types(&[]).is_ok());
    }

    #[test]
    fn test_all_event_types_valid() {
        let types: Vec<String> = WebhookEventType::all()
            .iter()
            .map(|et| et.as_str().to_string())
            .collect();
        assert!(validate_event_types(&types).is_ok());
    }
}
