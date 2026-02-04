//! Rate limiting middleware for tenant provisioning endpoint.
//!
//! Implements IP-based rate limiting to prevent abuse of the provisioning endpoint.
//! Uses the existing `RateLimiter` infrastructure from `xavyo-api-auth`.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use xavyo_api_auth::middleware::{extract_client_ip, RateLimitConfig, RateLimiter};

/// Maximum provisioning requests per IP per hour.
pub const PROVISION_RATE_LIMIT_MAX: usize = 10;

/// Rate limit window in seconds (1 hour).
pub const PROVISION_RATE_LIMIT_WINDOW_SECS: u64 = 3600;

/// Create a rate limiter configured for tenant provisioning.
///
/// Configuration: 10 requests per IP per hour.
#[must_use]
pub fn provision_rate_limiter() -> RateLimiter {
    RateLimiter::new(RateLimitConfig {
        max_attempts: PROVISION_RATE_LIMIT_MAX,
        window: Duration::from_secs(PROVISION_RATE_LIMIT_WINDOW_SECS),
    })
}

/// Rate limiting middleware for the tenant provisioning endpoint.
///
/// Checks incoming requests against the rate limiter and returns 429
/// if the client IP has exceeded the rate limit (10 requests per hour).
///
/// ## IP Extraction
///
/// IP address is extracted in this order:
/// 1. `X-Forwarded-For` header (first IP in chain) - for reverse proxies
/// 2. `X-Real-IP` header - commonly used by nginx
/// 3. Peer address from connection - direct connection fallback
///
/// Adds rate limit headers to all responses:
/// - `X-RateLimit-Limit`: Maximum requests allowed
/// - `X-RateLimit-Remaining`: Requests remaining in window
/// - `X-RateLimit-Reset`: Unix timestamp when window resets
pub async fn provision_rate_limit_middleware(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Extension(limiter): Extension<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Extract client IP from headers or connection info
    // Uses X-Forwarded-For, X-Real-IP, or falls back to peer address
    let ip = match extract_client_ip(&request) {
        Some(ip_str) => match ip_str.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                // If IP parsing fails, fall back to connection info
                if let Some(ConnectInfo(addr)) = connect_info { addr.ip() } else {
                    // Cannot determine IP - fail open but log
                    tracing::warn!(
                        "Cannot determine client IP for rate limiting, allowing request"
                    );
                    return next.run(request).await;
                }
            }
        },
        None => {
            // Fall back to connection info
            if let Some(ConnectInfo(addr)) = connect_info { addr.ip() } else {
                tracing::warn!(
                    "Cannot determine client IP for rate limiting, allowing request"
                );
                return next.run(request).await;
            }
        }
    };

    // Check if rate limited before recording
    if limiter.is_limited(ip) {
        return rate_limit_exceeded_response(ip, &limiter);
    }

    // Record the attempt
    if !limiter.record_attempt(ip) {
        return rate_limit_exceeded_response(ip, &limiter);
    }

    // Get remaining attempts for headers
    let remaining = limiter.remaining_attempts(ip);
    let reset_time = calculate_reset_time();

    // Execute the request
    let mut response = next.run(request).await;

    // Add rate limit headers to successful response
    add_rate_limit_headers(response.headers_mut(), remaining, reset_time);

    response
}

/// Generate a 429 Too Many Requests response with RFC 7807 format.
fn rate_limit_exceeded_response(ip: IpAddr, limiter: &RateLimiter) -> Response {
    let remaining = limiter.remaining_attempts(ip);
    let reset_time = calculate_reset_time();

    let body = serde_json::json!({
        "type": "https://xavyo.net/errors/rate-limit-exceeded",
        "title": "Too Many Requests",
        "status": 429,
        "detail": "Rate limit exceeded for tenant provisioning. Please wait before trying again.",
        "instance": "/tenants/provision",
        "remaining_attempts": remaining,
        "retry_after": reset_time
    });

    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::CONTENT_TYPE, "application/problem+json")],
        body.to_string(),
    )
        .into_response();

    add_rate_limit_headers(response.headers_mut(), remaining, reset_time);

    // Add Retry-After header
    let retry_after_secs = reset_time.saturating_sub(current_timestamp());
    if let Ok(value) = header::HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }

    response
}

/// Add rate limit headers to a response.
fn add_rate_limit_headers(headers: &mut header::HeaderMap, remaining: usize, reset_time: u64) {
    // X-RateLimit-Limit
    if let Ok(value) = header::HeaderValue::from_str(&PROVISION_RATE_LIMIT_MAX.to_string()) {
        headers.insert(header::HeaderName::from_static("x-ratelimit-limit"), value);
    }

    // X-RateLimit-Remaining
    if let Ok(value) = header::HeaderValue::from_str(&remaining.to_string()) {
        headers.insert(
            header::HeaderName::from_static("x-ratelimit-remaining"),
            value,
        );
    }

    // X-RateLimit-Reset
    if let Ok(value) = header::HeaderValue::from_str(&reset_time.to_string()) {
        headers.insert(header::HeaderName::from_static("x-ratelimit-reset"), value);
    }
}

/// Calculate the Unix timestamp when the rate limit window resets.
fn calculate_reset_time() -> u64 {
    current_timestamp() + PROVISION_RATE_LIMIT_WINDOW_SECS
}

/// Get the current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provision_rate_limiter_config() {
        let limiter = provision_rate_limiter();
        assert_eq!(limiter.config().max_attempts, PROVISION_RATE_LIMIT_MAX);
        assert_eq!(
            limiter.config().window,
            Duration::from_secs(PROVISION_RATE_LIMIT_WINDOW_SECS)
        );
    }

    #[test]
    fn test_rate_limit_constants() {
        assert_eq!(PROVISION_RATE_LIMIT_MAX, 10);
        assert_eq!(PROVISION_RATE_LIMIT_WINDOW_SECS, 3600);
    }

    #[test]
    fn test_allows_up_to_max_attempts() {
        let limiter = provision_rate_limiter();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // First 10 attempts should succeed
        for i in 0..PROVISION_RATE_LIMIT_MAX {
            assert!(
                limiter.record_attempt(ip),
                "Attempt {} should succeed",
                i + 1
            );
        }

        // 11th attempt should fail
        assert!(!limiter.record_attempt(ip), "Attempt 11 should be blocked");
        assert!(limiter.is_limited(ip));
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = provision_rate_limiter();
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Exhaust IP 1
        for _ in 0..PROVISION_RATE_LIMIT_MAX {
            limiter.record_attempt(ip1);
        }
        assert!(limiter.is_limited(ip1));

        // IP 2 should still be allowed
        assert!(!limiter.is_limited(ip2));
        assert!(limiter.record_attempt(ip2));
    }

    #[test]
    fn test_remaining_attempts() {
        let limiter = provision_rate_limiter();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert_eq!(limiter.remaining_attempts(ip), PROVISION_RATE_LIMIT_MAX);

        limiter.record_attempt(ip);
        assert_eq!(limiter.remaining_attempts(ip), PROVISION_RATE_LIMIT_MAX - 1);

        for _ in 1..5 {
            limiter.record_attempt(ip);
        }
        assert_eq!(limiter.remaining_attempts(ip), PROVISION_RATE_LIMIT_MAX - 5);
    }

    #[test]
    fn test_calculate_reset_time() {
        let now = current_timestamp();
        let reset = calculate_reset_time();

        // Reset time should be approximately 1 hour from now
        assert!(reset >= now + PROVISION_RATE_LIMIT_WINDOW_SECS - 1);
        assert!(reset <= now + PROVISION_RATE_LIMIT_WINDOW_SECS + 1);
    }
}
