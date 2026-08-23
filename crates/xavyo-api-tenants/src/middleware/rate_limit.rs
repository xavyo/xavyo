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
pub const PROVISION_RATE_LIMIT_MAX: usize = 100;

/// Rate limit window in seconds (1 hour).
pub const PROVISION_RATE_LIMIT_WINDOW_SECS: u64 = 3600;

/// Create a rate limiter configured for tenant provisioning.
///
/// Configuration: 100 requests per IP per hour.
#[must_use]
pub fn provision_rate_limiter() -> RateLimiter {
    RateLimiter::new(RateLimitConfig {
        max_attempts: PROVISION_RATE_LIMIT_MAX,
        window: Duration::from_secs(PROVISION_RATE_LIMIT_WINDOW_SECS),
    })
}

/// Resolve the IP used as the provisioning rate-limit key.
///
/// Prefers `extract_client_ip` (TrustXff-gated forwarded headers, else peer).
/// Falls back to the `ConnectInfo` extractor. Returns `None` when neither
/// source yields a valid address — the middleware must refuse, not skip.
#[must_use]
pub(crate) fn provision_client_ip(extracted: Option<&str>, peer: Option<IpAddr>) -> Option<IpAddr> {
    extracted.and_then(|s| s.parse().ok()).or(peer)
}

/// Rate limiting middleware for the tenant provisioning endpoint.
///
/// Checks incoming requests against the rate limiter and returns 429
/// if the client IP has exceeded the rate limit (100 requests per hour).
///
/// ## IP Extraction
///
/// Uses `extract_client_ip`: forwarded headers only when `TrustXff` is set,
/// otherwise the peer address. A client-supplied `X-Forwarded-For` must not
/// bypass the provisioning rate limit. If no valid IP can be determined the
/// request is refused (fail closed) so the limiter cannot be skipped.
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
    let extracted = extract_client_ip(&request);
    let peer = connect_info.map(|ConnectInfo(addr)| addr.ip());
    let Some(ip) = provision_client_ip(extracted.as_deref(), peer) else {
        tracing::warn!("Cannot determine client IP for rate limiting, refusing request");
        return unknown_client_ip_response();
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

/// Generate a 400 Bad Request when the client IP cannot be determined.
///
/// Provisioning is IP-rate-limited. Skipping the limiter would fail open.
fn unknown_client_ip_response() -> Response {
    let body = serde_json::json!({
        "type": "https://xavyo.net/errors/client-ip-required",
        "title": "Bad Request",
        "status": 400,
        "detail": "Cannot determine client IP for tenant provisioning rate limiting.",
        "instance": "/tenants/provision"
    });

    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/problem+json")],
        body.to_string(),
    )
        .into_response()
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
        assert_eq!(PROVISION_RATE_LIMIT_MAX, 100);
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

    #[test]
    fn provision_client_ip_prefers_extracted() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            provision_client_ip(Some("203.0.113.10"), Some(peer)),
            Some("203.0.113.10".parse().unwrap())
        );
    }

    #[test]
    fn provision_client_ip_falls_back_to_peer() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(provision_client_ip(None, Some(peer)), Some(peer));
    }

    #[test]
    fn provision_client_ip_invalid_extracted_falls_back_to_peer() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            provision_client_ip(Some("not-an-ip"), Some(peer)),
            Some(peer)
        );
    }

    #[test]
    fn provision_client_ip_none_when_unknown() {
        assert_eq!(provision_client_ip(None, None), None);
        assert_eq!(provision_client_ip(Some("not-an-ip"), None), None);
    }

    #[test]
    fn provision_client_ip_accepts_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(provision_client_ip(Some("2001:db8::1"), None), Some(ip));
    }

    #[test]
    fn unknown_client_ip_is_bad_request_problem_json() {
        let response = unknown_client_ip_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
    }

    fn provision_app() -> axum::Router {
        async fn ok() -> &'static str {
            "ok"
        }
        axum::Router::new()
            .route("/tenants/provision", axum::routing::post(ok))
            .layer(axum::middleware::from_fn(provision_rate_limit_middleware))
            .layer(Extension(Arc::new(provision_rate_limiter())))
    }

    #[tokio::test]
    async fn middleware_refuses_when_client_ip_unknown() {
        use tower::ServiceExt;

        let response = provision_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tenants/provision")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
    }

    #[tokio::test]
    async fn middleware_allows_when_peer_ip_present() {
        use tower::ServiceExt;

        let mut req = Request::builder()
            .method("POST")
            .uri("/tenants/provision")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 443))));
        let response = provision_app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
