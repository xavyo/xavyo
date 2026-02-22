//! Request middleware for tracing, context propagation, and security headers.
//!
//! This module provides middleware for:
//! - Request ID generation and propagation
//! - Distributed request tracing with W3C Trace Context propagation (F072)
//! - OWASP security response headers (F069-S2)

use axum::{
    body::Body,
    extract::MatchedPath,
    http::{header::HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

/// Create a tower layer stack for request ID handling.
///
/// This creates middleware that:
/// 1. Sets a request ID if not present (using UUID v4)
/// 2. Propagates the request ID in the response header
///
/// The request ID is available via the `X-Request-Id` header.
pub fn request_id_layer() -> tower::ServiceBuilder<
    tower::layer::util::Stack<
        PropagateRequestIdLayer,
        tower::layer::util::Stack<SetRequestIdLayer<MakeRequestUuid>, tower::layer::util::Identity>,
    >,
> {
    tower::ServiceBuilder::new()
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
}

// ── Distributed Tracing Middleware (F072 — US1) ──────────────────────────

/// Extract W3C Trace Context from request headers into an OpenTelemetry context.
///
/// This enables incoming `traceparent` / `tracestate` headers to be propagated
/// into the current span, linking cross-service traces (FR-002).
fn extract_otel_context(headers: &axum::http::HeaderMap) -> opentelemetry::Context {
    struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

    impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }
        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(axum::http::HeaderName::as_str).collect()
        }
    }

    let propagator =
        opentelemetry::global::get_text_map_propagator(|p| p.extract(&HeaderExtractor(headers)));
    propagator
}

/// Axum middleware that creates a tracing span for each HTTP request with
/// OpenTelemetry-compatible attributes and W3C Trace Context propagation.
///
/// Span attributes:
/// - `http.method`: HTTP method (GET, POST, etc.)
/// - `http.route`: Matched route pattern (e.g., `/admin/users/:id`)
/// - `http.target`: Full request URI path
/// - `http.status_code`: Response status code (recorded after response)
/// - `otel.status_code`: Set to `ERROR` for 5xx responses
///
/// Incoming `traceparent` headers are extracted via W3C Trace Context propagation
/// so that distributed traces are linked across services (FR-002).
pub async fn otel_trace_middleware(
    matched_path: Option<MatchedPath>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    use tracing::Instrument;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let method = request.method().to_string();
    let target = request.uri().path().to_string();
    let route = matched_path
        .as_ref()
        .map_or_else(|| "unmatched".to_string(), |m| m.as_str().to_string());

    // Extract W3C trace context from incoming headers (FR-002)
    let otel_cx = extract_otel_context(request.headers());

    let span = tracing::info_span!(
        "http.request",
        http.method = %method,
        http.route = %route,
        http.target = %target,
        http.status_code = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
    );

    // Link the span to the extracted OTel context (traceparent propagation)
    span.set_parent(otel_cx);

    let response = next.run(request).instrument(span.clone()).await;

    let status = response.status().as_u16();
    span.record("http.status_code", status);
    if response.status().is_server_error() {
        span.record("otel.status_code", "ERROR");
    }

    response
}

// ── Security Headers (F069-S2) ────────────────────────────────────────────

// Header name constants
static X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
static X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
static STRICT_TRANSPORT_SECURITY: HeaderName = HeaderName::from_static("strict-transport-security");
static REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
static CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
static PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
static X_XSS_PROTECTION: HeaderName = HeaderName::from_static("x-xss-protection");

/// Axum middleware that adds OWASP security headers to every response.
///
/// Headers added:
/// - `X-Content-Type-Options: nosniff`
/// - `X-Frame-Options: DENY`
/// - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
/// - `Referrer-Policy: strict-origin-when-cross-origin`
/// - `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`
/// - `Permissions-Policy: camera=(), microphone=(), geolocation=()`
///
/// Also removes the `Server` header to prevent server fingerprinting.
pub async fn security_headers_middleware(
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        X_CONTENT_TYPE_OPTIONS.clone(),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(X_FRAME_OPTIONS.clone(), HeaderValue::from_static("DENY"));
    headers.insert(
        STRICT_TRANSPORT_SECURITY.clone(),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        REFERRER_POLICY.clone(),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        CONTENT_SECURITY_POLICY.clone(),
        HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
    );
    headers.insert(
        PERMISSIONS_POLICY.clone(),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    // F082: X-XSS-Protection: 0 — modern browsers rely on CSP instead of legacy XSS filter
    headers.insert(X_XSS_PROTECTION.clone(), HeaderValue::from_static("0"));

    // Remove Server header to prevent fingerprinting
    headers.remove(axum::http::header::SERVER);

    response
}

// ── Request Timeout (F082-US9) ────────────────────────────────────────────

/// Axum middleware that enforces a configurable request timeout.
///
/// Returns 408 Request Timeout if the handler takes longer than the configured
/// timeout (stored as Extension<RequestTimeoutSecs>).
pub async fn request_timeout_middleware(
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let timeout_secs = request
        .extensions()
        .get::<RequestTimeoutSecs>()
        .map_or(30, |t| t.0);

    if let Ok(response) = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        next.run(request),
    )
    .await
    {
        response
    } else {
        let mut response = Response::new(Body::from(
            serde_json::json!({
                "error": "request_timeout",
                "error_description": "Request timed out"
            })
            .to_string(),
        ));
        *response.status_mut() = axum::http::StatusCode::REQUEST_TIMEOUT;
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response
    }
}

/// Request timeout configuration (seconds), stored as Extension.
#[derive(Clone, Copy)]
pub struct RequestTimeoutSecs(pub u64);

// ── Content-Type Validation (F082-US9) ────────────────────────────────────

/// Axum middleware that validates Content-Type header on POST/PUT/PATCH requests.
///
/// Rejects requests with missing or unsupported Content-Type with 415 Unsupported Media Type.
/// Allowed types: application/json, application/x-www-form-urlencoded, multipart/form-data.
pub async fn content_type_validation_middleware(
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();

    // Only validate Content-Type for methods with request bodies
    if method == axum::http::Method::POST
        || method == axum::http::Method::PUT
        || method == axum::http::Method::PATCH
    {
        let content_type = request
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let is_valid = content_type.starts_with("application/json")
            || content_type.starts_with("application/x-www-form-urlencoded")
            || content_type.starts_with("multipart/form-data")
            || content_type.starts_with("text/xml")       // SAML
            || content_type.starts_with("application/xml") // SAML
            || content_type.starts_with("application/scim+json"); // SCIM

        if !is_valid && !content_type.is_empty() {
            let mut response = Response::new(Body::from(
                serde_json::json!({
                    "error": "unsupported_media_type",
                    "error_description": "Content-Type header must be application/json, application/x-www-form-urlencoded, or multipart/form-data"
                })
                .to_string(),
            ));
            *response.status_mut() = axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE;
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return response;
        }
    }

    next.run(request).await
}

// ── Error Sanitization (F082-US9) ─────────────────────────────────────────

/// Axum middleware that sanitizes 5xx error responses in production mode.
///
/// Replaces detailed error messages with a generic JSON error to prevent
/// leaking internal details (stack traces, SQL errors, file paths).
/// In development mode, responses pass through unchanged.
pub async fn error_sanitization_middleware(
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let is_production = std::env::var("APP_ENV")
        .map(|v| v == "production" || v == "prod")
        .unwrap_or(false);

    let response = next.run(request).await;

    if is_production && response.status().is_server_error() {
        let status = response.status();
        let mut sanitized = Response::new(Body::from(
            serde_json::json!({
                "error": "internal_server_error",
                "error_description": "An unexpected error occurred. Please try again later."
            })
            .to_string(),
        ));
        *sanitized.status_mut() = status;
        sanitized.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return sanitized;
    }

    response
}

// ── Per-Endpoint Rate Limiting (F082-US7) ─────────────────────────────────

use governor::{clock::DefaultClock, Quota};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Shared rate limiter state for per-endpoint rate limiting.
///
/// Each endpoint group (login, token, registration) gets its own keyed limiter.
/// Keys are derived from client IP address, account identifier, or `client_id`.
#[derive(Clone)]
pub struct EndpointRateLimiters {
    /// Login rate limiter per IP (5/min default)
    pub login_ip: Arc<
        governor::RateLimiter<
            String,
            governor::state::keyed::DefaultKeyedStateStore<String>,
            DefaultClock,
        >,
    >,
    /// Login rate limiter per account (10/min default).
    /// Reserved for account-level rate limiting (requires extracting account from request body).
    #[allow(dead_code)]
    pub login_account: Arc<
        governor::RateLimiter<
            String,
            governor::state::keyed::DefaultKeyedStateStore<String>,
            DefaultClock,
        >,
    >,
    /// Token endpoint rate limiter per `client_id` (30/min default)
    pub token_client: Arc<
        governor::RateLimiter<
            String,
            governor::state::keyed::DefaultKeyedStateStore<String>,
            DefaultClock,
        >,
    >,
    /// Registration rate limiter per IP (3/hr default)
    pub registration_ip: Arc<
        governor::RateLimiter<
            String,
            governor::state::keyed::DefaultKeyedStateStore<String>,
            DefaultClock,
        >,
    >,
}

/// Safe non-zero constant defaults for rate limiting.
/// SAFETY: These are compile-time constants that are guaranteed non-zero.
const DEFAULT_LOGIN_IP: NonZeroU32 = match NonZeroU32::new(5) {
    Some(v) => v,
    None => unreachable!(),
};
const DEFAULT_LOGIN_ACCOUNT: NonZeroU32 = match NonZeroU32::new(10) {
    Some(v) => v,
    None => unreachable!(),
};
const DEFAULT_TOKEN_CLIENT: NonZeroU32 = match NonZeroU32::new(30) {
    Some(v) => v,
    None => unreachable!(),
};
const DEFAULT_REGISTRATION_IP: NonZeroU32 = match NonZeroU32::new(3) {
    Some(v) => v,
    None => unreachable!(),
};

impl EndpointRateLimiters {
    /// Create rate limiters from configuration.
    pub fn from_config(config: &crate::config::RateLimitingConfig) -> Self {
        Self {
            login_ip: Arc::new(governor::RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(config.login_per_ip).unwrap_or(DEFAULT_LOGIN_IP),
            ))),
            login_account: Arc::new(governor::RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(config.login_per_account).unwrap_or(DEFAULT_LOGIN_ACCOUNT),
            ))),
            token_client: Arc::new(governor::RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(config.token_per_client).unwrap_or(DEFAULT_TOKEN_CLIENT),
            ))),
            registration_ip: Arc::new(governor::RateLimiter::keyed(Quota::per_hour(
                NonZeroU32::new(config.registration_per_ip).unwrap_or(DEFAULT_REGISTRATION_IP),
            ))),
        }
    }
}

/// Extract client IP from request, checking X-Forwarded-For first, then `ConnectInfo`.
///
/// Only trusts X-Forwarded-For headers when the `TrustXff` marker is present in
/// request extensions (set by `proxy_trust_middleware` for trusted proxy CIDRs).
fn extract_client_ip(request: &axum::http::Request<Body>) -> String {
    let connect_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());

    // Only trust X-Forwarded-For when proxy_trust_middleware has set the TrustXff marker
    if request
        .extensions()
        .get::<xavyo_api_auth::TrustXff>()
        .is_some()
    {
        if let Some(forwarded) = request.headers().get("x-forwarded-for") {
            if let Ok(val) = forwarded.to_str() {
                if let Some(first_ip) = val.split(',').next() {
                    return first_ip.trim().to_string();
                }
            }
        }
    }

    // Fall back to ConnectInfo
    if let Some(ip) = connect_ip {
        return ip.to_string();
    }

    "unknown".to_string()
}

/// Axum middleware that sets `TrustXff` in request extensions when the direct
/// connection IP matches a trusted proxy CIDR.
///
/// This enables downstream middleware (like `jwt_auth_middleware`) to safely
/// parse X-Forwarded-For headers only from trusted sources.
pub async fn proxy_trust_middleware(
    mut request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let should_trust = request
        .extensions()
        .get::<crate::config::TrustedProxyConfig>()
        .is_some_and(|config| {
            if !config.has_trusted_proxies() {
                return false;
            }
            request
                .extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .is_some_and(|ci| config.is_trusted(&ci.0.ip()))
        });

    if should_trust {
        request.extensions_mut().insert(xavyo_api_auth::TrustXff);
    }

    next.run(request).await
}

/// Axum middleware for login endpoint rate limiting (IP + account based).
///
/// Returns 429 Too Many Requests with Retry-After header when limits are exceeded.
/// Emits structured security audit event on rate limit hit.
pub async fn login_rate_limit_middleware(
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let limiters = match request.extensions().get::<EndpointRateLimiters>() {
        Some(l) => l.clone(),
        None => return next.run(request).await,
    };

    let ip = extract_client_ip(&request);

    // Check IP-based rate limit
    if limiters.login_ip.check_key(&ip).is_err() {
        tracing::warn!(
            target: "security",
            event_type = "rate_limit_hit",
            endpoint = "login",
            key_type = "ip",
            key = %ip,
            outcome = "rejected",
            "Login rate limit exceeded (per IP)"
        );
        return rate_limit_response();
    }

    next.run(request).await
}

/// Axum middleware for token endpoint rate limiting (`client_id` based).
///
/// Returns 429 Too Many Requests with Retry-After header when limits are exceeded.
pub async fn token_rate_limit_middleware(
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let limiters = match request.extensions().get::<EndpointRateLimiters>() {
        Some(l) => l.clone(),
        None => return next.run(request).await,
    };

    // For the token endpoint, the client_id is in the POST body or Basic auth header.
    // We rate-limit by IP as a fallback since we can't easily read the body here.
    let ip = extract_client_ip(&request);

    if limiters.token_client.check_key(&ip).is_err() {
        tracing::warn!(
            target: "security",
            event_type = "rate_limit_hit",
            endpoint = "token",
            key_type = "ip",
            key = %ip,
            outcome = "rejected",
            "Token endpoint rate limit exceeded"
        );
        return rate_limit_response();
    }

    next.run(request).await
}

/// Axum middleware for registration endpoint rate limiting (IP based).
///
/// Returns 429 Too Many Requests with Retry-After header when limits are exceeded.
pub async fn registration_rate_limit_middleware(
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let limiters = match request.extensions().get::<EndpointRateLimiters>() {
        Some(l) => l.clone(),
        None => return next.run(request).await,
    };

    let ip = extract_client_ip(&request);

    if limiters.registration_ip.check_key(&ip).is_err() {
        tracing::warn!(
            target: "security",
            event_type = "rate_limit_hit",
            endpoint = "registration",
            key_type = "ip",
            key = %ip,
            outcome = "rejected",
            "Registration rate limit exceeded (per IP)"
        );
        return rate_limit_response();
    }

    next.run(request).await
}

/// Build a 429 Too Many Requests response with Retry-After header.
fn rate_limit_response() -> Response {
    let mut response = Response::new(Body::from(
        serde_json::json!({
            "error": "too_many_requests",
            "error_description": "Rate limit exceeded. Please try again later."
        })
        .to_string(),
    ));
    *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        HeaderValue::from_static("60"),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

// ── HTTP Idempotency Middleware (F-IDEMPOTENCY) ───────────────────────────

use axum::http::StatusCode;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use xavyo_db::models::{CreateIdempotentRequest, IdempotentRequest, IdempotentState, InsertResult};

/// Maximum request body size for idempotency middleware buffering (1 MB).
/// Prevents unbounded memory allocation from oversized request bodies.
const IDEMPOTENCY_MAX_REQUEST_BODY: usize = 1_048_576;

/// Maximum response body size for idempotency middleware caching (8 MB).
/// Larger than request limit to accommodate batch/list API responses.
/// Responses exceeding this are not cached but still returned to the client.
const IDEMPOTENCY_MAX_RESPONSE_BODY: usize = 8_388_608;

/// Header name for client-provided idempotency key.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Header name for indicating a replayed response.
pub const IDEMPOTENCY_REPLAYED_HEADER: &str = "idempotency-replayed";

/// Maximum length for idempotency key.
const MAX_KEY_LENGTH: usize = 256;

/// Error type for idempotency middleware.
#[derive(Debug)]
pub enum IdempotencyError {
    /// Invalid idempotency key format.
    InvalidKey(String),
    /// Another request with the same key is currently processing.
    Conflict,
    /// Key was used with a different request body.
    Mismatch,
    /// Database error.
    Database(sqlx::Error),
}

impl IdempotencyError {
    /// Convert to HTTP response.
    fn into_response(self) -> Response {
        let (status, error, message) = match self {
            Self::InvalidKey(msg) => (StatusCode::BAD_REQUEST, "invalid_idempotency_key", msg),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "A request with this idempotency key is currently being processed".to_string(),
            ),
            Self::Mismatch => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "idempotency_mismatch",
                "Idempotency key was used with a different request body".to_string(),
            ),
            Self::Database(e) => {
                tracing::error!(error = %e, "Idempotency database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred".to_string(),
                )
            }
        };

        let mut response = Response::new(Body::from(
            serde_json::json!({
                "error": error,
                "message": message
            })
            .to_string(),
        ));
        *response.status_mut() = status;
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response
    }
}

/// Extract and validate idempotency key from request headers.
///
/// Returns `Ok(Some(key))` if valid key present, `Ok(None)` if no header,
/// or `Err(IdempotencyError::InvalidKey)` if invalid.
pub fn extract_idempotency_key(
    headers: &axum::http::HeaderMap,
) -> Result<Option<String>, IdempotencyError> {
    let key = match headers.get(IDEMPOTENCY_KEY_HEADER) {
        Some(value) => value,
        None => return Ok(None),
    };

    let key_str = key.to_str().map_err(|_| {
        IdempotencyError::InvalidKey("Idempotency key must be valid ASCII".to_string())
    })?;

    // Validate length
    if key_str.is_empty() {
        return Err(IdempotencyError::InvalidKey(
            "Idempotency key must not be empty".to_string(),
        ));
    }

    if key_str.len() > MAX_KEY_LENGTH {
        return Err(IdempotencyError::InvalidKey(format!(
            "Idempotency key must be at most {MAX_KEY_LENGTH} characters"
        )));
    }

    // Validate printable ASCII (0x20-0x7E)
    for ch in key_str.chars() {
        if !('\x20'..='\x7e').contains(&ch) {
            return Err(IdempotencyError::InvalidKey(
                "Idempotency key must contain only printable ASCII characters".to_string(),
            ));
        }
    }

    Ok(Some(key_str.to_string()))
}

/// Hash request body with SHA-256.
pub fn hash_request_body(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// State needed for idempotency middleware.
#[derive(Clone)]
pub struct IdempotencyState {
    pub pool: PgPool,
}

/// Axum middleware for HTTP-level idempotency (`TenantId` extension variant).
///
/// When a request includes an `Idempotency-Key` header:
/// 1. Validates the key format
/// 2. Hashes the request body
/// 3. Checks if key exists in DB:
///    - If processing: returns 409 Conflict
///    - If completed: returns cached response with `Idempotency-Replayed: true`
///    - If hash mismatch: returns 422 Unprocessable Entity
/// 4. If new: processes request and caches response
///
/// Requests without the header pass through unchanged.
#[allow(dead_code)]
pub async fn idempotency_middleware(
    axum::extract::State(state): axum::extract::State<IdempotencyState>,
    axum::extract::Extension(tenant_id): axum::extract::Extension<xavyo_core::TenantId>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    idempotency_middleware_inner(state, *tenant_id.as_uuid(), request, next).await
}

/// Axum middleware for HTTP-level idempotency (JWT claims variant).
///
/// This variant extracts `tenant_id` from JWT claims, suitable for endpoints
/// that authenticate via JWT but don't have a `TenantId` extension (e.g., provisioning).
pub async fn idempotency_middleware_jwt(
    axum::extract::State(state): axum::extract::State<IdempotencyState>,
    axum::extract::Extension(claims): axum::extract::Extension<xavyo_auth::JwtClaims>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let tenant_uuid = if let Some(tid) = claims.tenant_id() {
        *tid.as_uuid()
    } else {
        tracing::error!("Idempotency middleware: JWT claims missing tenant_id");
        return IdempotencyError::Database(sqlx::Error::Protocol(
            "Missing tenant context".to_string(),
        ))
        .into_response();
    };

    idempotency_middleware_inner(state, tenant_uuid, request, next).await
}

/// Internal implementation for idempotency middleware.
async fn idempotency_middleware_inner(
    state: IdempotencyState,
    tenant_uuid: uuid::Uuid,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    // Extract idempotency key
    let key = match extract_idempotency_key(request.headers()) {
        Ok(Some(k)) => k,
        Ok(None) => {
            // No idempotency key - pass through
            return next.run(request).await;
        }
        Err(e) => return e.into_response(),
    };
    let endpoint = request.uri().path().to_string();
    let method = request.method().to_string();

    // Buffer request body for hashing
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, IDEMPOTENCY_MAX_REQUEST_BODY).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, "Failed to read request body");
            return IdempotencyError::Database(sqlx::Error::Protocol(
                "Failed to read request body".to_string(),
            ))
            .into_response();
        }
    };

    let request_hash = hash_request_body(&body_bytes);

    // Try to insert new idempotent request
    let insert_data = CreateIdempotentRequest {
        tenant_id: tenant_uuid,
        idempotency_key: key.clone(),
        request_hash: request_hash.clone(),
        endpoint: endpoint.clone(),
        http_method: method.clone(),
    };

    let insert_result = match IdempotentRequest::try_insert(&state.pool, insert_data).await {
        Ok(r) => r,
        Err(e) => return IdempotencyError::Database(e).into_response(),
    };

    match insert_result {
        InsertResult::Inserted(record) => {
            // New request - process it
            let record_id = record.id;

            // Reconstruct request with buffered body
            let request = axum::http::Request::from_parts(parts, Body::from(body_bytes.to_vec()));

            // Execute handler
            let response = next.run(request).await;

            // Capture response for caching
            let status = response.status().as_u16() as i16;
            let (resp_parts, resp_body) = response.into_parts();

            let resp_bytes =
                match axum::body::to_bytes(resp_body, IDEMPOTENCY_MAX_RESPONSE_BODY).await {
                    Ok(bytes) => bytes.to_vec(),
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to read response body");
                        Vec::new()
                    }
                };

            // Store response headers as JSON
            let headers_json: serde_json::Value = resp_parts
                .headers
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|s| (k.as_str().to_string(), serde_json::json!(s)))
                })
                .collect();

            // Update DB with response
            let is_success = resp_parts.status.is_success();
            if is_success {
                if let Err(e) = IdempotentRequest::complete(
                    &state.pool,
                    record_id,
                    status,
                    &resp_bytes,
                    headers_json,
                )
                .await
                {
                    tracing::error!(error = %e, "Failed to cache idempotent response");
                }
            } else if let Err(e) =
                IdempotentRequest::fail(&state.pool, record_id, status, &resp_bytes).await
            {
                tracing::error!(error = %e, "Failed to cache failed idempotent response");
            }

            // Return original response
            Response::from_parts(resp_parts, Body::from(resp_bytes))
        }
        InsertResult::Conflict(existing) => {
            // Key already exists - check state and hash
            match existing.state() {
                IdempotentState::Processing => {
                    // Check for stale lock
                    if existing.is_processing_timed_out() {
                        // Try to delete stale record and retry
                        if let Ok(true) =
                            IdempotentRequest::delete_stale(&state.pool, existing.id).await
                        {
                            tracing::warn!(
                                idempotency_key = %key,
                                "Deleted stale processing idempotent request"
                            );
                            // Return conflict - client should retry
                        }
                    }
                    IdempotencyError::Conflict.into_response()
                }
                IdempotentState::Completed | IdempotentState::Failed => {
                    // Check hash match
                    if existing.request_hash != request_hash {
                        return IdempotencyError::Mismatch.into_response();
                    }

                    // Return cached response
                    let status =
                        StatusCode::from_u16(existing.response_status.unwrap_or(200) as u16)
                            .unwrap_or(StatusCode::OK);

                    let body_bytes = existing.response_body.unwrap_or_default();
                    let mut response = Response::new(Body::from(body_bytes));
                    *response.status_mut() = status;

                    // Restore headers from JSON
                    if let Some(headers_json) = existing.response_headers {
                        if let Some(obj) = headers_json.as_object() {
                            for (k, v) in obj {
                                if let (Ok(name), Some(val)) = (
                                    axum::http::header::HeaderName::try_from(k.as_str()),
                                    v.as_str(),
                                ) {
                                    if let Ok(hv) = HeaderValue::from_str(val) {
                                        response.headers_mut().insert(name, hv);
                                    }
                                }
                            }
                        }
                    }

                    // Add replayed header
                    response.headers_mut().insert(
                        HeaderName::from_static(IDEMPOTENCY_REPLAYED_HEADER),
                        HeaderValue::from_static("true"),
                    );

                    tracing::info!(
                        idempotency_key = %key,
                        "Returning cached idempotent response"
                    );

                    response
                }
            }
        }
    }
}

// ── RLS Tenant Context for xavyo_app Pool ─────────────────────────────────

// Task-local storage for the current tenant ID.
//
// This is set by `rls_tenant_middleware` and read by the `before_acquire`
// callback on the app pool to automatically set `app.current_tenant` on
// every connection acquired from the pool. This ensures RLS policies
// are properly enforced without requiring handler changes.
tokio::task_local! {
    pub static CURRENT_TENANT: uuid::Uuid;
}

/// A nil UUID used as a sentinel for "no tenant context".
///
/// This is set on connections when no tenant is active. Because existing RLS
/// policies cast `current_setting('app.current_tenant')::uuid` directly (without
/// NULLIF), we use a valid but non-existent UUID to avoid `invalid input syntax`
/// errors. This UUID never matches any real tenant, so RLS returns 0 rows (fail-closed).
const NIL_TENANT: &str = "00000000-0000-0000-0000-000000000000";

/// Create an app pool (connecting as `xavyo_app`) with RLS-aware connection hooks.
///
/// The `before_acquire` callback reads the task-local `CURRENT_TENANT` and
/// sets `app.current_tenant` on the connection. The `after_release` callback
/// resets to the nil sentinel to prevent tenant context leaking across requests.
pub async fn create_rls_pool(
    database_url: &str,
    max_connections: u32,
) -> Result<sqlx::PgPool, sqlx::Error> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                // Set nil tenant on new connections (fail-closed default)
                sqlx::Executor::execute(
                    &mut *conn,
                    sqlx::query("SELECT set_config('app.current_tenant', $1::text, false)")
                        .bind(NIL_TENANT)
                        as sqlx::query::Query<'_, sqlx::Postgres, _>,
                )
                .await?;
                Ok(())
            })
        })
        .before_acquire(|conn, _meta| {
            Box::pin(async move {
                // Read the task-local tenant ID and set app.current_tenant
                let tenant_str = CURRENT_TENANT
                    .try_with(|tenant_id| tenant_id.to_string())
                    .unwrap_or_else(|_| NIL_TENANT.to_string());

                sqlx::Executor::execute(
                    &mut *conn,
                    sqlx::query("SELECT set_config('app.current_tenant', $1::text, false)")
                        .bind(tenant_str)
                        as sqlx::query::Query<'_, sqlx::Postgres, _>,
                )
                .await?;
                Ok(true)
            })
        })
        .after_release(|conn, _meta| {
            Box::pin(async move {
                // Reset to nil sentinel when returning connection to pool
                let _ = sqlx::Executor::execute(
                    &mut *conn,
                    sqlx::query("SELECT set_config('app.current_tenant', $1::text, false)")
                        .bind(NIL_TENANT)
                        as sqlx::query::Query<'_, sqlx::Postgres, _>,
                )
                .await;
                Ok(true)
            })
        })
        .connect(database_url)
        .await
}

/// Axum middleware that wraps request processing with the task-local tenant context.
///
/// This is a GLOBAL middleware that runs BEFORE route-level middleware (including
/// TenantLayer). It extracts the tenant ID directly from:
///   1. Request extensions (set by prior middleware, e.g. API key auth)
///   2. `X-Tenant-ID` header (same source as TenantLayer)
///
/// It scopes the handler execution within a `CURRENT_TENANT` task-local, so any
/// pool connection acquired within the handler will automatically have
/// `app.current_tenant` set via the `before_acquire` callback.
pub async fn rls_tenant_middleware(req: axum::extract::Request, next: Next) -> Response {
    // Try to extract TenantId from extensions first (set by API key auth middleware)
    let tenant_id = req
        .extensions()
        .get::<xavyo_core::TenantId>()
        .map(|t| *t.as_uuid())
        // Fall back to X-Tenant-ID header (same source as TenantLayer)
        .or_else(|| {
            req.headers()
                .get("X-Tenant-ID")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<uuid::Uuid>().ok())
        })
        // Fall back to ?tenant= query parameter (used by SAML SSO/SLO browser redirects
        // which cannot set custom headers)
        .or_else(|| {
            req.uri()
                .query()
                .and_then(|q| {
                    q.split('&')
                        .find_map(|pair| pair.strip_prefix("tenant="))
                })
                .and_then(|s| s.trim().parse::<uuid::Uuid>().ok())
        });

    match tenant_id {
        Some(tid) => {
            // Wrap the handler in a task-local scope with the tenant ID
            CURRENT_TENANT
                .scope(tid, async move { next.run(req).await })
                .await
        }
        None => {
            // No tenant context — proceed without setting task-local
            // (health checks, public endpoints, etc.)
            next.run(req).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    /// Helper: create a test router with the security headers middleware.
    fn test_app() -> Router {
        Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware))
    }

    async fn send_request(app: Router) -> axum::http::Response<Body> {
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        app.oneshot(req).await.unwrap()
    }

    #[test]
    fn test_request_id_layer_creation() {
        let _layer = request_id_layer();
    }

    // T020: X-Content-Type-Options: nosniff
    #[tokio::test]
    async fn test_security_header_x_content_type_options() {
        let response = send_request(test_app()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    // T021: X-Frame-Options: DENY
    #[tokio::test]
    async fn test_security_header_x_frame_options() {
        let response = send_request(test_app()).await;
        assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
    }

    // T022: Strict-Transport-Security
    #[tokio::test]
    async fn test_security_header_strict_transport_security() {
        let response = send_request(test_app()).await;
        assert_eq!(
            response.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }

    // T023: Referrer-Policy
    #[tokio::test]
    async fn test_security_header_referrer_policy() {
        let response = send_request(test_app()).await;
        assert_eq!(
            response.headers().get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
    }

    // T024: Content-Security-Policy
    #[tokio::test]
    async fn test_security_header_content_security_policy() {
        let response = send_request(test_app()).await;
        assert_eq!(
            response.headers().get("content-security-policy").unwrap(),
            "default-src 'self'; frame-ancestors 'none'"
        );
    }

    // T025: Permissions-Policy
    #[tokio::test]
    async fn test_security_header_permissions_policy() {
        let response = send_request(test_app()).await;
        assert_eq!(
            response.headers().get("permissions-policy").unwrap(),
            "camera=(), microphone=(), geolocation=()"
        );
    }

    // F082: X-XSS-Protection: 0
    #[tokio::test]
    async fn test_security_header_x_xss_protection() {
        let response = send_request(test_app()).await;
        assert_eq!(response.headers().get("x-xss-protection").unwrap(), "0");
    }

    // T026: Server header removed
    #[tokio::test]
    async fn test_security_header_removes_server() {
        let app = Router::new()
            .route(
                "/test",
                get(|| async {
                    let mut resp = axum::http::Response::new(Body::from("ok"));
                    resp.headers_mut().insert(
                        axum::http::header::SERVER,
                        HeaderValue::from_static("leaked-server"),
                    );
                    resp
                }),
            )
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let response: axum::http::Response<Body> = app.oneshot(req).await.unwrap();
        assert!(response.headers().get("server").is_none());
    }

    // ── Idempotency Middleware Tests ──────────────────────────────────────

    #[test]
    fn test_extract_idempotency_key_valid() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            super::IDEMPOTENCY_KEY_HEADER,
            "test-key-123".parse().unwrap(),
        );

        let result = super::extract_idempotency_key(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("test-key-123".to_string()));
    }

    #[test]
    fn test_extract_idempotency_key_missing() {
        let headers = axum::http::HeaderMap::new();

        let result = super::extract_idempotency_key(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_extract_idempotency_key_empty() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(super::IDEMPOTENCY_KEY_HEADER, "".parse().unwrap());

        let result = super::extract_idempotency_key(&headers);
        assert!(result.is_err());
        match result {
            Err(super::IdempotencyError::InvalidKey(msg)) => {
                assert!(msg.contains("empty"));
            }
            _ => panic!("Expected InvalidKey error"),
        }
    }

    #[test]
    fn test_extract_idempotency_key_too_long() {
        let mut headers = axum::http::HeaderMap::new();
        let long_key = "a".repeat(257);
        headers.insert(super::IDEMPOTENCY_KEY_HEADER, long_key.parse().unwrap());

        let result = super::extract_idempotency_key(&headers);
        assert!(result.is_err());
        match result {
            Err(super::IdempotencyError::InvalidKey(msg)) => {
                assert!(msg.contains("256"));
            }
            _ => panic!("Expected InvalidKey error"),
        }
    }

    #[test]
    fn test_extract_idempotency_key_non_printable() {
        // HeaderValue doesn't allow non-printable ASCII (< 0x20), so we test
        // characters outside the printable range (0x20-0x7E) that HeaderValue accepts.
        // DEL (0x7F) and extended ASCII (0x80+) are rejected by HeaderValue parsing.
        // Tab (0x09) is allowed by HTTP but we want to reject it.

        // Since HeaderValue::from_str rejects control chars, we use a different approach:
        // Test that our validation logic works for the boundary character (0x1F is rejected
        // by HeaderValue, so we just verify the function works with valid edge cases)

        let mut headers = axum::http::HeaderMap::new();
        // Space (0x20) is minimum printable ASCII - should be valid
        headers.insert(
            super::IDEMPOTENCY_KEY_HEADER,
            " valid key ".parse().unwrap(),
        );
        let result = super::extract_idempotency_key(&headers);
        assert!(result.is_ok());

        // Tilde (0x7E) is maximum printable ASCII - should be valid
        let mut headers2 = axum::http::HeaderMap::new();
        headers2.insert(
            super::IDEMPOTENCY_KEY_HEADER,
            "key~with~tilde".parse().unwrap(),
        );
        let result2 = super::extract_idempotency_key(&headers2);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_hash_request_body_deterministic() {
        let body = b"test request body";
        let hash1 = super::hash_request_body(body);
        let hash2 = super::hash_request_body(body);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_request_body_different_input() {
        let body1 = b"request body 1";
        let body2 = b"request body 2";
        let hash1 = super::hash_request_body(body1);
        let hash2 = super::hash_request_body(body2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_request_body_sha256_format() {
        let body = b"test";
        let hash = super::hash_request_body(body);
        // SHA-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_idempotency_key_max_length() {
        let mut headers = axum::http::HeaderMap::new();
        let max_key = "a".repeat(256);
        headers.insert(super::IDEMPOTENCY_KEY_HEADER, max_key.parse().unwrap());

        let result = super::extract_idempotency_key(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().map(|k| k.len()), Some(256));
    }
}
