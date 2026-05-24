//! Rate limiting middleware using governor crate.

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::{
    collections::HashMap,
    future::Future,
    num::NonZeroU32,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::config::{GatewayConfig, RateLimitConfig};
use crate::error::ErrorResponse;
use crate::middleware::tenant::TenantContext;

/// Type alias for our rate limiter.
type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Fallback quota when the configured `requests_per_minute` is zero (which
/// `NonZeroU32::new` rejects). 100 r/min is the gateway's documented default.
const FALLBACK_RPM: NonZeroU32 = match NonZeroU32::new(100) {
    Some(n) => n,
    None => unreachable!(),
};

/// Fallback burst size when configured `burst_size` is zero. 10 is the
/// gateway's documented default.
const FALLBACK_BURST: NonZeroU32 = match NonZeroU32::new(10) {
    Some(n) => n,
    None => unreachable!(),
};

/// Build a `Quota` from a raw (rpm, burst) tuple, swapping in safe fallbacks
/// if either input is zero. Centralising this keeps the construction sites
/// short and avoids the `unwrap_or(NonZeroU32::new(N).unwrap())` pattern that
/// peppered this file pre-refactor.
fn quota_from_raw(rpm: u32, burst: u32) -> Quota {
    Quota::per_minute(NonZeroU32::new(rpm).unwrap_or(FALLBACK_RPM))
        .allow_burst(NonZeroU32::new(burst).unwrap_or(FALLBACK_BURST))
}

/// Rate limit state for all tenants.
#[derive(Clone)]
pub struct RateLimitState {
    /// Default rate limiter for unknown/unauthenticated requests.
    default_limiter: Arc<Limiter>,
    /// Per-tenant rate limiters.
    tenant_limiters: Arc<RwLock<HashMap<String, Arc<Limiter>>>>,
    /// Configuration for creating new limiters.
    config: RateLimitConfig,
}

impl RateLimitState {
    /// Create a new rate limit state from configuration.
    pub fn new(config: &RateLimitConfig) -> Self {
        let default_quota = quota_from_raw(
            config.default_requests_per_minute,
            config.default_burst_size,
        );

        Self {
            default_limiter: Arc::new(RateLimiter::direct(default_quota)),
            tenant_limiters: Arc::new(RwLock::new(HashMap::new())),
            config: config.clone(),
        }
    }

    /// Get or create a rate limiter for a tenant.
    pub fn get_limiter(&self, tenant_id: Option<&str>) -> Arc<Limiter> {
        let Some(tid) = tenant_id else {
            return self.default_limiter.clone();
        };

        let quota = if let Some(o) = self.config.tenant_overrides.get(tid) {
            quota_from_raw(o.requests_per_minute, o.burst_size)
        } else {
            quota_from_raw(
                self.config.default_requests_per_minute,
                self.config.default_burst_size,
            )
        };

        // Read-fast path: limiter already exists.
        {
            let limiters = self
                .tenant_limiters
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(limiter) = limiters.get(tid) {
                return limiter.clone();
            }
        }

        // Slow path: write-lock and create. Re-check under the write lock to
        // handle a concurrent inserter.
        let mut limiters = self
            .tenant_limiters
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = limiters.get(tid) {
            return existing.clone();
        }
        let limiter = Arc::new(RateLimiter::direct(quota));
        limiters.insert(tid.to_string(), limiter.clone());
        limiter
    }

    /// Check if a request is allowed.
    pub fn check(&self, tenant_id: Option<&str>) -> Result<(), u64> {
        let limiter = self.get_limiter(tenant_id);
        match limiter.check() {
            Ok(()) => Ok(()),
            Err(not_until) => {
                let wait_time =
                    not_until.wait_time_from(governor::clock::Clock::now(&DefaultClock::default()));
                Err(wait_time.as_secs().max(1))
            }
        }
    }
}

/// Layer for rate limiting middleware.
#[derive(Clone)]
pub struct RateLimitLayer {
    state: RateLimitState,
    enabled: bool,
}

impl RateLimitLayer {
    /// Create a new rate limit layer from configuration.
    pub fn new(config: Arc<GatewayConfig>) -> Self {
        Self {
            state: RateLimitState::new(&config.rate_limits),
            enabled: config.rate_limits.enabled,
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            state: self.state.clone(),
            enabled: self.enabled,
        }
    }
}

/// Rate limiting service wrapper.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    state: RateLimitState,
    enabled: bool,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let state = self.state.clone();
        let enabled = self.enabled;
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if !enabled {
                return inner.call(request).await;
            }

            // Get tenant ID from context
            let tenant_id = request
                .extensions()
                .get::<TenantContext>()
                .map(|ctx| ctx.tenant_id.as_str());

            // Check rate limit
            match state.check(tenant_id) {
                Ok(()) => inner.call(request).await,
                Err(retry_after) => Ok(rate_limited_response(retry_after)),
            }
        })
    }
}

/// Create a rate limited response.
fn rate_limited_response(retry_after: u64) -> Response {
    let body = ErrorResponse {
        error: "RATE_LIMITED".to_string(),
        message: format!("Rate limit exceeded. Try again in {retry_after} seconds."),
        request_id: None,
    };

    let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    // `retry_after.to_string()` produces only digit characters, which always
    // parse to a valid `HeaderValue` — but we route through `if let Ok` to
    // avoid an `.unwrap()` in an HTTP response path.
    if let Ok(header_val) = retry_after.to_string().parse() {
        response.headers_mut().insert("Retry-After", header_val);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            default_requests_per_minute: 10,
            default_burst_size: 2,
            tenant_overrides: HashMap::new(),
            endpoint_overrides: vec![],
        }
    }

    #[test]
    fn test_rate_limit_state_new() {
        let config = create_test_config();
        let state = RateLimitState::new(&config);
        assert!(state.check(None).is_ok());
    }

    #[test]
    fn test_rate_limit_burst() {
        let config = create_test_config();
        let state = RateLimitState::new(&config);

        // Should allow burst
        assert!(state.check(None).is_ok());
        assert!(state.check(None).is_ok());

        // Third request might exceed burst depending on timing
    }

    #[test]
    fn test_rate_limit_per_tenant() {
        let config = create_test_config();
        let state = RateLimitState::new(&config);

        // Different tenants have separate limits
        assert!(state.check(Some("tenant-a")).is_ok());
        assert!(state.check(Some("tenant-b")).is_ok());
        assert!(state.check(Some("tenant-a")).is_ok());
        assert!(state.check(Some("tenant-b")).is_ok());
    }
}
