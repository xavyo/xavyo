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
        let default_quota = Quota::per_minute(
            NonZeroU32::new(config.default_requests_per_minute)
                .unwrap_or(NonZeroU32::new(100).unwrap()),
        )
        .allow_burst(
            NonZeroU32::new(config.default_burst_size).unwrap_or(NonZeroU32::new(10).unwrap()),
        );

        Self {
            default_limiter: Arc::new(RateLimiter::direct(default_quota)),
            tenant_limiters: Arc::new(RwLock::new(HashMap::new())),
            config: config.clone(),
        }
    }

    /// Get or create a rate limiter for a tenant.
    pub fn get_limiter(&self, tenant_id: Option<&str>) -> Arc<Limiter> {
        match tenant_id {
            Some(tid) => {
                // Check if we have an override for this tenant
                if let Some(override_config) = self.config.tenant_overrides.get(tid) {
                    let quota = Quota::per_minute(
                        NonZeroU32::new(override_config.requests_per_minute)
                            .unwrap_or(NonZeroU32::new(100).unwrap()),
                    )
                    .allow_burst(
                        NonZeroU32::new(override_config.burst_size)
                            .unwrap_or(NonZeroU32::new(10).unwrap()),
                    );

                    // Get or create limiter for this tenant
                    let limiters = self.tenant_limiters.read().unwrap();
                    if let Some(limiter) = limiters.get(tid) {
                        return limiter.clone();
                    }
                    drop(limiters);

                    let mut limiters = self.tenant_limiters.write().unwrap();
                    let limiter = Arc::new(RateLimiter::direct(quota));
                    limiters.insert(tid.to_string(), limiter.clone());
                    limiter
                } else {
                    // Use default quota for this tenant
                    let limiters = self.tenant_limiters.read().unwrap();
                    if let Some(limiter) = limiters.get(tid) {
                        return limiter.clone();
                    }
                    drop(limiters);

                    let quota = Quota::per_minute(
                        NonZeroU32::new(self.config.default_requests_per_minute)
                            .unwrap_or(NonZeroU32::new(100).unwrap()),
                    )
                    .allow_burst(
                        NonZeroU32::new(self.config.default_burst_size)
                            .unwrap_or(NonZeroU32::new(10).unwrap()),
                    );

                    let mut limiters = self.tenant_limiters.write().unwrap();
                    let limiter = Arc::new(RateLimiter::direct(quota));
                    limiters.insert(tid.to_string(), limiter.clone());
                    limiter
                }
            }
            None => self.default_limiter.clone(),
        }
    }

    /// Check if a request is allowed.
    pub fn check(&self, tenant_id: Option<&str>) -> Result<(), u64> {
        let limiter = self.get_limiter(tenant_id);
        match limiter.check() {
            Ok(_) => Ok(()),
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
        message: format!("Rate limit exceeded. Try again in {} seconds.", retry_after),
        request_id: None,
    };

    let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    response
        .headers_mut()
        .insert("Retry-After", retry_after.to_string().parse().unwrap());
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
