//! Rate limiting middleware using token bucket algorithm.

use axum::{
    body::Body,
    http::Request,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tower::{Layer, Service};
use uuid::Uuid;

use crate::error::ScimError;
use crate::middleware::auth::ScimAuthContext;

/// Token bucket for rate limiting.
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current number of tokens available.
    tokens: f64,
    /// Maximum tokens (burst capacity).
    max_tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, tokens: f64) -> Option<Duration> {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            None // Success
        } else {
            // Calculate wait time
            let needed = tokens - self.tokens;
            let wait_secs = needed / self.refill_rate;
            Some(Duration::from_secs_f64(wait_secs))
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = elapsed * self.refill_rate;

        self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
        self.last_refill = now;
    }
}

/// Rate limiter state shared across requests.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<Uuid, TokenBucket>>>,
    max_tokens: f64,
    refill_rate: f64,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `requests_per_second`: Maximum sustained request rate.
    /// - `burst`: Maximum burst capacity.
    #[must_use] 
    pub fn new(requests_per_second: u32, burst: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_tokens: f64::from(burst),
            refill_rate: f64::from(requests_per_second),
        }
    }

    /// Try to acquire a token for the given tenant.
    ///
    /// Returns `None` if allowed, or `Some(wait_time)` if rate limited.
    #[must_use] 
    pub fn try_acquire(&self, tenant_id: Uuid) -> Option<Duration> {
        let mut buckets = self.buckets.lock().unwrap();

        let bucket = buckets
            .entry(tenant_id)
            .or_insert_with(|| TokenBucket::new(self.max_tokens, self.refill_rate));

        bucket.try_consume(1.0)
    }

    /// Clean up old buckets that haven't been used recently.
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();

        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }
}

/// Layer for rate limiting SCIM requests.
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: RateLimiter,
}

impl RateLimitLayer {
    /// Create a new rate limit layer.
    ///
    /// - `requests_per_second`: Maximum sustained request rate per tenant.
    /// - `burst`: Maximum burst capacity per tenant.
    #[must_use] 
    pub fn new(requests_per_second: u32, burst: u32) -> Self {
        Self {
            limiter: RateLimiter::new(requests_per_second, burst),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

/// Rate limiting service wrapper.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    limiter: RateLimiter,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let limiter = self.limiter.clone();
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            // Get tenant ID from auth context
            let tenant_id = req
                .extensions()
                .get::<ScimAuthContext>()
                .map(|ctx| ctx.tenant_id);

            // Only rate limit if we have a tenant ID
            if let Some(tenant_id) = tenant_id {
                if let Some(wait_time) = limiter.try_acquire(tenant_id) {
                    let retry_after = wait_time.as_secs().max(1) as u32;
                    return Ok(ScimError::RateLimitExceeded { retry_after }.into_response());
                }
            }

            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_initial() {
        let bucket = TokenBucket::new(50.0, 25.0);
        assert_eq!(bucket.tokens, 50.0);
        assert_eq!(bucket.max_tokens, 50.0);
        assert_eq!(bucket.refill_rate, 25.0);
    }

    #[test]
    fn test_token_bucket_consume() {
        let mut bucket = TokenBucket::new(10.0, 10.0);

        // Should succeed
        assert!(bucket.try_consume(1.0).is_none());
        // Tokens should be around 9.0 (may be slightly higher due to refill)
        assert!(bucket.tokens <= 9.0 + 0.1);
        assert!(bucket.tokens >= 8.9);

        // Consume all remaining in one call to minimize time drift
        let remaining = bucket.tokens;
        assert!(bucket.try_consume(remaining).is_none());
        // Tokens should now be very close to 0 (may be slightly higher due to refill)
        assert!(bucket.tokens < 0.1);

        // Should fail (need to consume more than available)
        let wait = bucket.try_consume(1.0);
        assert!(wait.is_some());
    }

    #[test]
    fn test_rate_limiter_per_tenant() {
        let limiter = RateLimiter::new(100, 100);
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();

        // Consume all tokens for tenant1
        for _ in 0..100 {
            assert!(limiter.try_acquire(tenant1).is_none());
        }

        // Tenant1 should be rate limited
        assert!(limiter.try_acquire(tenant1).is_some());

        // Tenant2 should still be allowed
        assert!(limiter.try_acquire(tenant2).is_none());
    }

    #[test]
    fn test_rate_limiter_burst() {
        let limiter = RateLimiter::new(25, 50);
        let tenant = Uuid::new_v4();

        // Should allow burst of 50
        for _ in 0..50 {
            assert!(limiter.try_acquire(tenant).is_none());
        }

        // 51st request should be rate limited
        assert!(limiter.try_acquire(tenant).is_some());
    }
}
