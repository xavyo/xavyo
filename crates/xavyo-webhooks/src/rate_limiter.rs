//! Rate limiter implementation for webhook delivery.
//!
//! Provides per-destination rate limiting using a token bucket algorithm
//! to prevent overwhelming webhook endpoints with too many requests.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Configuration for rate limiting behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of requests per second.
    pub requests_per_second: f64,
    /// Maximum burst size (token bucket capacity).
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10.0,
            burst_size: 20,
        }
    }
}

impl RateLimitConfig {
    /// Create a new rate limit configuration.
    #[must_use] 
    pub fn new(requests_per_second: f64, burst_size: u32) -> Self {
        Self {
            requests_per_second,
            burst_size,
        }
    }

    /// Create a configuration with custom requests per second.
    #[must_use] 
    pub fn with_requests_per_second(mut self, rps: f64) -> Self {
        self.requests_per_second = rps;
        self
    }

    /// Create a configuration with custom burst size.
    #[must_use] 
    pub fn with_burst_size(mut self, size: u32) -> Self {
        self.burst_size = size;
        self
    }
}

/// Token bucket rate limiter for a single subscription.
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    ///
    /// Starts with a full bucket of tokens.
    #[must_use] 
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            tokens: f64::from(config.burst_size),
            config,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = elapsed.as_secs_f64() * self.config.requests_per_second;

        self.tokens = (self.tokens + new_tokens).min(f64::from(self.config.burst_size));
        self.last_refill = now;
    }

    /// Try to acquire a token without blocking.
    ///
    /// Returns `true` if a token was acquired, `false` if rate limited.
    pub fn try_acquire(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Acquire a token, waiting if necessary.
    ///
    /// Returns the duration waited (zero if no wait was needed).
    pub async fn acquire(&mut self) -> Duration {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Duration::ZERO;
        }

        // Calculate wait time
        let tokens_needed = 1.0 - self.tokens;
        let wait_secs = tokens_needed / self.config.requests_per_second;
        let wait_duration = Duration::from_secs_f64(wait_secs);

        tokio::time::sleep(wait_duration).await;

        // After waiting, we should have enough tokens
        self.tokens = 0.0;
        self.last_refill = Instant::now();

        wait_duration
    }

    /// Get the current number of available tokens.
    pub fn available_tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    /// Get the configuration.
    #[must_use] 
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Check if any tokens are available without consuming them.
    pub fn has_capacity(&mut self) -> bool {
        self.refill();
        self.tokens >= 1.0
    }
}

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed to proceed.
    Allowed,
    /// Request should wait for the specified duration.
    Wait(Duration),
    /// Request is rejected (no waiting configured).
    Rejected,
}

/// Registry for managing rate limiters across all subscriptions.
#[derive(Clone)]
pub struct RateLimiterRegistry {
    limiters: Arc<RwLock<HashMap<Uuid, RateLimiter>>>,
    default_config: RateLimitConfig,
}

impl RateLimiterRegistry {
    /// Create a new registry with the given default configuration.
    #[must_use] 
    pub fn new(default_config: RateLimitConfig) -> Self {
        Self {
            limiters: Arc::new(RwLock::new(HashMap::new())),
            default_config,
        }
    }

    /// Get or create a rate limiter for a subscription.
    #[allow(dead_code)]
    async fn get_or_create(&self, subscription_id: Uuid) -> RateLimiter {
        {
            let limiters = self.limiters.read().await;
            if let Some(limiter) = limiters.get(&subscription_id) {
                // Clone the config and current state
                return RateLimiter {
                    config: limiter.config.clone(),
                    tokens: limiter.tokens,
                    last_refill: limiter.last_refill,
                };
            }
        }

        // Create new limiter
        RateLimiter::new(self.default_config.clone())
    }

    /// Try to acquire a token for a subscription without blocking.
    ///
    /// Returns `true` if allowed, `false` if rate limited.
    pub async fn try_acquire(&self, subscription_id: Uuid) -> bool {
        let mut limiters = self.limiters.write().await;
        let limiter = limiters
            .entry(subscription_id)
            .or_insert_with(|| RateLimiter::new(self.default_config.clone()));
        limiter.try_acquire()
    }

    /// Acquire a token for a subscription, waiting if necessary.
    ///
    /// Returns the duration waited.
    pub async fn acquire(&self, subscription_id: Uuid) -> Duration {
        let mut limiters = self.limiters.write().await;
        let limiter = limiters
            .entry(subscription_id)
            .or_insert_with(|| RateLimiter::new(self.default_config.clone()));

        // Check if we can acquire immediately
        limiter.refill();
        if limiter.tokens >= 1.0 {
            limiter.tokens -= 1.0;
            return Duration::ZERO;
        }

        // Calculate wait time
        let tokens_needed = 1.0 - limiter.tokens;
        let wait_secs = tokens_needed / limiter.config.requests_per_second;
        let wait_duration = Duration::from_secs_f64(wait_secs);

        // Drop the lock before sleeping
        drop(limiters);

        tokio::time::sleep(wait_duration).await;

        // Re-acquire the lock and consume the token
        let mut limiters = self.limiters.write().await;
        let limiter = limiters
            .entry(subscription_id)
            .or_insert_with(|| RateLimiter::new(self.default_config.clone()));
        limiter.refill();
        limiter.tokens = (limiter.tokens - 1.0).max(0.0);

        wait_duration
    }

    /// Check rate limit status for a subscription without consuming a token.
    pub async fn check(&self, subscription_id: Uuid) -> RateLimitResult {
        let mut limiters = self.limiters.write().await;
        let limiter = limiters
            .entry(subscription_id)
            .or_insert_with(|| RateLimiter::new(self.default_config.clone()));

        limiter.refill();

        if limiter.tokens >= 1.0 {
            RateLimitResult::Allowed
        } else {
            let tokens_needed = 1.0 - limiter.tokens;
            let wait_secs = tokens_needed / limiter.config.requests_per_second;
            RateLimitResult::Wait(Duration::from_secs_f64(wait_secs))
        }
    }

    /// Set a custom rate limit configuration for a subscription.
    pub async fn set_config(&self, subscription_id: Uuid, config: RateLimitConfig) {
        let mut limiters = self.limiters.write().await;
        let limiter = limiters
            .entry(subscription_id)
            .or_insert_with(|| RateLimiter::new(config.clone()));
        limiter.config = config;
    }

    /// Remove a rate limiter for a subscription.
    pub async fn remove(&self, subscription_id: Uuid) {
        let mut limiters = self.limiters.write().await;
        limiters.remove(&subscription_id);
    }

    /// Clear all rate limiters.
    pub async fn clear(&self) {
        let mut limiters = self.limiters.write().await;
        limiters.clear();
    }

    /// Get the number of active rate limiters.
    pub async fn count(&self) -> usize {
        let limiters = self.limiters.read().await;
        limiters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_second, 10.0);
        assert_eq!(config.burst_size, 20);
    }

    #[test]
    fn test_rate_limit_config_builder() {
        let config = RateLimitConfig::default()
            .with_requests_per_second(5.0)
            .with_burst_size(10);

        assert_eq!(config.requests_per_second, 5.0);
        assert_eq!(config.burst_size, 10);
    }

    #[test]
    fn test_rate_limiter_new() {
        let config = RateLimitConfig::new(10.0, 20);
        let mut limiter = RateLimiter::new(config);

        // Should start with full bucket
        assert_eq!(limiter.available_tokens(), 20.0);
    }

    #[test]
    fn test_rate_limiter_try_acquire_success() {
        let config = RateLimitConfig::new(10.0, 5);
        let mut limiter = RateLimiter::new(config);

        // Should succeed 5 times (burst size)
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }

        // 6th should fail (no time to refill)
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_rate_limiter_has_capacity() {
        let config = RateLimitConfig::new(10.0, 2);
        let mut limiter = RateLimiter::new(config);

        assert!(limiter.has_capacity());

        // Consume all tokens
        limiter.try_acquire();
        limiter.try_acquire();

        assert!(!limiter.has_capacity());
    }

    #[tokio::test]
    async fn test_rate_limiter_acquire_waits() {
        let config = RateLimitConfig::new(100.0, 1); // 100 RPS, burst of 1
        let mut limiter = RateLimiter::new(config);

        // First acquire should be instant
        let wait1 = limiter.acquire().await;
        assert_eq!(wait1, Duration::ZERO);

        // Second acquire should wait ~10ms
        let wait2 = limiter.acquire().await;
        assert!(wait2 > Duration::ZERO);
        assert!(wait2 < Duration::from_millis(50)); // Should be ~10ms
    }

    #[tokio::test]
    async fn test_rate_limiter_registry_try_acquire() {
        let registry = RateLimiterRegistry::new(RateLimitConfig::new(10.0, 2));
        let sub_id = Uuid::new_v4();

        // Should succeed twice
        assert!(registry.try_acquire(sub_id).await);
        assert!(registry.try_acquire(sub_id).await);

        // Third should fail
        assert!(!registry.try_acquire(sub_id).await);
    }

    #[tokio::test]
    async fn test_rate_limiter_registry_check() {
        let registry = RateLimiterRegistry::new(RateLimitConfig::new(10.0, 1));
        let sub_id = Uuid::new_v4();

        // First check should be allowed
        match registry.check(sub_id).await {
            RateLimitResult::Allowed => {}
            _ => panic!("Expected Allowed"),
        }

        // Consume the token
        registry.try_acquire(sub_id).await;

        // Next check should indicate wait
        match registry.check(sub_id).await {
            RateLimitResult::Wait(d) => {
                assert!(d > Duration::ZERO);
            }
            _ => panic!("Expected Wait"),
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_registry_set_config() {
        let registry = RateLimiterRegistry::new(RateLimitConfig::default());
        let sub_id = Uuid::new_v4();

        // Set custom config
        registry
            .set_config(sub_id, RateLimitConfig::new(5.0, 100))
            .await;

        // Should be able to acquire 100 times (custom burst)
        for _ in 0..100 {
            assert!(registry.try_acquire(sub_id).await);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_registry_remove() {
        let registry = RateLimiterRegistry::new(RateLimitConfig::new(10.0, 1));
        let sub_id = Uuid::new_v4();

        // Exhaust tokens
        registry.try_acquire(sub_id).await;
        assert!(!registry.try_acquire(sub_id).await);

        // Remove and re-add (should get fresh bucket)
        registry.remove(sub_id).await;
        assert!(registry.try_acquire(sub_id).await);
    }

    #[tokio::test]
    async fn test_rate_limiter_registry_count() {
        let registry = RateLimiterRegistry::new(RateLimitConfig::default());

        assert_eq!(registry.count().await, 0);

        // Create limiters for 3 subscriptions
        for _ in 0..3 {
            registry.try_acquire(Uuid::new_v4()).await;
        }

        assert_eq!(registry.count().await, 3);

        // Clear should remove all
        registry.clear().await;
        assert_eq!(registry.count().await, 0);
    }

    #[tokio::test]
    async fn test_rate_limiter_refills_over_time() {
        let config = RateLimitConfig::new(1000.0, 1); // 1000 RPS
        let mut limiter = RateLimiter::new(config);

        // Consume the token
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());

        // Wait a bit for refill
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should have refilled some tokens
        assert!(limiter.available_tokens() > 0.0);
    }
}
