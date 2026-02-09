//! Integration tests for the rate limiter functionality.
//!
//! Tests token bucket rate limiting, burst handling, token refill,
//! and webhook queuing behavior.

use std::time::Duration;

use uuid::Uuid;
use xavyo_webhooks::{RateLimitConfig, RateLimitResult, RateLimiter, RateLimiterRegistry};

// ---------------------------------------------------------------------------
// T051: rate_limiter_throttles_excess_requests
// ---------------------------------------------------------------------------

#[test]
fn rate_limiter_throttles_excess_requests() {
    let config = RateLimitConfig::new(10.0, 5); // 10 RPS, burst of 5
    let mut limiter = RateLimiter::new(config);

    // Should allow first 5 requests (burst)
    for _ in 0..5 {
        assert!(limiter.try_acquire());
    }

    // 6th request should be throttled
    assert!(!limiter.try_acquire());
}

#[test]
fn rate_limiter_throttles_at_burst_limit() {
    let config = RateLimitConfig::new(100.0, 3);
    let mut limiter = RateLimiter::new(config);

    assert!(limiter.try_acquire()); // 1
    assert!(limiter.try_acquire()); // 2
    assert!(limiter.try_acquire()); // 3
    assert!(!limiter.try_acquire()); // Throttled
}

// ---------------------------------------------------------------------------
// T052: rate_limiter_allows_burst
// ---------------------------------------------------------------------------

#[test]
fn rate_limiter_allows_burst() {
    let config = RateLimitConfig::new(1.0, 10); // 1 RPS, burst of 10
    let mut limiter = RateLimiter::new(config);

    // Should allow all 10 requests in burst
    let mut count = 0;
    while limiter.try_acquire() && count < 20 {
        count += 1;
    }

    // Should have allowed exactly 10 (the burst size)
    assert_eq!(count, 10);
}

#[test]
fn rate_limiter_burst_size_respected() {
    let config = RateLimitConfig::new(0.1, 20); // Very low RPS, burst of 20
    let mut limiter = RateLimiter::new(config);

    // Should allow 20 rapid requests
    for i in 0..20 {
        assert!(limiter.try_acquire(), "Failed at request {i}");
    }

    // 21st should fail
    assert!(!limiter.try_acquire());
}

// ---------------------------------------------------------------------------
// T053: rate_limiter_refills_tokens_over_time
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limiter_refills_tokens_over_time() {
    let config = RateLimitConfig::new(1000.0, 1); // 1000 RPS = 1 token per ms
    let mut limiter = RateLimiter::new(config);

    // Exhaust the token
    assert!(limiter.try_acquire());
    assert!(!limiter.try_acquire());

    // Wait for refill (at 1000 RPS, should refill ~10 tokens in 10ms)
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Should have refilled
    assert!(limiter.try_acquire());
}

#[tokio::test]
async fn rate_limiter_refills_proportionally() {
    let config = RateLimitConfig::new(100.0, 5); // 100 RPS = 1 token per 10ms
    let mut limiter = RateLimiter::new(config);

    // Exhaust all tokens
    for _ in 0..5 {
        limiter.try_acquire();
    }
    assert!(!limiter.try_acquire());

    // Wait for partial refill
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Should have refilled ~3 tokens
    let available = limiter.available_tokens();
    assert!((2.0..=5.0).contains(&available));
}

#[tokio::test]
async fn rate_limiter_caps_at_burst_size() {
    let config = RateLimitConfig::new(1000.0, 5);
    let mut limiter = RateLimiter::new(config);

    // Already at max (5 tokens)
    assert_eq!(limiter.available_tokens(), 5.0);

    // Wait for would-be refill
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Should still be capped at 5
    assert_eq!(limiter.available_tokens(), 5.0);
}

// ---------------------------------------------------------------------------
// T054: rate_limiter_queues_excess_webhooks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limiter_acquire_waits_when_needed() {
    let config = RateLimitConfig::new(100.0, 1); // 100 RPS, burst of 1
    let mut limiter = RateLimiter::new(config);

    // First acquire is instant
    let wait1 = limiter.acquire().await;
    assert_eq!(wait1, Duration::ZERO);

    // Second acquire should wait ~10ms
    let wait2 = limiter.acquire().await;
    assert!(wait2 > Duration::ZERO);
    assert!(wait2 < Duration::from_millis(50));
}

#[tokio::test]
async fn rate_limiter_registry_queues_requests() {
    let registry = RateLimiterRegistry::new(RateLimitConfig::new(100.0, 1));
    let sub_id = Uuid::new_v4();

    // First request is instant
    let wait1 = registry.acquire(sub_id).await;
    assert_eq!(wait1, Duration::ZERO);

    // Second request waits
    let wait2 = registry.acquire(sub_id).await;
    assert!(wait2 > Duration::ZERO);
}

// ---------------------------------------------------------------------------
// Additional rate limiter tests
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_config_defaults() {
    let config = RateLimitConfig::default();

    assert_eq!(config.requests_per_second, 10.0);
    assert_eq!(config.burst_size, 20);
}

#[test]
fn rate_limit_config_builder() {
    let config = RateLimitConfig::default()
        .with_requests_per_second(5.0)
        .with_burst_size(10);

    assert_eq!(config.requests_per_second, 5.0);
    assert_eq!(config.burst_size, 10);
}

#[test]
fn rate_limiter_has_capacity() {
    let config = RateLimitConfig::new(10.0, 2);
    let mut limiter = RateLimiter::new(config);

    assert!(limiter.has_capacity());

    limiter.try_acquire();
    limiter.try_acquire();

    assert!(!limiter.has_capacity());
}

#[tokio::test]
async fn rate_limiter_registry_check_result() {
    let registry = RateLimiterRegistry::new(RateLimitConfig::new(10.0, 1));
    let sub_id = Uuid::new_v4();

    // First check should be allowed
    match registry.check(sub_id).await {
        RateLimitResult::Allowed => {}
        _ => panic!("Expected Allowed"),
    }

    // Consume the token
    registry.try_acquire(sub_id).await;

    // Second check should indicate wait
    match registry.check(sub_id).await {
        RateLimitResult::Wait(d) => {
            assert!(d > Duration::ZERO);
        }
        _ => panic!("Expected Wait"),
    }
}

#[tokio::test]
async fn rate_limiter_registry_per_subscription() {
    let registry = RateLimiterRegistry::new(RateLimitConfig::new(10.0, 1));
    let sub_1 = Uuid::new_v4();
    let sub_2 = Uuid::new_v4();

    // Each subscription has its own rate limiter
    assert!(registry.try_acquire(sub_1).await);
    assert!(registry.try_acquire(sub_2).await);

    // Both are now exhausted
    assert!(!registry.try_acquire(sub_1).await);
    assert!(!registry.try_acquire(sub_2).await);
}

#[tokio::test]
async fn rate_limiter_registry_set_custom_config() {
    let registry = RateLimiterRegistry::new(RateLimitConfig::default());
    let sub_id = Uuid::new_v4();

    // Set custom config with large burst
    registry
        .set_config(sub_id, RateLimitConfig::new(10.0, 100))
        .await;

    // Should be able to acquire many tokens
    for i in 0..100 {
        assert!(registry.try_acquire(sub_id).await, "Failed at {i}");
    }

    // 101st should fail
    assert!(!registry.try_acquire(sub_id).await);
}

#[tokio::test]
async fn rate_limiter_registry_remove_resets() {
    let registry = RateLimiterRegistry::new(RateLimitConfig::new(10.0, 1));
    let sub_id = Uuid::new_v4();

    // Exhaust the token
    assert!(registry.try_acquire(sub_id).await);
    assert!(!registry.try_acquire(sub_id).await);

    // Remove the limiter
    registry.remove(sub_id).await;

    // New limiter should have fresh tokens
    assert!(registry.try_acquire(sub_id).await);
}

#[tokio::test]
async fn rate_limiter_registry_clear() {
    let registry = RateLimiterRegistry::new(RateLimitConfig::default());

    // Create limiters for multiple subscriptions
    for _ in 0..5 {
        registry.try_acquire(Uuid::new_v4()).await;
    }

    assert_eq!(registry.count().await, 5);

    registry.clear().await;

    assert_eq!(registry.count().await, 0);
}

#[test]
fn rate_limiter_available_tokens() {
    let config = RateLimitConfig::new(10.0, 5);
    let mut limiter = RateLimiter::new(config);

    assert_eq!(limiter.available_tokens(), 5.0);

    limiter.try_acquire();
    limiter.try_acquire();

    // Should have ~3 tokens left (might have refilled slightly)
    let available = limiter.available_tokens();
    assert!((3.0..=5.0).contains(&available));
}

#[test]
fn rate_limiter_config_serialization() {
    let config = RateLimitConfig::new(50.0, 100);

    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("50"));
    assert!(json.contains("100"));

    let deserialized: RateLimitConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.requests_per_second, 50.0);
    assert_eq!(deserialized.burst_size, 100);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn rate_limiter_handles_zero_burst() {
    // Zero burst size is an edge case - immediate throttling
    let config = RateLimitConfig::new(10.0, 0);
    let mut limiter = RateLimiter::new(config);

    // With 0 burst, no tokens available
    assert!(!limiter.try_acquire());
}

#[test]
fn rate_limiter_handles_high_rps() {
    let config = RateLimitConfig::new(10000.0, 1000);
    let mut limiter = RateLimiter::new(config);

    // Should handle high RPS
    for _ in 0..1000 {
        assert!(limiter.try_acquire());
    }
}

#[test]
fn rate_limiter_handles_low_rps() {
    let config = RateLimitConfig::new(0.001, 1); // 1 request per 1000 seconds
    let mut limiter = RateLimiter::new(config);

    // First request succeeds
    assert!(limiter.try_acquire());

    // Second fails (would need to wait ~1000s)
    assert!(!limiter.try_acquire());
}
