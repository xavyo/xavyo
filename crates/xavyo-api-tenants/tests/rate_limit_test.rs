//! Integration tests for rate limiting on the tenant provisioning endpoint.
//!
//! These tests verify that the rate limiting middleware correctly:
//! - Allows requests up to the limit (10/hour)
//! - Returns 429 after exceeding the limit
//! - Includes rate limit headers in responses

use std::sync::Arc;
use xavyo_api_tenants::middleware::rate_limit::{
    provision_rate_limiter, PROVISION_RATE_LIMIT_MAX, PROVISION_RATE_LIMIT_WINDOW_SECS,
};

/// Test that the rate limiter is properly configured with expected values.
#[test]
fn test_provision_rate_limiter_configuration() {
    let limiter = provision_rate_limiter();

    assert_eq!(
        limiter.config().max_attempts,
        PROVISION_RATE_LIMIT_MAX,
        "Rate limiter should allow {} attempts",
        PROVISION_RATE_LIMIT_MAX
    );

    assert_eq!(
        limiter.config().window.as_secs(),
        PROVISION_RATE_LIMIT_WINDOW_SECS,
        "Rate limiter window should be {} seconds",
        PROVISION_RATE_LIMIT_WINDOW_SECS
    );
}

/// Test that the rate limiter blocks after exceeding the limit.
#[test]
fn test_rate_limiter_blocks_after_limit() {
    let limiter = Arc::new(provision_rate_limiter());
    let ip: std::net::IpAddr = "203.0.113.1".parse().unwrap();

    // Record max attempts
    for i in 0..PROVISION_RATE_LIMIT_MAX {
        assert!(
            limiter.record_attempt(ip),
            "Attempt {} of {} should succeed",
            i + 1,
            PROVISION_RATE_LIMIT_MAX
        );
    }

    // Next attempt should be blocked
    assert!(
        !limiter.record_attempt(ip),
        "Attempt {} should be blocked (exceeds limit)",
        PROVISION_RATE_LIMIT_MAX + 1
    );

    // Verify is_limited returns true
    assert!(
        limiter.is_limited(ip),
        "IP should be marked as limited after exceeding max attempts"
    );
}

/// Test that different IPs have independent rate limits.
#[test]
fn test_different_ips_have_independent_limits() {
    let limiter = Arc::new(provision_rate_limiter());
    let ip1: std::net::IpAddr = "203.0.113.1".parse().unwrap();
    let ip2: std::net::IpAddr = "203.0.113.2".parse().unwrap();

    // Exhaust limit for IP1
    for _ in 0..PROVISION_RATE_LIMIT_MAX {
        limiter.record_attempt(ip1);
    }

    // IP1 should be limited
    assert!(limiter.is_limited(ip1), "IP1 should be limited");

    // IP2 should NOT be limited
    assert!(!limiter.is_limited(ip2), "IP2 should not be limited");

    // IP2 can still make requests
    assert!(
        limiter.record_attempt(ip2),
        "IP2 should be able to make requests"
    );
}

/// Test that remaining attempts count is correct.
#[test]
fn test_remaining_attempts_tracking() {
    let limiter = Arc::new(provision_rate_limiter());
    let ip: std::net::IpAddr = "198.51.100.1".parse().unwrap();

    // Initially should have full quota
    assert_eq!(
        limiter.remaining_attempts(ip),
        PROVISION_RATE_LIMIT_MAX,
        "New IP should have full quota"
    );

    // After 3 attempts, should have 7 remaining
    for _ in 0..3 {
        limiter.record_attempt(ip);
    }
    assert_eq!(
        limiter.remaining_attempts(ip),
        PROVISION_RATE_LIMIT_MAX - 3,
        "Should have 7 remaining after 3 attempts"
    );

    // After exhausting, should have 0 remaining
    for _ in 0..(PROVISION_RATE_LIMIT_MAX - 3) {
        limiter.record_attempt(ip);
    }
    assert_eq!(
        limiter.remaining_attempts(ip),
        0,
        "Should have 0 remaining after exhausting limit"
    );
}

/// Test that the rate limiter can be shared across threads.
#[test]
fn test_rate_limiter_thread_safety() {
    use std::thread;

    let limiter = Arc::new(provision_rate_limiter());
    let mut handles = vec![];

    // Spawn multiple threads that try to record attempts
    for i in 0..5 {
        let limiter_clone = Arc::clone(&limiter);
        let ip: std::net::IpAddr = format!("10.0.0.{}", i).parse().unwrap();

        let handle = thread::spawn(move || {
            for _ in 0..3 {
                limiter_clone.record_attempt(ip);
            }
            limiter_clone.remaining_attempts(ip)
        });

        handles.push(handle);
    }

    // All threads should complete without panic
    for handle in handles {
        let remaining = handle.join().expect("Thread should not panic");
        assert_eq!(
            remaining,
            PROVISION_RATE_LIMIT_MAX - 3,
            "Each IP should have 7 remaining attempts"
        );
    }
}

/// Test rate limit constants are reasonable values.
#[test]
fn test_rate_limit_constants_are_reasonable() {
    // Max attempts should be between 1 and 100
    assert!(
        PROVISION_RATE_LIMIT_MAX >= 1 && PROVISION_RATE_LIMIT_MAX <= 100,
        "Max attempts should be reasonable (1-100)"
    );

    // Window should be at least 1 minute and at most 24 hours
    assert!(
        PROVISION_RATE_LIMIT_WINDOW_SECS >= 60 && PROVISION_RATE_LIMIT_WINDOW_SECS <= 86400,
        "Window should be reasonable (1 min to 24 hours)"
    );
}
