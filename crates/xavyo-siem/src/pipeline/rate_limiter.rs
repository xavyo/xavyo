//! Per-destination rate limiting using token bucket algorithm.

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::num::NonZeroU32;

/// Rate limiter for a single SIEM destination.
pub struct DestinationRateLimiter {
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    rate_per_second: u32,
}

impl DestinationRateLimiter {
    /// Create a new rate limiter with the specified events per second.
    /// Burst capacity is 2x the rate.
    #[must_use] 
    pub fn new(rate_per_second: u32) -> Self {
        let rate = NonZeroU32::new(rate_per_second).unwrap_or(NonZeroU32::new(1000).unwrap());
        let burst = NonZeroU32::new(rate_per_second.saturating_mul(2).max(1))
            .unwrap_or(NonZeroU32::new(2000).unwrap());

        let quota = Quota::per_second(rate).allow_burst(burst);
        let limiter = RateLimiter::direct(quota);

        Self {
            limiter,
            rate_per_second,
        }
    }

    /// Check if an event can be sent (non-blocking).
    /// Returns Ok(()) if allowed, Err if rate-limited.
    #[allow(clippy::result_unit_err)]
    pub fn check(&self) -> Result<(), ()> {
        self.limiter.check().map_err(|_| ())
    }

    /// Wait until the rate limiter allows sending (blocking async).
    pub async fn wait(&self) {
        self.limiter.until_ready().await;
    }

    /// Get the configured rate per second.
    pub fn rate_per_second(&self) -> u32 {
        self.rate_per_second
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = DestinationRateLimiter::new(1000);
        assert_eq!(limiter.rate_per_second(), 1000);
    }

    #[test]
    fn test_rate_limiter_allows_within_burst() {
        let limiter = DestinationRateLimiter::new(100);
        // Should allow initial burst of 200 (2x rate)
        for _ in 0..200 {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_when_exceeded() {
        let limiter = DestinationRateLimiter::new(1);
        // First check should succeed (burst of 2)
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        // Third should be rate-limited
        assert!(limiter.check().is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_wait() {
        let limiter = DestinationRateLimiter::new(1000);
        // Should complete nearly instantly within burst
        limiter.wait().await;
    }
}
