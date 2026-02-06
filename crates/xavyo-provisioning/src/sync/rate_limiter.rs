//! Rate limiting for sync operations.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Token bucket rate limiter.
pub struct TokenBucket {
    /// Maximum tokens in the bucket.
    capacity: u64,
    /// Current number of tokens.
    tokens: AtomicU64,
    /// Tokens to add per refill.
    refill_rate: u64,
    /// Refill interval.
    refill_interval: Duration,
    /// Last refill time.
    last_refill: Mutex<Instant>,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum tokens in the bucket
    /// * `refill_rate` - Tokens to add per refill
    /// * `refill_interval` - How often to refill
    #[must_use]
    pub fn new(capacity: u64, refill_rate: u64, refill_interval: Duration) -> Self {
        Self {
            capacity,
            tokens: AtomicU64::new(capacity),
            refill_rate,
            refill_interval,
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Create a rate limiter for N requests per minute.
    #[must_use]
    pub fn per_minute(requests_per_minute: u64) -> Self {
        // Refill every second with 1/60th of the rate
        let refill_rate = requests_per_minute.div_ceil(60);
        Self::new(requests_per_minute, refill_rate, Duration::from_secs(1))
    }

    /// Try to acquire a token.
    ///
    /// Returns true if a token was acquired, false if rate limited.
    pub async fn try_acquire(&self) -> bool {
        self.try_acquire_many(1).await
    }

    /// Try to acquire multiple tokens.
    pub async fn try_acquire_many(&self, count: u64) -> bool {
        self.refill().await;

        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current < count {
                return false;
            }
            if self
                .tokens
                .compare_exchange(
                    current,
                    current - count,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Acquire a token, waiting if necessary.
    pub async fn acquire(&self) {
        self.acquire_many(1).await;
    }

    /// Acquire multiple tokens, waiting if necessary.
    pub async fn acquire_many(&self, count: u64) {
        while !self.try_acquire_many(count).await {
            tokio::time::sleep(self.refill_interval / 10).await;
        }
    }

    /// Get the current number of available tokens.
    pub fn available(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }

    /// Check if rate limited (no tokens available).
    pub fn is_limited(&self) -> bool {
        self.available() == 0
    }

    /// Refill tokens based on elapsed time.
    async fn refill(&self) {
        let mut last_refill = self.last_refill.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill);

        if elapsed >= self.refill_interval {
            let intervals = elapsed.as_secs_f64() / self.refill_interval.as_secs_f64();
            let new_tokens = (intervals as u64) * self.refill_rate;

            if new_tokens > 0 {
                loop {
                    let current = self.tokens.load(Ordering::Relaxed);
                    let new_count = (current + new_tokens).min(self.capacity);
                    if self
                        .tokens
                        .compare_exchange(current, new_count, Ordering::SeqCst, Ordering::Relaxed)
                        .is_ok()
                    {
                        break;
                    }
                }
                *last_refill = now;
            }
        }
    }
}

/// Rate limiter that can track multiple resources.
pub struct RateLimiter {
    /// Default bucket for general operations.
    default_bucket: TokenBucket,
}

impl RateLimiter {
    /// Create a new rate limiter.
    #[must_use]
    pub fn new(requests_per_minute: u64) -> Self {
        Self {
            default_bucket: TokenBucket::per_minute(requests_per_minute),
        }
    }

    /// Try to acquire a token.
    pub async fn try_acquire(&self) -> bool {
        self.default_bucket.try_acquire().await
    }

    /// Acquire a token, waiting if necessary.
    pub async fn acquire(&self) {
        self.default_bucket.acquire().await;
    }

    /// Check if rate limited.
    pub fn is_limited(&self) -> bool {
        self.default_bucket.is_limited()
    }

    /// Get available tokens.
    pub fn available(&self) -> u64 {
        self.default_bucket.available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(10, 1, Duration::from_millis(100));

        // Should be able to acquire 10 tokens initially
        for _ in 0..10 {
            assert!(bucket.try_acquire().await);
        }

        // Should be rate limited now
        assert!(!bucket.try_acquire().await);
        assert!(bucket.is_limited());
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(5, 5, Duration::from_millis(50));

        // Consume all tokens
        for _ in 0..5 {
            assert!(bucket.try_acquire().await);
        }
        assert!(bucket.is_limited());

        // Wait for refill
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Should have tokens again
        assert!(bucket.try_acquire().await);
    }

    #[tokio::test]
    async fn test_token_bucket_many() {
        let bucket = TokenBucket::new(10, 1, Duration::from_secs(1));

        // Acquire 5 at once
        assert!(bucket.try_acquire_many(5).await);
        assert_eq!(bucket.available(), 5);

        // Can't acquire 6 more
        assert!(!bucket.try_acquire_many(6).await);

        // Can acquire 5 more
        assert!(bucket.try_acquire_many(5).await);
        assert_eq!(bucket.available(), 0);
    }

    #[tokio::test]
    async fn test_per_minute() {
        let bucket = TokenBucket::per_minute(60);
        assert_eq!(bucket.capacity, 60);
        assert_eq!(bucket.refill_rate, 1);
        assert_eq!(bucket.refill_interval, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(10);

        for _ in 0..10 {
            assert!(limiter.try_acquire().await);
        }
        assert!(limiter.is_limited());
    }
}
