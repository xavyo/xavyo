//! Exponential backoff retry logic for delivery failures.

use std::time::Duration;

/// Maximum retry attempts before moving to dead letter.
const MAX_RETRIES: u8 = 7;

/// Maximum backoff duration (cap).
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Base backoff interval.
const BASE_BACKOFF: Duration = Duration::from_secs(1);

/// Retry policy for SIEM event delivery.
pub struct RetryPolicy {
    max_retries: u8,
}

impl RetryPolicy {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            max_retries: MAX_RETRIES,
        }
    }

    #[must_use] 
    pub fn with_max_retries(max_retries: u8) -> Self {
        Self { max_retries }
    }

    /// Check if another retry should be attempted.
    #[must_use] 
    pub fn should_retry(&self, attempt: u8) -> bool {
        attempt < self.max_retries
    }

    /// Check if the event should be moved to dead letter.
    #[must_use] 
    pub fn is_dead_letter(&self, attempt: u8) -> bool {
        attempt >= self.max_retries
    }

    /// Calculate the next retry delay using exponential backoff.
    /// Intervals: 1s, 2s, 4s, 8s, 16s, 32s, 60s (capped)
    #[must_use] 
    pub fn next_delay(&self, attempt: u8) -> Duration {
        let backoff = BASE_BACKOFF
            .checked_mul(2u32.saturating_pow(u32::from(attempt)))
            .unwrap_or(MAX_BACKOFF);
        backoff.min(MAX_BACKOFF)
    }

    /// Get the maximum number of retries.
    #[must_use] 
    pub fn max_retries(&self) -> u8 {
        self.max_retries
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_max_retries() {
        let policy = RetryPolicy::new();
        assert_eq!(policy.max_retries(), 7);
    }

    #[test]
    fn test_should_retry_within_limit() {
        let policy = RetryPolicy::new();
        assert!(policy.should_retry(0));
        assert!(policy.should_retry(1));
        assert!(policy.should_retry(6));
    }

    #[test]
    fn test_should_not_retry_at_limit() {
        let policy = RetryPolicy::new();
        assert!(!policy.should_retry(7));
        assert!(!policy.should_retry(8));
    }

    #[test]
    fn test_dead_letter_at_max_retries() {
        let policy = RetryPolicy::new();
        assert!(!policy.is_dead_letter(0));
        assert!(!policy.is_dead_letter(6));
        assert!(policy.is_dead_letter(7));
        assert!(policy.is_dead_letter(10));
    }

    #[test]
    fn test_exponential_backoff_intervals() {
        let policy = RetryPolicy::new();
        assert_eq!(policy.next_delay(0), Duration::from_secs(1));
        assert_eq!(policy.next_delay(1), Duration::from_secs(2));
        assert_eq!(policy.next_delay(2), Duration::from_secs(4));
        assert_eq!(policy.next_delay(3), Duration::from_secs(8));
        assert_eq!(policy.next_delay(4), Duration::from_secs(16));
        assert_eq!(policy.next_delay(5), Duration::from_secs(32));
        assert_eq!(policy.next_delay(6), Duration::from_secs(60)); // Capped
    }

    #[test]
    fn test_backoff_capped_at_60_seconds() {
        let policy = RetryPolicy::new();
        assert_eq!(policy.next_delay(7), Duration::from_secs(60));
        assert_eq!(policy.next_delay(10), Duration::from_secs(60));
        assert_eq!(policy.next_delay(20), Duration::from_secs(60));
    }

    #[test]
    fn test_custom_max_retries() {
        let policy = RetryPolicy::with_max_retries(3);
        assert!(policy.should_retry(0));
        assert!(policy.should_retry(2));
        assert!(!policy.should_retry(3));
        assert!(policy.is_dead_letter(3));
    }
}
