//! Exponential backoff retry logic for SCIM operations.

use crate::error::{ScimClientError, ScimClientResult};
use std::time::Duration;
use tracing::{debug, warn};

/// Retry policy configuration.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retries).
    pub max_retries: u32,
    /// Base delay in seconds for exponential backoff.
    pub base_delay_secs: u64,
    /// Maximum delay cap in seconds.
    pub max_delay_secs: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_delay_secs: 1,
            max_delay_secs: 60,
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy with the given max retries and base delay.
    /// The maximum delay cap defaults to 60 seconds.
    #[must_use] 
    pub fn new(max_retries: u32, base_delay_secs: u64) -> Self {
        Self {
            max_retries,
            base_delay_secs,
            max_delay_secs: 60,
        }
    }

    /// Whether the error should be retried at the given attempt number.
    ///
    /// Returns `true` if the attempt number is within the configured maximum
    /// and the error is either retryable (network/rate-limit/timeout) or a
    /// server-side 5xx error.
    #[must_use] 
    pub fn should_retry(&self, attempt: u32, error: &ScimClientError) -> bool {
        if attempt >= self.max_retries {
            return false;
        }
        error.is_retryable() || error.is_server_error()
    }

    /// Calculate delay for the given attempt using exponential backoff.
    ///
    /// If the error is [`ScimClientError::RateLimited`] with a `retry_after_secs`
    /// value, that value is used directly (capped at `max_delay_secs`).
    /// Otherwise the delay is `min(base_delay_secs * 2^attempt, max_delay_secs)`.
    #[must_use] 
    pub fn delay_for(&self, attempt: u32, error: &ScimClientError) -> Duration {
        let secs = if let ScimClientError::RateLimited {
                retry_after_secs: Some(retry_after),
            } = error { (*retry_after).min(self.max_delay_secs) } else {
            let exponential = self
                .base_delay_secs
                .saturating_mul(2u64.saturating_pow(attempt));
            exponential.min(self.max_delay_secs)
        };
        Duration::from_secs(secs)
    }

    /// Execute an async operation with retry.
    ///
    /// The closure `f` is called repeatedly until it succeeds, a non-retryable
    /// error is encountered, or the maximum number of retries is exhausted.
    ///
    /// Each retry attempt is logged at `debug` level; the final failure after
    /// exhausting retries is logged at `warn` level.
    pub async fn execute<F, Fut, T>(&self, operation_name: &str, mut f: F) -> ScimClientResult<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ScimClientResult<T>>,
    {
        let mut attempt: u32 = 0;
        loop {
            match f().await {
                Ok(value) => {
                    if attempt > 0 {
                        debug!(
                            operation = operation_name,
                            attempt = attempt + 1,
                            "Operation succeeded after retries"
                        );
                    }
                    return Ok(value);
                }
                Err(error) => {
                    if !self.should_retry(attempt, &error) {
                        if attempt >= self.max_retries {
                            warn!(
                                operation = operation_name,
                                attempts = attempt + 1,
                                error = %error,
                                "Max retries exceeded"
                            );
                            return Err(ScimClientError::MaxRetriesExceeded {
                                attempts: attempt + 1,
                                message: format!(
                                    "{operation_name} failed after {} attempt(s): {error}",
                                    attempt + 1
                                ),
                            });
                        }
                        // Non-retryable error — return immediately.
                        return Err(error);
                    }

                    let delay = self.delay_for(attempt, &error);
                    debug!(
                        operation = operation_name,
                        attempt = attempt + 1,
                        max_retries = self.max_retries,
                        delay_secs = delay.as_secs(),
                        error = %error,
                        "Retrying after transient error"
                    );

                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_default_policy() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 5);
        assert_eq!(policy.base_delay_secs, 1);
        assert_eq!(policy.max_delay_secs, 60);
    }

    #[test]
    fn test_new_policy() {
        let policy = RetryPolicy::new(3, 2);
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.base_delay_secs, 2);
        assert_eq!(policy.max_delay_secs, 60);
    }

    #[test]
    fn test_should_retry_retryable_error() {
        let policy = RetryPolicy::new(3, 1);
        let error = ScimClientError::RateLimited {
            retry_after_secs: None,
        };
        assert!(policy.should_retry(0, &error));
        assert!(policy.should_retry(2, &error));
        assert!(!policy.should_retry(3, &error)); // at max
    }

    #[test]
    fn test_should_retry_server_error() {
        let policy = RetryPolicy::new(3, 1);
        let error = ScimClientError::ScimError {
            status: 503,
            detail: "service unavailable".into(),
        };
        assert!(policy.should_retry(0, &error));
    }

    #[test]
    fn test_should_not_retry_client_error() {
        let policy = RetryPolicy::new(3, 1);

        let not_found = ScimClientError::NotFound("user".into());
        assert!(!policy.should_retry(0, &not_found));

        let scim_400 = ScimClientError::ScimError {
            status: 400,
            detail: "bad request".into(),
        };
        assert!(!policy.should_retry(0, &scim_400));

        let auth = ScimClientError::AuthError("invalid token".into());
        assert!(!policy.should_retry(0, &auth));
    }

    #[test]
    fn test_delay_exponential_backoff() {
        let policy = RetryPolicy::new(5, 1);
        let error = ScimClientError::Unreachable("host".into());

        assert_eq!(policy.delay_for(0, &error), Duration::from_secs(1)); // 1 * 2^0
        assert_eq!(policy.delay_for(1, &error), Duration::from_secs(2)); // 1 * 2^1
        assert_eq!(policy.delay_for(2, &error), Duration::from_secs(4)); // 1 * 2^2
        assert_eq!(policy.delay_for(3, &error), Duration::from_secs(8)); // 1 * 2^3
    }

    #[test]
    fn test_delay_capped_at_max() {
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay_secs: 1,
            max_delay_secs: 10,
        };
        let error = ScimClientError::Unreachable("host".into());

        assert_eq!(policy.delay_for(5, &error), Duration::from_secs(10)); // 32 capped to 10
        assert_eq!(policy.delay_for(8, &error), Duration::from_secs(10)); // 256 capped to 10
    }

    #[test]
    fn test_delay_rate_limited_with_retry_after() {
        let policy = RetryPolicy::new(5, 1);
        let error = ScimClientError::RateLimited {
            retry_after_secs: Some(30),
        };

        assert_eq!(policy.delay_for(0, &error), Duration::from_secs(30));
        assert_eq!(policy.delay_for(3, &error), Duration::from_secs(30));
    }

    #[test]
    fn test_delay_rate_limited_retry_after_capped() {
        let policy = RetryPolicy {
            max_retries: 5,
            base_delay_secs: 1,
            max_delay_secs: 10,
        };
        let error = ScimClientError::RateLimited {
            retry_after_secs: Some(120),
        };

        assert_eq!(policy.delay_for(0, &error), Duration::from_secs(10));
    }

    #[test]
    fn test_delay_rate_limited_without_retry_after() {
        let policy = RetryPolicy::new(5, 2);
        let error = ScimClientError::RateLimited {
            retry_after_secs: None,
        };

        // Falls back to exponential: 2 * 2^1 = 4
        assert_eq!(policy.delay_for(1, &error), Duration::from_secs(4));
    }

    #[tokio::test]
    async fn test_execute_succeeds_first_try() {
        let policy = RetryPolicy::new(3, 0);
        let result = policy
            .execute("test_op", || async { Ok::<_, ScimClientError>(42) })
            .await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_execute_succeeds_after_retries() {
        let policy = RetryPolicy::new(3, 0);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = policy
            .execute("test_op", move || {
                let counter = counter_clone.clone();
                async move {
                    let attempt = counter.fetch_add(1, Ordering::SeqCst);
                    if attempt < 2 {
                        Err(ScimClientError::Unreachable("host".into()))
                    } else {
                        Ok(99)
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), 99);
        assert_eq!(counter.load(Ordering::SeqCst), 3); // initial + 2 retries
    }

    #[tokio::test]
    async fn test_execute_non_retryable_fails_immediately() {
        let policy = RetryPolicy::new(3, 0);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result: ScimClientResult<()> = policy
            .execute("test_op", move || {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err(ScimClientError::NotFound("user".into()))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1); // only one attempt
    }

    #[tokio::test]
    async fn test_execute_max_retries_exceeded() {
        let policy = RetryPolicy::new(2, 0);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result: ScimClientResult<()> = policy
            .execute("test_op", move || {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err(ScimClientError::Unreachable("host".into()))
                }
            })
            .await;

        match result {
            Err(ScimClientError::MaxRetriesExceeded { attempts, .. }) => {
                assert_eq!(attempts, 3); // 1 initial + 2 retries
            }
            other => panic!("Expected MaxRetriesExceeded, got: {other:?}"),
        }
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_no_retries_policy() {
        let policy = RetryPolicy::new(0, 1);
        let error = ScimClientError::Unreachable("host".into());
        assert!(!policy.should_retry(0, &error));
    }
}
