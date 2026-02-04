//! Rate limiting and retry logic for REST connector.
//!
//! This module provides:
//! - Per-endpoint rate limiting with configurable limits
//! - Exponential backoff retry logic with jitter
//! - Request queuing when rate limited
//! - Logging verbosity control

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, trace, warn};

/// Configuration for rate limiting behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Maximum requests per second (default: 10).
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,

    /// Maximum concurrent requests (default: 5).
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,

    /// Maximum queue depth when rate limited (default: 100).
    #[serde(default = "default_max_queue_depth")]
    pub max_queue_depth: u32,

    /// Per-endpoint rate limit overrides.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub endpoint_limits: HashMap<String, EndpointRateLimit>,
}

fn default_enabled() -> bool {
    true
}

fn default_requests_per_second() -> u32 {
    10
}

fn default_max_concurrent() -> u32 {
    5
}

fn default_max_queue_depth() -> u32 {
    100
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            requests_per_second: default_requests_per_second(),
            max_concurrent: default_max_concurrent(),
            max_queue_depth: default_max_queue_depth(),
            endpoint_limits: HashMap::new(),
        }
    }
}

impl RateLimitConfig {
    /// Create a new rate limit config with custom RPS.
    #[must_use] 
    pub fn new(requests_per_second: u32) -> Self {
        Self {
            requests_per_second,
            ..Default::default()
        }
    }

    /// Disable rate limiting.
    #[must_use] 
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Set max concurrent requests.
    #[must_use] 
    pub fn with_max_concurrent(mut self, max: u32) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Add endpoint-specific rate limit.
    pub fn with_endpoint_limit(
        mut self,
        endpoint: impl Into<String>,
        limit: EndpointRateLimit,
    ) -> Self {
        self.endpoint_limits.insert(endpoint.into(), limit);
        self
    }
}

/// Per-endpoint rate limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRateLimit {
    /// Maximum requests per second for this endpoint.
    pub requests_per_second: u32,

    /// Maximum concurrent requests for this endpoint.
    #[serde(default = "default_endpoint_concurrent")]
    pub max_concurrent: u32,
}

fn default_endpoint_concurrent() -> u32 {
    3
}

impl EndpointRateLimit {
    /// Create a new endpoint rate limit.
    #[must_use] 
    pub fn new(requests_per_second: u32) -> Self {
        Self {
            requests_per_second,
            max_concurrent: default_endpoint_concurrent(),
        }
    }

    /// Set max concurrent for this endpoint.
    #[must_use] 
    pub fn with_max_concurrent(mut self, max: u32) -> Self {
        self.max_concurrent = max;
        self
    }
}

/// Configuration for retry behavior with exponential backoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (default: 3).
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Initial backoff delay in milliseconds (default: 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,

    /// Maximum backoff delay in milliseconds (default: 30000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,

    /// Backoff multiplier (default: 2.0).
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,

    /// Whether to add jitter to backoff (default: true).
    #[serde(default = "default_use_jitter")]
    pub use_jitter: bool,

    /// HTTP status codes that should trigger a retry.
    #[serde(default = "default_retry_status_codes")]
    pub retry_status_codes: Vec<u16>,
}

fn default_max_retries() -> u32 {
    3
}

fn default_initial_backoff_ms() -> u64 {
    100
}

fn default_max_backoff_ms() -> u64 {
    30000
}

fn default_backoff_multiplier() -> f64 {
    2.0
}

fn default_use_jitter() -> bool {
    true
}

fn default_retry_status_codes() -> Vec<u16> {
    vec![429, 502, 503, 504]
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            backoff_multiplier: default_backoff_multiplier(),
            use_jitter: default_use_jitter(),
            retry_status_codes: default_retry_status_codes(),
        }
    }
}

impl RetryConfig {
    /// Create a new retry config with custom max retries.
    #[must_use] 
    pub fn new(max_retries: u32) -> Self {
        Self {
            max_retries,
            ..Default::default()
        }
    }

    /// Disable retries.
    #[must_use] 
    pub fn disabled() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Set initial backoff.
    #[must_use] 
    pub fn with_initial_backoff(mut self, ms: u64) -> Self {
        self.initial_backoff_ms = ms;
        self
    }

    /// Set max backoff.
    #[must_use] 
    pub fn with_max_backoff(mut self, ms: u64) -> Self {
        self.max_backoff_ms = ms;
        self
    }

    /// Calculate backoff duration for a given attempt.
    #[must_use] 
    pub fn calculate_backoff(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_millis(0);
        }

        let base =
            self.initial_backoff_ms as f64 * self.backoff_multiplier.powi(attempt as i32 - 1);
        let capped = base.min(self.max_backoff_ms as f64);

        let delay_ms = if self.use_jitter {
            // Add up to 25% jitter
            let jitter_range = capped * 0.25;
            let jitter = (rand_simple() * jitter_range * 2.0) - jitter_range;
            (capped + jitter).max(0.0)
        } else {
            capped
        };

        Duration::from_millis(delay_ms as u64)
    }

    /// Check if a status code should trigger a retry.
    #[must_use] 
    pub fn should_retry(&self, status_code: u16) -> bool {
        self.retry_status_codes.contains(&status_code)
    }
}

/// Simple pseudo-random number generator for jitter.
/// Returns a value between 0.0 and 1.0.
fn rand_simple() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (f64::from(nanos) / f64::from(u32::MAX)).fract()
}

/// Logging verbosity level for request/response logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogVerbosity {
    /// No request/response logging.
    Quiet,
    /// Log request URL and status code only (default).
    #[default]
    Normal,
    /// Log request/response headers.
    Verbose,
    /// Log request/response headers and bodies.
    Debug,
}

impl LogVerbosity {
    /// Check if headers should be logged.
    #[must_use] 
    pub fn log_headers(&self) -> bool {
        matches!(self, LogVerbosity::Verbose | LogVerbosity::Debug)
    }

    /// Check if bodies should be logged.
    #[must_use] 
    pub fn log_bodies(&self) -> bool {
        matches!(self, LogVerbosity::Debug)
    }

    /// Check if any logging should occur.
    #[must_use] 
    pub fn is_enabled(&self) -> bool {
        !matches!(self, LogVerbosity::Quiet)
    }
}

/// Rate limiter with token bucket algorithm and request queuing.
pub struct RateLimiter {
    /// Configuration.
    config: RateLimitConfig,

    /// Global concurrency semaphore.
    global_semaphore: Arc<Semaphore>,

    /// Per-endpoint state.
    endpoint_state: Arc<Mutex<HashMap<String, EndpointState>>>,

    /// Global token bucket state.
    global_tokens: Arc<Mutex<TokenBucket>>,
}

/// State tracking for a specific endpoint.
struct EndpointState {
    /// Concurrency semaphore for this endpoint.
    semaphore: Arc<Semaphore>,

    /// Token bucket for this endpoint.
    tokens: TokenBucket,

    /// Queue depth counter.
    queued: u32,
}

/// Token bucket for rate limiting.
struct TokenBucket {
    /// Available tokens.
    tokens: f64,

    /// Maximum tokens (bucket size).
    max_tokens: f64,

    /// Refill rate (tokens per second).
    refill_rate: f64,

    /// Last refill timestamp.
    last_refill: Instant,
}

impl TokenBucket {
    fn new(tokens_per_second: u32) -> Self {
        Self {
            tokens: f64::from(tokens_per_second),
            max_tokens: f64::from(tokens_per_second),
            refill_rate: f64::from(tokens_per_second),
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = elapsed.as_secs_f64() * self.refill_rate;
        self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Try to acquire a token. Returns wait time if not available.
    fn try_acquire(&mut self) -> Result<(), Duration> {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate wait time until a token is available
            let tokens_needed = 1.0 - self.tokens;
            let wait_secs = tokens_needed / self.refill_rate;
            Err(Duration::from_secs_f64(wait_secs))
        }
    }
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    #[must_use] 
    pub fn new(config: RateLimitConfig) -> Self {
        let global_semaphore = Arc::new(Semaphore::new(config.max_concurrent as usize));
        let global_tokens = Arc::new(Mutex::new(TokenBucket::new(config.requests_per_second)));

        Self {
            config,
            global_semaphore,
            endpoint_state: Arc::new(Mutex::new(HashMap::new())),
            global_tokens,
        }
    }

    /// Acquire permission to make a request to an endpoint.
    ///
    /// This method handles:
    /// 1. Concurrency limiting (via semaphores)
    /// 2. Rate limiting (via token bucket)
    /// 3. Request queuing when rate limited
    ///
    /// Returns a guard that releases the permit when dropped.
    pub async fn acquire(&self, endpoint: &str) -> Result<RateLimitGuard, RateLimitError> {
        if !self.config.enabled {
            return Ok(RateLimitGuard::noop());
        }

        // Check queue depth
        {
            let state = self.endpoint_state.lock().await;
            if let Some(ep_state) = state.get(endpoint) {
                if ep_state.queued >= self.config.max_queue_depth {
                    warn!(
                        endpoint = %endpoint,
                        queue_depth = ep_state.queued,
                        max_depth = self.config.max_queue_depth,
                        "Rate limit queue full"
                    );
                    return Err(RateLimitError::QueueFull);
                }
            }
        }

        // Increment queue counter
        self.increment_queued(endpoint).await;

        // Get endpoint-specific limits or use global
        let (rps, max_concurrent) = self.get_endpoint_limits(endpoint);

        // First, acquire concurrency permit
        let permit = if let Some(ep_limit) = self.config.endpoint_limits.get(endpoint) {
            // Use endpoint-specific semaphore
            let semaphore = self
                .get_or_create_endpoint_semaphore(endpoint, ep_limit.max_concurrent)
                .await;
            semaphore
                .acquire_owned()
                .await
                .map_err(|_| RateLimitError::SemaphoreClosed)?
        } else {
            // Use global semaphore
            self.global_semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| RateLimitError::SemaphoreClosed)?
        };

        // Then, wait for rate limit token
        loop {
            let wait_time: Option<Duration> = if self.config.endpoint_limits.contains_key(endpoint)
            {
                let mut state = self.endpoint_state.lock().await;
                let ep_state = state
                    .entry(endpoint.to_string())
                    .or_insert_with(|| EndpointState {
                        semaphore: Arc::new(Semaphore::new(max_concurrent as usize)),
                        tokens: TokenBucket::new(rps),
                        queued: 0,
                    });
                ep_state.tokens.try_acquire().err()
            } else {
                let mut global = self.global_tokens.lock().await;
                global.try_acquire().err()
            };

            match wait_time {
                None => {
                    // Token acquired
                    self.decrement_queued(endpoint).await;
                    trace!(endpoint = %endpoint, "Rate limit token acquired");
                    return Ok(RateLimitGuard::with_permit(permit));
                }
                Some(wait) => {
                    debug!(
                        endpoint = %endpoint,
                        wait_ms = wait.as_millis(),
                        "Rate limited, waiting for token"
                    );
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    /// Get rate limits for an endpoint.
    fn get_endpoint_limits(&self, endpoint: &str) -> (u32, u32) {
        if let Some(ep_limit) = self.config.endpoint_limits.get(endpoint) {
            (ep_limit.requests_per_second, ep_limit.max_concurrent)
        } else {
            (self.config.requests_per_second, self.config.max_concurrent)
        }
    }

    /// Get or create endpoint-specific semaphore.
    async fn get_or_create_endpoint_semaphore(
        &self,
        endpoint: &str,
        max_concurrent: u32,
    ) -> Arc<Semaphore> {
        let mut state = self.endpoint_state.lock().await;
        let ep_state = state.entry(endpoint.to_string()).or_insert_with(|| {
            let (rps, _) = self.get_endpoint_limits(endpoint);
            EndpointState {
                semaphore: Arc::new(Semaphore::new(max_concurrent as usize)),
                tokens: TokenBucket::new(rps),
                queued: 0,
            }
        });
        ep_state.semaphore.clone()
    }

    /// Increment queued counter for an endpoint.
    async fn increment_queued(&self, endpoint: &str) {
        let mut state = self.endpoint_state.lock().await;
        let ep_state = state.entry(endpoint.to_string()).or_insert_with(|| {
            let (rps, max_concurrent) = self.get_endpoint_limits(endpoint);
            EndpointState {
                semaphore: Arc::new(Semaphore::new(max_concurrent as usize)),
                tokens: TokenBucket::new(rps),
                queued: 0,
            }
        });
        ep_state.queued = ep_state.queued.saturating_add(1);
    }

    /// Decrement queued counter for an endpoint.
    async fn decrement_queued(&self, endpoint: &str) {
        let mut state = self.endpoint_state.lock().await;
        if let Some(ep_state) = state.get_mut(endpoint) {
            ep_state.queued = ep_state.queued.saturating_sub(1);
        }
    }

    /// Handle a rate limit response (429) with Retry-After header.
    pub async fn handle_rate_limit_response(&self, retry_after: Option<Duration>) {
        let wait = retry_after.unwrap_or(Duration::from_secs(1));
        info!(
            wait_secs = wait.as_secs_f64(),
            "Received rate limit response, backing off"
        );
        tokio::time::sleep(wait).await;
    }

    /// Get current statistics.
    pub async fn stats(&self) -> RateLimitStats {
        let state = self.endpoint_state.lock().await;
        let endpoint_stats: HashMap<String, EndpointStats> = state
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    EndpointStats {
                        queued: v.queued,
                        available_tokens: v.tokens.tokens as u32,
                    },
                )
            })
            .collect();

        let global_tokens = self.global_tokens.lock().await;
        RateLimitStats {
            global_available_tokens: global_tokens.tokens as u32,
            global_available_permits: self.global_semaphore.available_permits() as u32,
            endpoints: endpoint_stats,
        }
    }
}

/// Guard returned when rate limit permit is acquired.
/// Releases the permit when dropped.
pub struct RateLimitGuard {
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl RateLimitGuard {
    fn noop() -> Self {
        Self { _permit: None }
    }

    fn with_permit(permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self {
            _permit: Some(permit),
        }
    }
}

/// Rate limiter statistics.
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    /// Global available tokens.
    pub global_available_tokens: u32,

    /// Global available concurrency permits.
    pub global_available_permits: u32,

    /// Per-endpoint statistics.
    pub endpoints: HashMap<String, EndpointStats>,
}

/// Per-endpoint statistics.
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// Number of requests currently queued.
    pub queued: u32,

    /// Available tokens in bucket.
    pub available_tokens: u32,
}

/// Rate limiter errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    /// Request queue is full.
    QueueFull,

    /// Semaphore was closed.
    SemaphoreClosed,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::QueueFull => write!(f, "Rate limit queue is full"),
            RateLimitError::SemaphoreClosed => write!(f, "Rate limiter semaphore was closed"),
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Parse Retry-After header value.
///
/// Supports both delay-seconds format (e.g., "120") and
/// HTTP-date format (e.g., "Wed, 21 Oct 2015 07:28:00 GMT").
#[must_use] 
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    // Try parsing as seconds first
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    // Try parsing as HTTP date (simplified - just support a few formats)
    // In production, you'd want to use a proper date parsing library
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // RateLimitConfig Tests
    // ==========================================================================

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert!(config.enabled);
        assert_eq!(config.requests_per_second, 10);
        assert_eq!(config.max_concurrent, 5);
        assert_eq!(config.max_queue_depth, 100);
        assert!(config.endpoint_limits.is_empty());
    }

    #[test]
    fn test_rate_limit_config_disabled() {
        let config = RateLimitConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_rate_limit_config_new() {
        let config = RateLimitConfig::new(20);
        assert_eq!(config.requests_per_second, 20);
        assert!(config.enabled);
    }

    #[test]
    fn test_rate_limit_config_with_max_concurrent() {
        let config = RateLimitConfig::default().with_max_concurrent(10);
        assert_eq!(config.max_concurrent, 10);
    }

    #[test]
    fn test_rate_limit_config_with_endpoint_limit() {
        let config =
            RateLimitConfig::default().with_endpoint_limit("/users", EndpointRateLimit::new(5));

        assert!(config.endpoint_limits.contains_key("/users"));
        assert_eq!(config.endpoint_limits["/users"].requests_per_second, 5);
    }

    // ==========================================================================
    // EndpointRateLimit Tests
    // ==========================================================================

    #[test]
    fn test_endpoint_rate_limit_new() {
        let limit = EndpointRateLimit::new(15);
        assert_eq!(limit.requests_per_second, 15);
        assert_eq!(limit.max_concurrent, 3); // default
    }

    #[test]
    fn test_endpoint_rate_limit_with_max_concurrent() {
        let limit = EndpointRateLimit::new(15).with_max_concurrent(7);
        assert_eq!(limit.max_concurrent, 7);
    }

    // ==========================================================================
    // RetryConfig Tests
    // ==========================================================================

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff_ms, 100);
        assert_eq!(config.max_backoff_ms, 30000);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert!(config.use_jitter);
        assert!(config.retry_status_codes.contains(&429));
        assert!(config.retry_status_codes.contains(&502));
        assert!(config.retry_status_codes.contains(&503));
        assert!(config.retry_status_codes.contains(&504));
    }

    #[test]
    fn test_retry_config_disabled() {
        let config = RetryConfig::disabled();
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_retry_config_new() {
        let config = RetryConfig::new(5);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_retry_config_with_initial_backoff() {
        let config = RetryConfig::default().with_initial_backoff(200);
        assert_eq!(config.initial_backoff_ms, 200);
    }

    #[test]
    fn test_retry_config_with_max_backoff() {
        let config = RetryConfig::default().with_max_backoff(60000);
        assert_eq!(config.max_backoff_ms, 60000);
    }

    #[test]
    fn test_retry_config_calculate_backoff_attempt_0() {
        let config = RetryConfig::default();
        let backoff = config.calculate_backoff(0);
        assert_eq!(backoff, Duration::from_millis(0));
    }

    #[test]
    fn test_retry_config_calculate_backoff_no_jitter() {
        let config = RetryConfig {
            use_jitter: false,
            initial_backoff_ms: 100,
            backoff_multiplier: 2.0,
            max_backoff_ms: 30000,
            ..Default::default()
        };

        assert_eq!(config.calculate_backoff(1), Duration::from_millis(100));
        assert_eq!(config.calculate_backoff(2), Duration::from_millis(200));
        assert_eq!(config.calculate_backoff(3), Duration::from_millis(400));
        assert_eq!(config.calculate_backoff(4), Duration::from_millis(800));
    }

    #[test]
    fn test_retry_config_calculate_backoff_capped() {
        let config = RetryConfig {
            use_jitter: false,
            initial_backoff_ms: 1000,
            backoff_multiplier: 10.0,
            max_backoff_ms: 5000,
            ..Default::default()
        };

        // 1st attempt: 1000ms
        assert_eq!(config.calculate_backoff(1), Duration::from_millis(1000));
        // 2nd attempt: 10000ms -> capped to 5000ms
        assert_eq!(config.calculate_backoff(2), Duration::from_millis(5000));
    }

    #[test]
    fn test_retry_config_calculate_backoff_with_jitter() {
        let config = RetryConfig::default(); // jitter enabled

        // With jitter, result should be within 25% of expected value
        let backoff = config.calculate_backoff(1);
        let expected = 100.0;
        let min = expected * 0.75;
        let max = expected * 1.25;

        assert!(
            backoff.as_millis() >= min as u128 && backoff.as_millis() <= max as u128,
            "Backoff {} should be between {} and {}",
            backoff.as_millis(),
            min,
            max
        );
    }

    #[test]
    fn test_retry_config_should_retry() {
        let config = RetryConfig::default();

        assert!(config.should_retry(429)); // Too Many Requests
        assert!(config.should_retry(502)); // Bad Gateway
        assert!(config.should_retry(503)); // Service Unavailable
        assert!(config.should_retry(504)); // Gateway Timeout

        assert!(!config.should_retry(200)); // OK
        assert!(!config.should_retry(400)); // Bad Request
        assert!(!config.should_retry(401)); // Unauthorized
        assert!(!config.should_retry(404)); // Not Found
        assert!(!config.should_retry(500)); // Internal Server Error
    }

    // ==========================================================================
    // LogVerbosity Tests
    // ==========================================================================

    #[test]
    fn test_log_verbosity_default() {
        let verbosity = LogVerbosity::default();
        assert_eq!(verbosity, LogVerbosity::Normal);
    }

    #[test]
    fn test_log_verbosity_quiet() {
        let verbosity = LogVerbosity::Quiet;
        assert!(!verbosity.is_enabled());
        assert!(!verbosity.log_headers());
        assert!(!verbosity.log_bodies());
    }

    #[test]
    fn test_log_verbosity_normal() {
        let verbosity = LogVerbosity::Normal;
        assert!(verbosity.is_enabled());
        assert!(!verbosity.log_headers());
        assert!(!verbosity.log_bodies());
    }

    #[test]
    fn test_log_verbosity_verbose() {
        let verbosity = LogVerbosity::Verbose;
        assert!(verbosity.is_enabled());
        assert!(verbosity.log_headers());
        assert!(!verbosity.log_bodies());
    }

    #[test]
    fn test_log_verbosity_debug() {
        let verbosity = LogVerbosity::Debug;
        assert!(verbosity.is_enabled());
        assert!(verbosity.log_headers());
        assert!(verbosity.log_bodies());
    }

    // ==========================================================================
    // TokenBucket Tests
    // ==========================================================================

    #[test]
    fn test_token_bucket_new() {
        let bucket = TokenBucket::new(10);
        assert_eq!(bucket.max_tokens, 10.0);
        assert_eq!(bucket.refill_rate, 10.0);
        assert_eq!(bucket.tokens, 10.0);
    }

    #[test]
    fn test_token_bucket_try_acquire_success() {
        let mut bucket = TokenBucket::new(10);
        assert!(bucket.try_acquire().is_ok());
        // Should have consumed one token
        assert!(bucket.tokens < 10.0);
    }

    #[test]
    fn test_token_bucket_try_acquire_depleted() {
        let mut bucket = TokenBucket::new(1);

        // First acquire should succeed
        assert!(bucket.try_acquire().is_ok());

        // Second acquire should fail (no tokens left)
        let result = bucket.try_acquire();
        assert!(result.is_err());

        // Should return wait time
        let wait = result.unwrap_err();
        assert!(wait.as_millis() > 0);
    }

    // ==========================================================================
    // RateLimiter Tests
    // ==========================================================================

    #[tokio::test]
    async fn test_rate_limiter_new() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);

        let stats = limiter.stats().await;
        assert_eq!(stats.global_available_permits, 5);
        assert!(stats.endpoints.is_empty());
    }

    #[tokio::test]
    async fn test_rate_limiter_disabled() {
        let config = RateLimitConfig::disabled();
        let limiter = RateLimiter::new(config);

        // Should immediately return when disabled
        let guard = limiter.acquire("/test").await;
        assert!(guard.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_acquire_success() {
        let config = RateLimitConfig::new(100); // High RPS for test
        let limiter = RateLimiter::new(config);

        let guard = limiter.acquire("/users").await;
        assert!(guard.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_acquire_multiple() {
        let config = RateLimitConfig::new(100).with_max_concurrent(10);
        let limiter = RateLimiter::new(config);

        // Acquire multiple permits
        let mut guards = Vec::new();
        for _ in 0..5 {
            let guard = limiter.acquire("/test").await;
            assert!(guard.is_ok());
            guards.push(guard.unwrap());
        }

        // Check stats
        let stats = limiter.stats().await;
        assert_eq!(stats.global_available_permits, 5); // 10 - 5 = 5
    }

    #[tokio::test]
    async fn test_rate_limiter_release_on_drop() {
        let config = RateLimitConfig::new(100).with_max_concurrent(2);
        let limiter = RateLimiter::new(config);

        // Acquire all permits
        let guard1 = limiter.acquire("/test").await.unwrap();
        let guard2 = limiter.acquire("/test").await.unwrap();

        let stats = limiter.stats().await;
        assert_eq!(stats.global_available_permits, 0);

        // Drop one guard
        drop(guard1);

        // Permit should be released
        let stats = limiter.stats().await;
        assert_eq!(stats.global_available_permits, 1);

        drop(guard2);
    }

    #[tokio::test]
    async fn test_rate_limiter_endpoint_limits() {
        let config = RateLimitConfig::default()
            .with_endpoint_limit("/slow", EndpointRateLimit::new(1).with_max_concurrent(1));
        let limiter = RateLimiter::new(config);

        // Acquire permit for slow endpoint
        let _guard = limiter.acquire("/slow").await.unwrap();

        // Stats should show endpoint-specific tracking
        let stats = limiter.stats().await;
        assert!(stats.endpoints.contains_key("/slow"));
    }

    // ==========================================================================
    // parse_retry_after Tests
    // ==========================================================================

    #[test]
    fn test_parse_retry_after_seconds() {
        assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after("0"), Some(Duration::from_secs(0)));
        assert_eq!(parse_retry_after("3600"), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_parse_retry_after_invalid() {
        assert_eq!(parse_retry_after("invalid"), None);
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("-1"), None);
    }

    // ==========================================================================
    // RateLimitError Tests
    // ==========================================================================

    #[test]
    fn test_rate_limit_error_display() {
        assert_eq!(
            RateLimitError::QueueFull.to_string(),
            "Rate limit queue is full"
        );
        assert_eq!(
            RateLimitError::SemaphoreClosed.to_string(),
            "Rate limiter semaphore was closed"
        );
    }

    // ==========================================================================
    // Serialization Tests
    // ==========================================================================

    #[test]
    fn test_rate_limit_config_serialization() {
        let config = RateLimitConfig::new(20)
            .with_max_concurrent(10)
            .with_endpoint_limit("/api", EndpointRateLimit::new(5));

        let json = serde_json::to_string(&config).unwrap();
        let parsed: RateLimitConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.requests_per_second, 20);
        assert_eq!(parsed.max_concurrent, 10);
        assert!(parsed.endpoint_limits.contains_key("/api"));
    }

    #[test]
    fn test_retry_config_serialization() {
        let config = RetryConfig::new(5)
            .with_initial_backoff(200)
            .with_max_backoff(60000);

        let json = serde_json::to_string(&config).unwrap();
        let parsed: RetryConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.max_retries, 5);
        assert_eq!(parsed.initial_backoff_ms, 200);
        assert_eq!(parsed.max_backoff_ms, 60000);
    }

    #[test]
    fn test_log_verbosity_serialization() {
        let verbosity = LogVerbosity::Verbose;
        let json = serde_json::to_string(&verbosity).unwrap();
        assert_eq!(json, "\"verbose\"");

        let parsed: LogVerbosity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, LogVerbosity::Verbose);
    }
}
