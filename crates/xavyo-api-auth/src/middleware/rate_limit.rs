//! Rate limiting middleware for authentication endpoints.
//!
//! Implements in-memory rate limiting with a sliding window algorithm.
//! Tracks login attempts per IP address to prevent brute-force attacks.
//! Also supports email-based rate limiting for password reset and verification flows.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Default maximum attempts per window.
pub const DEFAULT_MAX_ATTEMPTS: usize = 5;

/// Default window duration in seconds.
pub const DEFAULT_WINDOW_SECS: u64 = 60;

/// Email-based rate limit: max requests per email per hour.
pub const EMAIL_RATE_LIMIT_MAX: usize = 3;

/// Email-based rate limit window in seconds (1 hour).
pub const EMAIL_RATE_LIMIT_WINDOW_SECS: u64 = 3600;

/// IP-based rate limit for email endpoints: max requests per IP per hour.
pub const EMAIL_IP_RATE_LIMIT_MAX: usize = 10;

/// Signup rate limit: max requests per IP per hour (F111).
/// Override with env var `SIGNUP_RATE_LIMIT_MAX`.
pub const SIGNUP_RATE_LIMIT_MAX: usize = 10;

/// Signup rate limit window in seconds (1 hour).
/// Override with env var `SIGNUP_RATE_LIMIT_WINDOW_SECS`.
pub const SIGNUP_RATE_LIMIT_WINDOW_SECS: u64 = 3600;

/// Key type for rate limiting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RateLimitKey {
    /// Rate limit by IP address.
    Ip(IpAddr),
    /// Rate limit by email address.
    Email(String),
    /// Rate limit by combined IP and endpoint.
    IpEndpoint(IpAddr, String),
    /// Rate limit by email and endpoint.
    EmailEndpoint(String, String),
}

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of attempts allowed within the window.
    pub max_attempts: usize,
    /// Duration of the sliding window.
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            window: Duration::from_secs(DEFAULT_WINDOW_SECS),
        }
    }
}

/// Entry tracking attempts from a single IP.
#[derive(Debug, Clone)]
struct AttemptEntry {
    /// Timestamps of attempts within the window.
    timestamps: Vec<Instant>,
}

impl AttemptEntry {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    /// Clean up old attempts and add a new one.
    fn record_attempt(&mut self, now: Instant, window: Duration) {
        // Remove attempts outside the window
        self.timestamps.retain(|&t| now.duration_since(t) < window);
        // Add the new attempt
        self.timestamps.push(now);
    }

    /// Count attempts within the window.
    fn count(&self, now: Instant, window: Duration) -> usize {
        self.timestamps
            .iter()
            .filter(|&&t| now.duration_since(t) < window)
            .count()
    }

    /// Check if rate limit is exceeded.
    fn is_exceeded(&self, now: Instant, config: &RateLimitConfig) -> bool {
        self.count(now, config.window) >= config.max_attempts
    }
}

/// In-memory rate limiter for tracking login attempts.
///
/// Thread-safe and designed for high concurrency.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Configuration for rate limiting.
    config: RateLimitConfig,
    /// Attempt entries keyed by IP address.
    entries: Arc<Mutex<HashMap<IpAddr, AttemptEntry>>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new rate limiter with default configuration (5 attempts/minute).
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Check if the given IP is rate limited.
    ///
    /// Returns `true` if the IP has exceeded the rate limit.
    #[must_use]
    pub fn is_limited(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entries = self.entries.lock();

        entries
            .get(&ip)
            .is_some_and(|entry| entry.is_exceeded(now, &self.config))
    }

    /// Record an attempt from the given IP.
    ///
    /// Returns `true` if the attempt is allowed, `false` if rate limited.
    pub fn record_attempt(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock();

        let entry = entries.entry(ip).or_insert_with(AttemptEntry::new);

        // Check if already exceeded BEFORE recording
        if entry.is_exceeded(now, &self.config) {
            return false;
        }

        entry.record_attempt(now, self.config.window);
        true
    }

    /// Get the number of remaining attempts for an IP.
    #[must_use]
    pub fn remaining_attempts(&self, ip: IpAddr) -> usize {
        let now = Instant::now();
        let entries = self.entries.lock();

        let count = entries
            .get(&ip)
            .map_or(0, |entry| entry.count(now, self.config.window));

        self.config.max_attempts.saturating_sub(count)
    }

    /// Reset attempts for a specific IP (e.g., after successful login).
    pub fn reset(&self, ip: IpAddr) {
        let mut entries = self.entries.lock();
        entries.remove(&ip);
    }

    /// Clean up stale entries from all IPs.
    ///
    /// Should be called periodically to prevent memory growth.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut entries = self.entries.lock();

        entries.retain(|_, entry| {
            // Keep entries that have any attempts within the window
            entry.count(now, self.config.window) > 0
        });
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Multi-key rate limiter supporting IP and email-based rate limiting.
///
/// Used for password reset and email verification endpoints where
/// we want to limit both per-email and per-IP.
#[derive(Debug, Clone)]
pub struct EmailRateLimiter {
    /// Rate limit configuration for email-based limiting.
    email_config: RateLimitConfig,
    /// Rate limit configuration for IP-based limiting.
    ip_config: RateLimitConfig,
    /// Entries keyed by rate limit key.
    entries: Arc<Mutex<HashMap<RateLimitKey, AttemptEntry>>>,
}

impl EmailRateLimiter {
    /// Create a new email rate limiter with default configuration.
    ///
    /// Default: 3 requests per email per hour, 10 requests per IP per hour.
    #[must_use]
    pub fn new() -> Self {
        Self {
            email_config: RateLimitConfig {
                max_attempts: EMAIL_RATE_LIMIT_MAX,
                window: Duration::from_secs(EMAIL_RATE_LIMIT_WINDOW_SECS),
            },
            ip_config: RateLimitConfig {
                max_attempts: EMAIL_IP_RATE_LIMIT_MAX,
                window: Duration::from_secs(EMAIL_RATE_LIMIT_WINDOW_SECS),
            },
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new email rate limiter with custom configuration.
    #[must_use]
    pub fn with_config(email_max: usize, ip_max: usize, window_secs: u64) -> Self {
        let window = Duration::from_secs(window_secs);
        Self {
            email_config: RateLimitConfig {
                max_attempts: email_max,
                window,
            },
            ip_config: RateLimitConfig {
                max_attempts: ip_max,
                window,
            },
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if rate limited by email or IP.
    ///
    /// Returns `true` if either limit is exceeded.
    #[must_use]
    pub fn is_limited(&self, email: &str, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entries = self.entries.lock();

        let email_key = RateLimitKey::Email(email.to_lowercase());
        let ip_key = RateLimitKey::Ip(ip);

        let email_limited = entries
            .get(&email_key)
            .is_some_and(|e| e.is_exceeded(now, &self.email_config));

        let ip_limited = entries
            .get(&ip_key)
            .is_some_and(|e| e.is_exceeded(now, &self.ip_config));

        email_limited || ip_limited
    }

    /// Check if rate limited by email only.
    #[must_use]
    pub fn is_email_limited(&self, email: &str) -> bool {
        let now = Instant::now();
        let entries = self.entries.lock();
        let key = RateLimitKey::Email(email.to_lowercase());

        entries
            .get(&key)
            .is_some_and(|e| e.is_exceeded(now, &self.email_config))
    }

    /// Check if rate limited by IP only.
    #[must_use]
    pub fn is_ip_limited(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entries = self.entries.lock();
        let key = RateLimitKey::Ip(ip);

        entries
            .get(&key)
            .is_some_and(|e| e.is_exceeded(now, &self.ip_config))
    }

    /// Record an attempt for both email and IP.
    ///
    /// Returns `true` if the attempt is allowed, `false` if rate limited.
    pub fn record_attempt(&self, email: &str, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock();

        let email_key = RateLimitKey::Email(email.to_lowercase());
        let ip_key = RateLimitKey::Ip(ip);

        // Check if already exceeded
        let email_exceeded = entries
            .get(&email_key)
            .is_some_and(|e| e.is_exceeded(now, &self.email_config));

        let ip_exceeded = entries
            .get(&ip_key)
            .is_some_and(|e| e.is_exceeded(now, &self.ip_config));

        if email_exceeded || ip_exceeded {
            return false;
        }

        // Record attempts for both keys
        entries
            .entry(email_key)
            .or_insert_with(AttemptEntry::new)
            .record_attempt(now, self.email_config.window);

        entries
            .entry(ip_key)
            .or_insert_with(AttemptEntry::new)
            .record_attempt(now, self.ip_config.window);

        true
    }

    /// Get remaining attempts for email.
    #[must_use]
    pub fn remaining_email_attempts(&self, email: &str) -> usize {
        let now = Instant::now();
        let entries = self.entries.lock();
        let key = RateLimitKey::Email(email.to_lowercase());

        let count = entries
            .get(&key)
            .map_or(0, |e| e.count(now, self.email_config.window));

        self.email_config.max_attempts.saturating_sub(count)
    }

    /// Get remaining attempts for IP.
    #[must_use]
    pub fn remaining_ip_attempts(&self, ip: IpAddr) -> usize {
        let now = Instant::now();
        let entries = self.entries.lock();
        let key = RateLimitKey::Ip(ip);

        let count = entries
            .get(&key)
            .map_or(0, |e| e.count(now, self.ip_config.window));

        self.ip_config.max_attempts.saturating_sub(count)
    }

    /// Clean up stale entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        let window = self.email_config.window.max(self.ip_config.window);

        entries.retain(|_, entry| entry.count(now, window) > 0);
    }
}

impl Default for EmailRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiting middleware layer for Axum.
///
/// Checks incoming requests against the rate limiter and returns 429
/// if the client IP has exceeded the rate limit.
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::Extension(limiter): axum::Extension<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let ip = addr.ip();

    // Check if rate limited before recording
    if limiter.is_limited(ip) {
        return rate_limit_exceeded_response(limiter.remaining_attempts(ip));
    }

    // Record the attempt
    if !limiter.record_attempt(ip) {
        return rate_limit_exceeded_response(limiter.remaining_attempts(ip));
    }

    next.run(request).await
}

/// Generate a 429 Too Many Requests response.
fn rate_limit_exceeded_response(remaining: usize) -> Response {
    rate_limit_exceeded_response_with_endpoint(remaining, "/auth/login")
}

/// Generate a 429 Too Many Requests response with custom endpoint.
fn rate_limit_exceeded_response_with_endpoint(remaining: usize, endpoint: &str) -> Response {
    let body = serde_json::json!({
        "type": "https://xavyo.net/errors/rate-limit-exceeded",
        "title": "Too Many Requests",
        "status": 429,
        "detail": "Rate limit exceeded. Please wait before trying again.",
        "instance": endpoint,
        "remaining_attempts": remaining
    });

    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::CONTENT_TYPE, "application/problem+json")],
        body.to_string(),
    )
        .into_response()
}

/// Create a rate limiter for signup endpoint (F111).
///
/// Configuration: 10 requests per IP per hour (default).
/// Reads `SIGNUP_RATE_LIMIT_MAX` and `SIGNUP_RATE_LIMIT_WINDOW_SECS` env vars.
#[must_use]
pub fn signup_rate_limiter() -> RateLimiter {
    let max = std::env::var("SIGNUP_RATE_LIMIT_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(SIGNUP_RATE_LIMIT_MAX);
    let window_secs = std::env::var("SIGNUP_RATE_LIMIT_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(SIGNUP_RATE_LIMIT_WINDOW_SECS);
    RateLimiter::new(RateLimitConfig {
        max_attempts: max,
        window: Duration::from_secs(window_secs),
    })
}

/// Rate limiter for sensitive endpoints (MFA verification, password change, email change).
///
/// Configuration: 5 attempts per IP per minute.
/// Protects against brute-force attacks on authentication factors.
#[must_use]
pub fn sensitive_rate_limiter() -> RateLimiter {
    RateLimiter::new(RateLimitConfig {
        max_attempts: 5,
        window: Duration::from_secs(60),
    })
}

/// Rate limiting middleware specifically for signup endpoint (F111).
///
/// Similar to `rate_limit_middleware` but uses a separate rate limiter
/// configured for signup-specific limits (10/IP/hour).
pub async fn signup_rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::Extension(limiter): axum::Extension<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let ip = addr.ip();

    // Check if rate limited before recording
    if limiter.is_limited(ip) {
        return rate_limit_exceeded_response_with_endpoint(
            limiter.remaining_attempts(ip),
            "/auth/signup",
        );
    }

    // Record the attempt
    if !limiter.record_attempt(ip) {
        return rate_limit_exceeded_response_with_endpoint(
            limiter.remaining_attempts(ip),
            "/auth/signup",
        );
    }

    next.run(request).await
}

/// F202-US3: Per-API-key rate limiter using sliding window algorithm.
///
/// Keyed by API key UUID. Each key can have its own rate limit
/// (from `api_keys.rate_limit_per_hour`). The window is always 1 hour.
#[derive(Debug, Clone)]
pub struct ApiKeyRateLimiter {
    /// Entries keyed by API key UUID.
    entries: Arc<Mutex<HashMap<Uuid, ApiKeyAttemptEntry>>>,
}

/// Entry tracking attempts for a single API key.
#[derive(Debug, Clone)]
struct ApiKeyAttemptEntry {
    /// Timestamps of attempts within the window.
    timestamps: Vec<Instant>,
}

/// The sliding window duration for API key rate limiting (1 hour).
const API_KEY_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600);

impl ApiKeyAttemptEntry {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    /// Clean up old attempts and add a new one.
    fn record_attempt(&mut self, now: Instant) {
        self.timestamps
            .retain(|&t| now.duration_since(t) < API_KEY_RATE_LIMIT_WINDOW);
        self.timestamps.push(now);
    }

    /// Count attempts within the window.
    fn count(&self, now: Instant) -> usize {
        self.timestamps
            .iter()
            .filter(|&&t| now.duration_since(t) < API_KEY_RATE_LIMIT_WINDOW)
            .count()
    }
}

impl ApiKeyRateLimiter {
    /// Create a new API key rate limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record an attempt for the given API key.
    ///
    /// Returns `true` if the attempt is allowed, `false` if rate limited.
    /// `max_per_hour` is the per-key limit from the database.
    pub fn record_attempt(&self, key_id: Uuid, max_per_hour: usize) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock();

        let entry = entries
            .entry(key_id)
            .or_insert_with(ApiKeyAttemptEntry::new);

        // Check if already exceeded BEFORE recording
        if entry.count(now) >= max_per_hour {
            return false;
        }

        entry.record_attempt(now);
        true
    }

    /// Check if the given API key is rate limited.
    #[must_use]
    pub fn is_limited(&self, key_id: Uuid, max_per_hour: usize) -> bool {
        let now = Instant::now();
        let entries = self.entries.lock();

        entries
            .get(&key_id)
            .is_some_and(|entry| entry.count(now) >= max_per_hour)
    }

    /// Get the number of remaining attempts for an API key.
    #[must_use]
    pub fn remaining_attempts(&self, key_id: Uuid, max_per_hour: usize) -> usize {
        let now = Instant::now();
        let entries = self.entries.lock();

        let count = entries.get(&key_id).map_or(0, |entry| entry.count(now));

        max_per_hour.saturating_sub(count)
    }

    /// Clean up stale entries.
    ///
    /// Should be called periodically to prevent memory growth.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        entries.retain(|_, entry| entry.count(now) > 0);
    }
}

impl Default for ApiKeyRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn test_ip() -> IpAddr {
        "192.168.1.1".parse().unwrap()
    }

    fn test_ip_2() -> IpAddr {
        "192.168.1.2".parse().unwrap()
    }

    #[test]
    fn new_ip_not_limited() {
        let limiter = RateLimiter::default();
        assert!(!limiter.is_limited(test_ip()));
    }

    #[test]
    fn allows_up_to_max_attempts() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_attempts: 3,
            window: Duration::from_secs(60),
        });

        let ip = test_ip();

        // First 3 attempts should succeed
        assert!(limiter.record_attempt(ip));
        assert!(limiter.record_attempt(ip));
        assert!(limiter.record_attempt(ip));

        // 4th attempt should be blocked
        assert!(!limiter.record_attempt(ip));
        assert!(limiter.is_limited(ip));
    }

    #[test]
    fn different_ips_independent() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_attempts: 2,
            window: Duration::from_secs(60),
        });

        // Exhaust IP 1
        limiter.record_attempt(test_ip());
        limiter.record_attempt(test_ip());

        // IP 2 should still be allowed
        assert!(limiter.record_attempt(test_ip_2()));
        assert!(!limiter.is_limited(test_ip_2()));
    }

    #[test]
    fn remaining_attempts_correct() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_attempts: 5,
            window: Duration::from_secs(60),
        });

        let ip = test_ip();
        assert_eq!(limiter.remaining_attempts(ip), 5);

        limiter.record_attempt(ip);
        assert_eq!(limiter.remaining_attempts(ip), 4);

        limiter.record_attempt(ip);
        limiter.record_attempt(ip);
        assert_eq!(limiter.remaining_attempts(ip), 2);
    }

    #[test]
    fn reset_clears_attempts() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_attempts: 2,
            window: Duration::from_secs(60),
        });

        let ip = test_ip();

        // Exhaust attempts
        limiter.record_attempt(ip);
        limiter.record_attempt(ip);
        assert!(limiter.is_limited(ip));

        // Reset
        limiter.reset(ip);
        assert!(!limiter.is_limited(ip));
        assert_eq!(limiter.remaining_attempts(ip), 2);
    }

    #[test]
    fn window_sliding_behavior() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_attempts: 2,
            window: Duration::from_millis(100),
        });

        let ip = test_ip();

        // Exhaust attempts
        limiter.record_attempt(ip);
        limiter.record_attempt(ip);
        assert!(limiter.is_limited(ip));

        // Wait for window to pass
        sleep(Duration::from_millis(150));

        // Should be allowed again
        assert!(!limiter.is_limited(ip));
        assert!(limiter.record_attempt(ip));
    }

    #[test]
    fn cleanup_removes_stale_entries() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_attempts: 2,
            window: Duration::from_millis(50),
        });

        let ip = test_ip();
        limiter.record_attempt(ip);

        // Entry exists
        {
            let entries = limiter.entries.lock();
            assert!(entries.contains_key(&ip));
        }

        // Wait for window to expire
        sleep(Duration::from_millis(100));

        // Cleanup should remove stale entry
        limiter.cleanup();

        {
            let entries = limiter.entries.lock();
            assert!(!entries.contains_key(&ip));
        }
    }

    #[test]
    fn default_config_values() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert_eq!(config.window, Duration::from_secs(DEFAULT_WINDOW_SECS));
    }

    #[test]
    fn email_rate_limiter_allows_within_limit() {
        let limiter = EmailRateLimiter::with_config(2, 5, 60);
        let email = "test@example.com";
        let ip = test_ip();

        // First two attempts should succeed
        assert!(limiter.record_attempt(email, ip));
        assert!(limiter.record_attempt(email, ip));

        // Third attempt should fail (email limit = 2)
        assert!(!limiter.record_attempt(email, ip));
    }

    #[test]
    fn email_rate_limiter_different_emails_independent() {
        let limiter = EmailRateLimiter::with_config(2, 10, 60);
        let ip = test_ip();

        // Exhaust limit for email1
        limiter.record_attempt("email1@example.com", ip);
        limiter.record_attempt("email1@example.com", ip);

        // email2 should still be allowed
        assert!(limiter.record_attempt("email2@example.com", ip));
    }

    #[test]
    fn email_rate_limiter_ip_limit() {
        let limiter = EmailRateLimiter::with_config(10, 2, 60);
        let ip = test_ip();

        // First two attempts should succeed (even different emails)
        assert!(limiter.record_attempt("a@example.com", ip));
        assert!(limiter.record_attempt("b@example.com", ip));

        // Third attempt fails due to IP limit
        assert!(!limiter.record_attempt("c@example.com", ip));
    }

    #[test]
    fn email_rate_limiter_remaining_attempts() {
        let limiter = EmailRateLimiter::with_config(3, 5, 60);
        let email = "test@example.com";
        let ip = test_ip();

        assert_eq!(limiter.remaining_email_attempts(email), 3);
        assert_eq!(limiter.remaining_ip_attempts(ip), 5);

        limiter.record_attempt(email, ip);

        assert_eq!(limiter.remaining_email_attempts(email), 2);
        assert_eq!(limiter.remaining_ip_attempts(ip), 4);
    }

    #[test]
    fn email_rate_limiter_case_insensitive() {
        let limiter = EmailRateLimiter::with_config(2, 10, 60);
        let ip = test_ip();

        limiter.record_attempt("Test@Example.com", ip);
        limiter.record_attempt("test@example.com", ip);

        // Should be limited because both emails are treated as the same
        assert!(!limiter.record_attempt("TEST@EXAMPLE.COM", ip));
    }

    // ====== F202-US3: API key rate limiter tests ======

    #[test]
    fn test_api_key_rate_limiter_allows_within_limit() {
        let limiter = ApiKeyRateLimiter::new();
        let key_id = Uuid::new_v4();

        // First 5 attempts should succeed with limit of 5
        for _ in 0..5 {
            assert!(limiter.record_attempt(key_id, 5));
        }
    }

    #[test]
    fn test_api_key_rate_limiter_blocks_over_limit() {
        let limiter = ApiKeyRateLimiter::new();
        let key_id = Uuid::new_v4();

        // Exhaust limit
        for _ in 0..3 {
            assert!(limiter.record_attempt(key_id, 3));
        }

        // 4th attempt should be blocked
        assert!(!limiter.record_attempt(key_id, 3));
        assert!(limiter.is_limited(key_id, 3));
    }

    #[test]
    fn test_api_key_rate_limiter_independent_keys() {
        let limiter = ApiKeyRateLimiter::new();
        let key1 = Uuid::new_v4();
        let key2 = Uuid::new_v4();

        // Exhaust key1's limit
        for _ in 0..2 {
            limiter.record_attempt(key1, 2);
        }
        assert!(limiter.is_limited(key1, 2));

        // key2 should still be allowed
        assert!(limiter.record_attempt(key2, 2));
        assert!(!limiter.is_limited(key2, 2));
    }

    #[test]
    fn test_api_key_rate_limiter_remaining_attempts() {
        let limiter = ApiKeyRateLimiter::new();
        let key_id = Uuid::new_v4();

        assert_eq!(limiter.remaining_attempts(key_id, 5), 5);

        limiter.record_attempt(key_id, 5);
        assert_eq!(limiter.remaining_attempts(key_id, 4), 3);

        limiter.record_attempt(key_id, 5);
        limiter.record_attempt(key_id, 5);
        assert_eq!(limiter.remaining_attempts(key_id, 5), 2);
    }

    #[test]
    fn test_api_key_rate_limiter_cleanup() {
        let limiter = ApiKeyRateLimiter::new();
        let key_id = Uuid::new_v4();

        limiter.record_attempt(key_id, 10);

        // Entry exists
        {
            let entries = limiter.entries.lock();
            assert!(entries.contains_key(&key_id));
        }

        // Cleanup should keep entries within window (1 hour)
        limiter.cleanup();
        {
            let entries = limiter.entries.lock();
            assert!(entries.contains_key(&key_id));
        }
    }
}
