//! Webhook delivery execution service.
//!
//! Responsible for finding matching subscriptions for an event, creating
//! delivery records, executing HTTP POST with HMAC-SHA256 signatures,
//! and recording delivery results.
//!
//! Integrates with:
//! - Circuit breaker pattern to protect against failing endpoints
//! - Dead letter queue for webhooks that exhaust all retries
//! - Rate limiting to prevent overwhelming endpoints

use std::sync::Arc;
use std::time::Instant;

use chrono::{Duration, Utc};
use reqwest::Client;
use sqlx::PgPool;

use crate::circuit_breaker::{CircuitBreakerRegistry, FailureRecord};
use crate::crypto;
use crate::error::WebhookError;
use crate::models::WebhookPayload;
use crate::rate_limiter::RateLimiterRegistry;
use crate::services::dlq_service::{AttemptRecord, DlqService};
use crate::services::event_publisher::WebhookEvent;
use xavyo_db::models::{CreateWebhookDelivery, WebhookDelivery, WebhookSubscription};

/// Default maximum delivery attempts per event (initial + 5 retries).
pub const DEFAULT_MAX_ATTEMPTS: i32 = 6;

/// Default consecutive failure threshold before auto-disabling a subscription.
pub const DEFAULT_DISABLE_THRESHOLD: i32 = 50;

/// Exponential backoff schedule (in seconds): 1min, 5min, 30min, 2hr, 24hr.
const BACKOFF_SCHEDULE_SECS: [i64; 5] = [60, 300, 1800, 7200, 86400];

/// Service for webhook delivery operations.
#[derive(Clone)]
pub struct DeliveryService {
    pool: PgPool,
    http_client: Client,
    encryption_key: Vec<u8>,
    max_attempts: i32,
    disable_threshold: i32,
    /// Circuit breaker registry for tracking endpoint health.
    circuit_breaker_registry: Option<Arc<CircuitBreakerRegistry>>,
    /// DLQ service for storing failed webhooks.
    dlq_service: Option<Arc<DlqService>>,
    /// Rate limiter registry for per-destination throttling.
    rate_limiter_registry: Option<Arc<RateLimiterRegistry>>,
}

impl DeliveryService {
    /// Create a new delivery service with a shared HTTP client.
    ///
    /// # Errors
    ///
    /// Returns `WebhookError::Internal` if the HTTP client cannot be built.
    pub fn new(pool: PgPool, encryption_key: Vec<u8>) -> Result<Self, WebhookError> {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("xavyo-webhooks/1.0")
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| WebhookError::Internal(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            pool,
            http_client,
            encryption_key,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            disable_threshold: DEFAULT_DISABLE_THRESHOLD,
            circuit_breaker_registry: None,
            dlq_service: None,
            rate_limiter_registry: None,
        })
    }

    /// Set the maximum delivery attempts.
    pub fn with_max_attempts(mut self, max: i32) -> Self {
        self.max_attempts = max;
        self
    }

    /// Set the consecutive failure threshold for auto-disable.
    pub fn with_disable_threshold(mut self, threshold: i32) -> Self {
        self.disable_threshold = threshold;
        self
    }

    /// Set the circuit breaker registry for endpoint health tracking.
    pub fn with_circuit_breaker(mut self, registry: Arc<CircuitBreakerRegistry>) -> Self {
        self.circuit_breaker_registry = Some(registry);
        self
    }

    /// Set the DLQ service for storing failed webhooks.
    pub fn with_dlq_service(mut self, service: Arc<DlqService>) -> Self {
        self.dlq_service = Some(service);
        self
    }

    /// Set the rate limiter registry for per-destination throttling.
    pub fn with_rate_limiter(mut self, registry: Arc<RateLimiterRegistry>) -> Self {
        self.rate_limiter_registry = Some(registry);
        self
    }

    /// Deliver an event to all matching active subscriptions.
    ///
    /// For each active subscription whose event_types include the event's type,
    /// creates a delivery record and attempts immediate delivery.
    pub async fn deliver_event(&self, event: &WebhookEvent) {
        let subscriptions = match WebhookSubscription::find_active_by_event_type(
            &self.pool,
            event.tenant_id,
            &event.event_type,
        )
        .await
        {
            Ok(subs) => subs,
            Err(e) => {
                tracing::error!(
                    target: "webhook_delivery",
                    event_id = %event.event_id,
                    event_type = %event.event_type,
                    tenant_id = %event.tenant_id,
                    error = %e,
                    "Failed to query matching subscriptions"
                );
                return;
            }
        };

        if subscriptions.is_empty() {
            tracing::debug!(
                target: "webhook_delivery",
                event_id = %event.event_id,
                event_type = %event.event_type,
                tenant_id = %event.tenant_id,
                "No active subscriptions match event type"
            );
            return;
        }

        tracing::info!(
            target: "webhook_delivery",
            event_id = %event.event_id,
            event_type = %event.event_type,
            tenant_id = %event.tenant_id,
            subscription_count = subscriptions.len(),
            "Delivering event to matching subscriptions"
        );

        let payload = WebhookPayload {
            event_id: event.event_id,
            event_type: event.event_type.clone(),
            timestamp: event.timestamp,
            tenant_id: event.tenant_id,
            data: event.data.clone(),
        };

        for sub in subscriptions {
            self.deliver_to_subscription(&sub, &payload).await;
        }
    }

    /// Create a delivery record and attempt immediate delivery to a subscription.
    async fn deliver_to_subscription(
        &self,
        subscription: &WebhookSubscription,
        payload: &WebhookPayload,
    ) {
        let payload_json = match serde_json::to_value(payload) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    target: "webhook_delivery",
                    subscription_id = %subscription.id,
                    error = %e,
                    "Failed to serialize webhook payload"
                );
                return;
            }
        };

        // Create delivery record
        let delivery = match WebhookDelivery::create(
            &self.pool,
            CreateWebhookDelivery {
                tenant_id: subscription.tenant_id,
                subscription_id: subscription.id,
                event_id: payload.event_id,
                event_type: payload.event_type.clone(),
                request_payload: payload_json,
                max_attempts: self.max_attempts,
                next_attempt_at: Some(Utc::now()),
            },
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(
                    target: "webhook_delivery",
                    subscription_id = %subscription.id,
                    event_id = %payload.event_id,
                    error = %e,
                    "Failed to create delivery record"
                );
                return;
            }
        };

        // Attempt immediate delivery
        self.execute_delivery(&delivery, subscription).await;
    }

    /// Execute a single delivery attempt to a subscription's URL.
    pub async fn execute_delivery(
        &self,
        delivery: &WebhookDelivery,
        subscription: &WebhookSubscription,
    ) {
        // Check circuit breaker first - if open, reject immediately
        if let Some(ref cb_registry) = self.circuit_breaker_registry {
            match cb_registry
                .can_execute(subscription.tenant_id, subscription.id)
                .await
            {
                Ok(true) => {
                    // Circuit allows execution
                }
                Ok(false) => {
                    // Circuit is open - reject delivery
                    tracing::warn!(
                        target: "webhook_delivery",
                        delivery_id = %delivery.id,
                        subscription_id = %subscription.id,
                        "Delivery rejected - circuit breaker is open"
                    );
                    self.handle_delivery_failure(
                        delivery,
                        subscription,
                        "Circuit breaker open - endpoint temporarily unavailable",
                        None,
                        None,
                        None,
                    )
                    .await;
                    return;
                }
                Err(e) => {
                    tracing::error!(
                        target: "webhook_delivery",
                        delivery_id = %delivery.id,
                        error = %e,
                        "Failed to check circuit breaker status"
                    );
                    // Continue with delivery on error - fail open
                }
            }
        }

        // Apply rate limiting - wait if necessary
        if let Some(ref rl_registry) = self.rate_limiter_registry {
            let wait_duration = rl_registry.acquire(subscription.id).await;
            if !wait_duration.is_zero() {
                tracing::debug!(
                    target: "webhook_delivery",
                    delivery_id = %delivery.id,
                    subscription_id = %subscription.id,
                    wait_ms = wait_duration.as_millis(),
                    "Rate limited - waited before delivery"
                );
            }
        }

        let payload_bytes = match serde_json::to_vec(&delivery.request_payload) {
            Ok(b) => b,
            Err(e) => {
                self.handle_delivery_failure(
                    delivery,
                    subscription,
                    &format!("Failed to serialize payload: {e}"),
                    None,
                    None,
                    None,
                )
                .await;
                return;
            }
        };

        let timestamp = Utc::now().timestamp().to_string();

        // Build headers
        // SECURITY: Header values are constructed from safe constants and validated UUIDs,
        // so parse errors should never occur. Use unwrap_or_default as a fallback.
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(v) = "application/json".parse() {
            headers.insert("Content-Type", v);
        }
        if let Ok(v) = timestamp.parse() {
            headers.insert("X-Webhook-Timestamp", v);
        }
        if let Ok(v) = delivery.event_id.to_string().parse() {
            headers.insert("X-Event-ID", v);
        }

        // Compute HMAC-SHA256 signature if subscription has a secret
        if let Some(ref secret_encrypted) = subscription.secret_encrypted {
            match crypto::decrypt_secret(secret_encrypted, &self.encryption_key) {
                Ok(secret) => {
                    let signature =
                        crypto::compute_hmac_signature(&secret, &timestamp, &payload_bytes);
                    if let Ok(v) = format!("sha256={signature}").parse() {
                        headers.insert("X-Webhook-Signature", v);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "webhook_delivery",
                        delivery_id = %delivery.id,
                        subscription_id = %subscription.id,
                        error = %e,
                        "Failed to decrypt subscription secret — delivering without signature"
                    );
                }
            }
        }

        let request_headers_json =
            serde_json::to_value(headers_to_map(&headers)).unwrap_or_default();

        // Execute HTTP POST
        let start = Instant::now();
        let result = self
            .http_client
            .post(&subscription.url)
            .headers(headers)
            .body(payload_bytes)
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as i32;

        match result {
            Ok(response) => {
                let status_code = response.status().as_u16() as i16;
                let body = response
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(4096)
                    .collect::<String>();

                if (200..300).contains(&(status_code as u16)) {
                    self.handle_delivery_success(
                        delivery,
                        subscription,
                        status_code,
                        Some(&body),
                        latency_ms,
                        Some(&request_headers_json),
                    )
                    .await;
                } else {
                    self.handle_delivery_failure(
                        delivery,
                        subscription,
                        &format!("HTTP {status_code}"),
                        Some(status_code),
                        Some(&body),
                        Some(latency_ms),
                    )
                    .await;
                }
            }
            Err(e) => {
                let error_msg = if e.is_timeout() {
                    "Request timeout (10s)".to_string()
                } else if e.is_connect() {
                    format!("Connection failed: {e}")
                } else {
                    format!("Request error: {e}")
                };

                self.handle_delivery_failure(
                    delivery,
                    subscription,
                    &error_msg,
                    None,
                    None,
                    Some(latency_ms),
                )
                .await;
            }
        }
    }

    /// Handle a successful delivery.
    async fn handle_delivery_success(
        &self,
        delivery: &WebhookDelivery,
        subscription: &WebhookSubscription,
        response_code: i16,
        response_body: Option<&str>,
        latency_ms: i32,
        request_headers: Option<&serde_json::Value>,
    ) {
        tracing::info!(
            target: "webhook_delivery",
            delivery_id = %delivery.id,
            subscription_id = %subscription.id,
            tenant_id = %subscription.tenant_id,
            event_id = %delivery.event_id,
            event_type = %delivery.event_type,
            response_code,
            latency_ms,
            attempt_number = delivery.attempt_number + 1,
            "Webhook delivery succeeded"
        );

        if let Err(e) = WebhookDelivery::mark_success(
            &self.pool,
            delivery.tenant_id,
            delivery.id,
            response_code,
            response_body,
            latency_ms,
            request_headers,
        )
        .await
        {
            tracing::error!(
                target: "webhook_delivery",
                delivery_id = %delivery.id,
                error = %e,
                "Failed to update delivery status to success"
            );
        }

        // Record success to circuit breaker
        if let Some(ref cb_registry) = self.circuit_breaker_registry {
            if let Err(e) = cb_registry
                .record_success(subscription.tenant_id, subscription.id)
                .await
            {
                tracing::error!(
                    target: "webhook_delivery",
                    subscription_id = %subscription.id,
                    error = %e,
                    "Failed to record success to circuit breaker"
                );
            }
        }

        // Reset consecutive failures on success
        if subscription.consecutive_failures > 0 {
            if let Err(e) = WebhookSubscription::reset_consecutive_failures(
                &self.pool,
                subscription.tenant_id,
                subscription.id,
            )
            .await
            {
                tracing::error!(
                    target: "webhook_delivery",
                    subscription_id = %subscription.id,
                    error = %e,
                    "Failed to reset consecutive failures"
                );
            }
        }
    }

    /// Handle a failed delivery — schedule retry or disable subscription.
    async fn handle_delivery_failure(
        &self,
        delivery: &WebhookDelivery,
        subscription: &WebhookSubscription,
        error_message: &str,
        response_code: Option<i16>,
        response_body: Option<&str>,
        latency_ms: Option<i32>,
    ) {
        let next_attempt = delivery.attempt_number + 1;
        let next_attempt_at = calculate_next_attempt_at(next_attempt, self.max_attempts);
        let retries_exhausted = next_attempt_at.is_none();

        tracing::warn!(
            target: "webhook_delivery",
            delivery_id = %delivery.id,
            subscription_id = %subscription.id,
            tenant_id = %subscription.tenant_id,
            event_id = %delivery.event_id,
            event_type = %delivery.event_type,
            error = %error_message,
            attempt_number = next_attempt,
            has_next_retry = !retries_exhausted,
            "Webhook delivery failed"
        );

        // Record failure to circuit breaker
        if let Some(ref cb_registry) = self.circuit_breaker_registry {
            let failure_record =
                FailureRecord::new(error_message.to_string(), response_code, latency_ms);
            if let Err(e) = cb_registry
                .record_failure(subscription.tenant_id, subscription.id, failure_record)
                .await
            {
                tracing::error!(
                    target: "webhook_delivery",
                    subscription_id = %subscription.id,
                    error = %e,
                    "Failed to record failure to circuit breaker"
                );
            }
        }

        // Update delivery record
        if let Err(e) = WebhookDelivery::mark_failed(
            &self.pool,
            delivery.tenant_id,
            delivery.id,
            next_attempt,
            error_message,
            response_code,
            response_body,
            latency_ms,
            next_attempt_at,
            None,
        )
        .await
        {
            tracing::error!(
                target: "webhook_delivery",
                delivery_id = %delivery.id,
                error = %e,
                "Failed to update delivery status to failed"
            );
        }

        // If retries exhausted, move to DLQ
        if retries_exhausted {
            if let Some(ref dlq_service) = self.dlq_service {
                // Build attempt history from delivery attempts
                let attempt_history = self
                    .build_attempt_history(delivery, error_message, response_code, latency_ms)
                    .await;

                if let Err(e) = dlq_service
                    .add_to_dlq(
                        delivery.tenant_id,
                        delivery,
                        subscription,
                        error_message.to_string(),
                        response_code,
                        response_body.map(|s| s.to_string()),
                        attempt_history,
                    )
                    .await
                {
                    tracing::error!(
                        target: "webhook_delivery",
                        delivery_id = %delivery.id,
                        error = %e,
                        "Failed to move delivery to DLQ"
                    );
                }
            }
        }

        // Increment consecutive failures and check threshold
        match WebhookSubscription::increment_consecutive_failures(
            &self.pool,
            subscription.tenant_id,
            subscription.id,
        )
        .await
        {
            Ok(failures) => {
                if failures >= self.disable_threshold {
                    tracing::warn!(
                        target: "webhook_delivery",
                        subscription_id = %subscription.id,
                        tenant_id = %subscription.tenant_id,
                        consecutive_failures = failures,
                        threshold = self.disable_threshold,
                        "Auto-disabling subscription due to consecutive failures"
                    );

                    if let Err(e) = WebhookSubscription::disable(
                        &self.pool,
                        subscription.tenant_id,
                        subscription.id,
                    )
                    .await
                    {
                        tracing::error!(
                            target: "webhook_delivery",
                            subscription_id = %subscription.id,
                            error = %e,
                            "Failed to auto-disable subscription"
                        );
                    }

                    // Abandon all pending deliveries for the disabled subscription
                    if let Err(e) = WebhookDelivery::mark_abandoned_for_subscription(
                        &self.pool,
                        subscription.tenant_id,
                        subscription.id,
                    )
                    .await
                    {
                        tracing::error!(
                            target: "webhook_delivery",
                            subscription_id = %subscription.id,
                            error = %e,
                            "Failed to abandon pending deliveries for disabled subscription"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    target: "webhook_delivery",
                    subscription_id = %subscription.id,
                    error = %e,
                    "Failed to increment consecutive failures"
                );
            }
        }
    }

    /// Build attempt history for DLQ entry.
    async fn build_attempt_history(
        &self,
        delivery: &WebhookDelivery,
        final_error: &str,
        final_response_code: Option<i16>,
        final_latency_ms: Option<i32>,
    ) -> Vec<AttemptRecord> {
        // Create a simple history with the final attempt
        // In a more complete implementation, we would track all attempts
        vec![AttemptRecord {
            attempt_number: delivery.attempt_number + 1,
            timestamp: Utc::now(),
            error: final_error.to_string(),
            response_code: final_response_code,
            latency_ms: final_latency_ms,
        }]
    }

    /// Process a pending delivery that is ready for retry.
    pub async fn process_retry(&self, delivery: &WebhookDelivery) {
        // Load the subscription to check it's still enabled
        let subscription = match WebhookSubscription::find_by_id(
            &self.pool,
            delivery.tenant_id,
            delivery.subscription_id,
        )
        .await
        {
            Ok(Some(sub)) if sub.enabled => sub,
            Ok(Some(_)) => {
                // Subscription was disabled — abandon delivery
                tracing::info!(
                    target: "webhook_delivery",
                    delivery_id = %delivery.id,
                    subscription_id = %delivery.subscription_id,
                    "Abandoning retry — subscription is disabled"
                );
                let _ = WebhookDelivery::update_status(
                    &self.pool,
                    delivery.tenant_id,
                    delivery.id,
                    "abandoned",
                    delivery.attempt_number,
                    None,
                    None,
                    None,
                    Some("Subscription disabled"),
                    None,
                    None,
                    Some(Utc::now()),
                )
                .await;
                return;
            }
            Ok(None) => {
                // Subscription was deleted — abandon delivery
                tracing::info!(
                    target: "webhook_delivery",
                    delivery_id = %delivery.id,
                    subscription_id = %delivery.subscription_id,
                    "Abandoning retry — subscription not found"
                );
                let _ = WebhookDelivery::update_status(
                    &self.pool,
                    delivery.tenant_id,
                    delivery.id,
                    "abandoned",
                    delivery.attempt_number,
                    None,
                    None,
                    None,
                    Some("Subscription deleted"),
                    None,
                    None,
                    Some(Utc::now()),
                )
                .await;
                return;
            }
            Err(e) => {
                tracing::error!(
                    target: "webhook_delivery",
                    delivery_id = %delivery.id,
                    error = %e,
                    "Failed to load subscription for retry"
                );
                return;
            }
        };

        self.execute_delivery(delivery, &subscription).await;
    }

    /// Get a reference to the connection pool (for the worker).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Calculate the next retry timestamp based on attempt number and backoff schedule.
///
/// Returns None if all retries are exhausted.
pub fn calculate_next_attempt_at(
    attempt_number: i32,
    max_attempts: i32,
) -> Option<chrono::DateTime<chrono::Utc>> {
    if attempt_number >= max_attempts {
        return None;
    }

    // attempt_number is 1-based after first failure
    // Index into backoff schedule: attempt 1 -> index 0, attempt 2 -> index 1, etc.
    let idx = (attempt_number - 1).max(0) as usize;
    let delay_secs = BACKOFF_SCHEDULE_SECS
        .get(idx)
        .copied()
        .unwrap_or(*BACKOFF_SCHEDULE_SECS.last().unwrap());

    Some(Utc::now() + Duration::seconds(delay_secs))
}

/// Convert reqwest HeaderMap to a JSON-serializable map.
fn headers_to_map(
    headers: &reqwest::header::HeaderMap,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            map.insert(name.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_next_attempt_at_first_retry() {
        let next = calculate_next_attempt_at(1, 6);
        assert!(next.is_some());
        let delay = next.unwrap() - Utc::now();
        // Should be ~60 seconds (with small tolerance)
        assert!(delay.num_seconds() >= 58 && delay.num_seconds() <= 62);
    }

    #[test]
    fn test_calculate_next_attempt_at_second_retry() {
        let next = calculate_next_attempt_at(2, 6);
        assert!(next.is_some());
        let delay = next.unwrap() - Utc::now();
        // Should be ~300 seconds (5 minutes)
        assert!(delay.num_seconds() >= 298 && delay.num_seconds() <= 302);
    }

    #[test]
    fn test_calculate_next_attempt_at_third_retry() {
        let next = calculate_next_attempt_at(3, 6);
        assert!(next.is_some());
        let delay = next.unwrap() - Utc::now();
        // Should be ~1800 seconds (30 minutes)
        assert!(delay.num_seconds() >= 1798 && delay.num_seconds() <= 1802);
    }

    #[test]
    fn test_calculate_next_attempt_at_fourth_retry() {
        let next = calculate_next_attempt_at(4, 6);
        assert!(next.is_some());
        let delay = next.unwrap() - Utc::now();
        // Should be ~7200 seconds (2 hours)
        assert!(delay.num_seconds() >= 7198 && delay.num_seconds() <= 7202);
    }

    #[test]
    fn test_calculate_next_attempt_at_fifth_retry() {
        let next = calculate_next_attempt_at(5, 6);
        assert!(next.is_some());
        let delay = next.unwrap() - Utc::now();
        // Should be ~86400 seconds (24 hours)
        assert!(delay.num_seconds() >= 86398 && delay.num_seconds() <= 86402);
    }

    #[test]
    fn test_calculate_next_attempt_at_exhausted() {
        let next = calculate_next_attempt_at(6, 6);
        assert!(
            next.is_none(),
            "Should return None when all retries exhausted"
        );
    }

    #[test]
    fn test_calculate_next_attempt_at_over_max() {
        let next = calculate_next_attempt_at(10, 6);
        assert!(next.is_none());
    }

    #[test]
    fn test_backoff_schedule_length() {
        assert_eq!(
            BACKOFF_SCHEDULE_SECS.len(),
            5,
            "Should have 5 backoff intervals"
        );
    }

    #[test]
    fn test_backoff_schedule_monotonically_increasing() {
        for i in 1..BACKOFF_SCHEDULE_SECS.len() {
            assert!(
                BACKOFF_SCHEDULE_SECS[i] > BACKOFF_SCHEDULE_SECS[i - 1],
                "Backoff schedule should be monotonically increasing"
            );
        }
    }

    #[test]
    fn test_headers_to_map() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("X-Custom", "test-value".parse().unwrap());

        let map = headers_to_map(&headers);
        assert_eq!(map.get("content-type").unwrap(), "application/json");
        assert_eq!(map.get("x-custom").unwrap(), "test-value");
    }
}
