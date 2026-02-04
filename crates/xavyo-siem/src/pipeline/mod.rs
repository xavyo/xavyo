//! Export pipeline orchestration.
//!
//! Manages the flow: receive event → filter → format → rate limit → circuit breaker → deliver → record result.

pub mod circuit_breaker;
pub mod consumer;
pub mod rate_limiter;
pub mod retry;

use tokio::sync::Mutex;

use crate::delivery::DeliveryWorker;
use crate::format::{self, FormatError};
use crate::models::{ExportFormat, SiemEvent};
use circuit_breaker::CircuitBreaker;
use rate_limiter::DestinationRateLimiter;
use retry::RetryPolicy;

/// Errors from the export pipeline.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("Event filtered out by destination filter")]
    Filtered,

    #[error("Circuit breaker is open — delivery blocked")]
    CircuitOpen,

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Format error: {0}")]
    Format(#[from] FormatError),

    #[error("Delivery failed after retries: {0}")]
    DeliveryExhausted(String),
}

/// Result of processing a single event through the pipeline.
#[derive(Debug)]
pub struct PipelineResult {
    /// Whether the event was delivered successfully.
    pub delivered: bool,
    /// Delivery latency in milliseconds (if attempted).
    pub latency_ms: Option<u64>,
    /// Number of retry attempts made.
    pub retry_count: u8,
    /// Whether the event was sent to dead letter.
    pub dead_lettered: bool,
    /// Error message if delivery failed.
    pub error: Option<String>,
}

/// Configuration for an export pipeline instance.
pub struct PipelineConfig {
    /// Export format for this destination.
    pub export_format: ExportFormat,
    /// Event type filter — empty means accept all.
    pub event_type_filter: Vec<String>,
    /// Rate limit per second.
    pub rate_limit_per_second: u32,
    /// Circuit breaker failure threshold.
    pub circuit_breaker_threshold: u32,
    /// Circuit breaker cooldown in seconds.
    pub circuit_breaker_cooldown_secs: u64,
}

/// Export pipeline for a single SIEM destination.
///
/// Orchestrates: filter → format → rate limit → circuit breaker → deliver → retry.
pub struct ExportPipeline {
    worker: Box<dyn DeliveryWorker>,
    config: PipelineConfig,
    circuit_breaker: Mutex<CircuitBreaker>,
    rate_limiter: DestinationRateLimiter,
    retry_policy: RetryPolicy,
}

impl ExportPipeline {
    /// Create a new export pipeline for a destination.
    #[must_use] 
    pub fn new(worker: Box<dyn DeliveryWorker>, config: PipelineConfig) -> Self {
        let circuit_breaker = CircuitBreaker::new(
            config.circuit_breaker_threshold,
            config.circuit_breaker_cooldown_secs,
        );
        let rate_limiter = DestinationRateLimiter::new(config.rate_limit_per_second);
        let retry_policy = RetryPolicy::new();

        Self {
            worker,
            config,
            circuit_breaker: Mutex::new(circuit_breaker),
            rate_limiter,
            retry_policy,
        }
    }

    /// Process a single event through the pipeline.
    ///
    /// Returns a `PipelineResult` indicating the outcome. The caller is responsible
    /// for recording the result in the database (`siem_export_events`, `siem_delivery_health`).
    pub async fn process_event(&self, event: &SiemEvent) -> PipelineResult {
        // Step 1: Filter — check if event type is accepted
        if !self.matches_filter(event) {
            return PipelineResult {
                delivered: false,
                latency_ms: None,
                retry_count: 0,
                dead_lettered: false,
                error: None,
            };
        }

        // Step 2: Format the event
        let payload = match format::format_event(event, self.config.export_format) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to format event {}: {}", event.event_id, e);
                return PipelineResult {
                    delivered: false,
                    latency_ms: None,
                    retry_count: 0,
                    dead_lettered: true,
                    error: Some(format!("Format error: {e}")),
                };
            }
        };

        // Step 3: Rate limit — wait if necessary
        self.rate_limiter.wait().await;

        // Step 4: Deliver with circuit breaker + retry
        let mut attempt: u8 = 0;
        #[allow(unused_assignments)]
        let mut last_error: Option<String> = None;

        loop {
            // Check circuit breaker (scope ensures MutexGuard is dropped before any await)
            let cb_allows = {
                let mut cb = self.circuit_breaker.lock().await;
                cb.can_attempt()
            };

            if !cb_allows {
                tracing::warn!(
                    "Circuit breaker open for event {}; queuing for retry",
                    event.event_id
                );
                if self.retry_policy.is_dead_letter(attempt) {
                    return PipelineResult {
                        delivered: false,
                        latency_ms: None,
                        retry_count: attempt,
                        dead_lettered: true,
                        error: Some("Circuit breaker open — delivery exhausted".to_string()),
                    };
                }
                let delay = self.retry_policy.next_delay(attempt);
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }

            // Attempt delivery (no MutexGuard held across this await)
            let result = self.worker.deliver(&payload).await;

            match result {
                Ok(ref delivery_result) if delivery_result.success => {
                    {
                        let mut cb = self.circuit_breaker.lock().await;
                        cb.record_success();
                    }
                    return PipelineResult {
                        delivered: true,
                        latency_ms: Some(delivery_result.latency_ms),
                        retry_count: attempt,
                        dead_lettered: false,
                        error: None,
                    };
                }
                Ok(ref delivery_result) => {
                    last_error = delivery_result.error.clone();
                    let mut cb = self.circuit_breaker.lock().await;
                    cb.record_failure();
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                    let mut cb = self.circuit_breaker.lock().await;
                    cb.record_failure();
                }
            }

            attempt += 1;

            if self.retry_policy.is_dead_letter(attempt) {
                let err_msg =
                    last_error.unwrap_or_else(|| "Delivery failed after max retries".to_string());
                tracing::error!(
                    "Event {} dead-lettered after {} attempts: {}",
                    event.event_id,
                    attempt,
                    err_msg
                );
                return PipelineResult {
                    delivered: false,
                    latency_ms: None,
                    retry_count: attempt,
                    dead_lettered: true,
                    error: Some(err_msg),
                };
            }

            // Exponential backoff before retry
            let delay = self.retry_policy.next_delay(attempt - 1);
            tracing::debug!(
                "Retrying event {} (attempt {}/{}), delay {:?}",
                event.event_id,
                attempt,
                self.retry_policy.max_retries(),
                delay
            );
            tokio::time::sleep(delay).await;
        }
    }

    /// Check if the event matches this destination's event type filter.
    fn matches_filter(&self, event: &SiemEvent) -> bool {
        if self.config.event_type_filter.is_empty() {
            return true;
        }

        // Match by event type string or category name
        let category_str = event.category.as_str();
        self.config.event_type_filter.iter().any(|filter| {
            filter == &event.event_type
                || filter.eq_ignore_ascii_case(category_str)
                || filter == "*"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryError, DeliveryResult as DR};
    use crate::models::{EventCategory, ExportFormat, SiemEvent};
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use uuid::Uuid;

    /// Mock delivery worker for testing.
    struct MockWorker {
        succeed_after: AtomicU32,
        call_count: AtomicU32,
    }

    impl MockWorker {
        fn always_succeed() -> Self {
            Self {
                succeed_after: AtomicU32::new(0),
                call_count: AtomicU32::new(0),
            }
        }

        fn succeed_after(n: u32) -> Self {
            Self {
                succeed_after: AtomicU32::new(n),
                call_count: AtomicU32::new(0),
            }
        }

        fn always_fail() -> Self {
            Self {
                succeed_after: AtomicU32::new(u32::MAX),
                call_count: AtomicU32::new(0),
            }
        }

        #[allow(dead_code)]
        fn calls(&self) -> u32 {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl DeliveryWorker for MockWorker {
        async fn deliver(&self, _payload: &str) -> Result<DR, DeliveryError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            let threshold = self.succeed_after.load(Ordering::SeqCst);
            if count >= threshold {
                Ok(DR::success(5))
            } else {
                Ok(DR::failure(5, "Mock delivery failure".to_string()))
            }
        }
    }

    fn test_event() -> SiemEvent {
        SiemEvent {
            event_id: Uuid::new_v4(),
            event_type: "AUTH_LOGIN_SUCCESS".to_string(),
            category: EventCategory::Authentication,
            tenant_id: Uuid::new_v4(),
            actor_id: Some(Uuid::new_v4()),
            actor_email: Some("test@example.com".to_string()),
            timestamp: Utc::now(),
            severity: 3,
            event_name: "Login Success".to_string(),
            source_ip: Some("10.0.0.1".to_string()),
            target_user: None,
            target_resource: None,
            action: "login".to_string(),
            outcome: "Success".to_string(),
            reason: None,
            session_id: Some(Uuid::new_v4()),
            request_id: Some("req-123".to_string()),
            metadata: HashMap::new(),
        }
    }

    fn default_config() -> PipelineConfig {
        PipelineConfig {
            export_format: ExportFormat::Json,
            event_type_filter: vec![],
            rate_limit_per_second: 10000,
            circuit_breaker_threshold: 5,
            circuit_breaker_cooldown_secs: 1,
        }
    }

    #[tokio::test]
    async fn test_successful_delivery() {
        let worker = MockWorker::always_succeed();
        let pipeline = ExportPipeline::new(Box::new(worker), default_config());
        let event = test_event();

        let result = pipeline.process_event(&event).await;
        assert!(result.delivered);
        assert_eq!(result.retry_count, 0);
        assert!(!result.dead_lettered);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_filtered_event_skipped() {
        let worker = MockWorker::always_succeed();
        let mut config = default_config();
        config.event_type_filter = vec!["security".to_string()];
        let pipeline = ExportPipeline::new(Box::new(worker), config);

        let event = test_event(); // Authentication category
        let result = pipeline.process_event(&event).await;
        assert!(!result.delivered);
        assert!(!result.dead_lettered);
    }

    #[tokio::test]
    async fn test_filter_matches_category() {
        let worker = MockWorker::always_succeed();
        let mut config = default_config();
        config.event_type_filter = vec!["authentication".to_string()];
        let pipeline = ExportPipeline::new(Box::new(worker), config);

        let event = test_event();
        let result = pipeline.process_event(&event).await;
        assert!(result.delivered);
    }

    #[tokio::test]
    async fn test_filter_matches_event_type() {
        let worker = MockWorker::always_succeed();
        let mut config = default_config();
        config.event_type_filter = vec!["AUTH_LOGIN_SUCCESS".to_string()];
        let pipeline = ExportPipeline::new(Box::new(worker), config);

        let event = test_event();
        let result = pipeline.process_event(&event).await;
        assert!(result.delivered);
    }

    #[tokio::test]
    async fn test_retry_then_succeed() {
        let worker = MockWorker::succeed_after(2); // Fail first 2, succeed on 3rd
        let pipeline = ExportPipeline::new(Box::new(worker), default_config());
        let event = test_event();

        let result = pipeline.process_event(&event).await;
        assert!(result.delivered);
        assert_eq!(result.retry_count, 2);
        assert!(!result.dead_lettered);
    }

    #[tokio::test]
    async fn test_dead_letter_after_max_retries() {
        let worker = MockWorker::always_fail();
        let pipeline = ExportPipeline::new(Box::new(worker), default_config());
        let event = test_event();

        let result = pipeline.process_event(&event).await;
        assert!(!result.delivered);
        assert!(result.dead_lettered);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_wildcard_filter() {
        let worker = MockWorker::always_succeed();
        let mut config = default_config();
        config.event_type_filter = vec!["*".to_string()];
        let pipeline = ExportPipeline::new(Box::new(worker), config);

        let event = test_event();
        let result = pipeline.process_event(&event).await;
        assert!(result.delivered);
    }

    #[tokio::test]
    async fn test_empty_filter_accepts_all() {
        let worker = MockWorker::always_succeed();
        let pipeline = ExportPipeline::new(Box::new(worker), default_config());
        let event = test_event();

        let result = pipeline.process_event(&event).await;
        assert!(result.delivered);
    }
}
