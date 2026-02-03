//! Webhook delivery system for identity lifecycle event subscriptions.
//!
//! Provides tenant-scoped webhook subscription management, async delivery with
//! HMAC-SHA256 signing, exponential backoff retries, and delivery tracking.
//!
//! ## Circuit Breaker
//!
//! The circuit breaker pattern protects against failing endpoints by temporarily
//! blocking requests after a threshold of consecutive failures. States:
//! - **Closed**: Normal operation, requests proceed
//! - **Open**: Circuit tripped, requests immediately rejected
//! - **Half-Open**: Recovery probe, allows one request to test endpoint health
//!
//! ## Dead Letter Queue
//!
//! Failed webhooks that exhaust all retry attempts are moved to the DLQ for
//! manual investigation and replay. The DLQ preserves full delivery context
//! including the original payload and attempt history.
//!
//! ## Rate Limiting
//!
//! Per-destination rate limiting using a token bucket algorithm prevents
//! overwhelming webhook endpoints with too many concurrent requests.

pub mod circuit_breaker;
pub mod crypto;
pub mod error;
pub mod handlers;
pub mod models;
pub mod rate_limiter;
pub mod router;
pub mod services;
pub mod validation;
pub mod worker;

pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerRegistry, CircuitBreakerStatus,
    CircuitState, FailureRecord,
};
pub use error::WebhookError;
pub use models::WebhookEventType;
pub use rate_limiter::{RateLimitConfig, RateLimitResult, RateLimiter, RateLimiterRegistry};
pub use router::{webhooks_router, WebhooksState};
pub use services::dlq_service::{
    AttemptRecord as DlqAttemptRecord, BulkReplayRequest, BulkReplayResponse, DlqEntryDetail,
    DlqEntryList, DlqEntrySummary, DlqService, ReplayResponse,
};
pub use services::event_publisher::{EventPublisher, WebhookEvent};
pub use worker::WebhookWorker;
