//! Background delivery worker.
//!
//! Runs two concurrent loops:
//! 1. Event receiver loop — processes incoming events from the broadcast channel
//! 2. Retry poll loop — picks up pending deliveries ready for retry every 30 seconds

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::services::delivery_service::DeliveryService;
use crate::services::event_publisher::WebhookEvent;
use xavyo_db::models::WebhookDelivery;

/// Maximum concurrent retry deliveries per poll cycle.
const MAX_CONCURRENT_RETRIES: usize = 50;

/// Retry poll interval in seconds.
const RETRY_POLL_INTERVAL_SECS: u64 = 30;

/// Maximum pending deliveries to fetch per poll cycle.
const RETRY_BATCH_SIZE: i64 = 100;

/// Background worker that processes webhook events and retries.
pub struct WebhookWorker {
    delivery_service: DeliveryService,
    event_rx: broadcast::Receiver<WebhookEvent>,
    cancellation_token: CancellationToken,
}

impl WebhookWorker {
    /// Create a new webhook worker.
    pub fn new(
        delivery_service: DeliveryService,
        event_rx: broadcast::Receiver<WebhookEvent>,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            delivery_service,
            event_rx,
            cancellation_token,
        }
    }

    /// Run the worker — spawns event receiver and retry poller as concurrent tasks.
    pub async fn run(self) {
        tracing::info!(target: "webhook_delivery", "Webhook delivery worker started");

        let token = self.cancellation_token.clone();
        let delivery_service = self.delivery_service.clone();
        let event_rx = self.event_rx;

        // Spawn event receiver loop
        let event_token = token.clone();
        let event_service = delivery_service.clone();
        let event_handle = tokio::spawn(async move {
            run_event_receiver(event_service, event_rx, event_token).await;
        });

        // Spawn retry poll loop
        let retry_token = token.clone();
        let retry_service = delivery_service.clone();
        let retry_handle = tokio::spawn(async move {
            run_retry_poller(retry_service, retry_token).await;
        });

        // Wait for either task to complete (both should only stop on cancellation)
        tokio::select! {
            _ = event_handle => {
                tracing::info!(target: "webhook_delivery", "Event receiver loop ended");
            }
            _ = retry_handle => {
                tracing::info!(target: "webhook_delivery", "Retry poller loop ended");
            }
            _ = token.cancelled() => {
                tracing::info!(target: "webhook_delivery", "Webhook delivery worker shutdown requested");
            }
        }

        tracing::info!(target: "webhook_delivery", "Webhook delivery worker stopped");
    }
}

/// Event receiver loop — listens for broadcast events and delivers them.
async fn run_event_receiver(
    delivery_service: DeliveryService,
    mut event_rx: broadcast::Receiver<WebhookEvent>,
    token: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::info!(target: "webhook_delivery", "Event receiver shutting down");
                break;
            }
            result = event_rx.recv() => {
                match result {
                    Ok(event) => {
                        tracing::debug!(
                            target: "webhook_delivery",
                            event_id = %event.event_id,
                            event_type = %event.event_type,
                            tenant_id = %event.tenant_id,
                            "Received event for webhook delivery"
                        );
                        delivery_service.deliver_event(&event).await;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            target: "webhook_delivery",
                            skipped = n,
                            "Webhook event receiver lagged — skipped {n} events"
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::info!(
                            target: "webhook_delivery",
                            "Event broadcast channel closed — receiver shutting down"
                        );
                        break;
                    }
                }
            }
        }
    }
}

/// Retry poller loop — periodically checks for pending deliveries ready for retry.
async fn run_retry_poller(delivery_service: DeliveryService, token: CancellationToken) {
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(RETRY_POLL_INTERVAL_SECS));
    // Don't burst on startup
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::info!(target: "webhook_delivery", "Retry poller shutting down");
                break;
            }
            _ = interval.tick() => {
                process_pending_retries(&delivery_service).await;
            }
        }
    }
}

/// Fetch and process pending deliveries with bounded concurrency.
async fn process_pending_retries(delivery_service: &DeliveryService) {
    let deliveries =
        match WebhookDelivery::find_pending_for_retry(delivery_service.pool(), RETRY_BATCH_SIZE)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(
                    target: "webhook_delivery",
                    error = %e,
                    "Failed to query pending retries"
                );
                return;
            }
        };

    if deliveries.is_empty() {
        return;
    }

    tracing::info!(
        target: "webhook_delivery",
        count = deliveries.len(),
        "Processing pending webhook retries"
    );

    // Process with bounded concurrency using a semaphore
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RETRIES));
    let mut handles = Vec::with_capacity(deliveries.len());

    for delivery in deliveries {
        let sem = semaphore.clone();
        let service = delivery_service.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            service.process_retry(&delivery).await;
        });

        handles.push(handle);
    }

    // Wait for all retries to complete
    for handle in handles {
        if let Err(e) = handle.await {
            tracing::error!(
                target: "webhook_delivery",
                error = %e,
                "Retry task panicked"
            );
        }
    }
}
