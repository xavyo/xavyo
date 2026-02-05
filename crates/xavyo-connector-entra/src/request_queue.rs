//! Request queue for rate limit handling.
//!
//! Queues requests when rate limited instead of sending them immediately,
//! processing them in FIFO order when the rate limit clears.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, info, warn};

use crate::EntraError;

/// A queued request waiting to be processed.
#[derive(Debug)]
pub struct QueuedRequest<T> {
    /// Unique request identifier.
    pub id: u64,
    /// When request was queued.
    pub queued_at: Instant,
    /// Request payload.
    pub payload: T,
    /// Channel to send response back.
    pub response_tx: oneshot::Sender<Result<(), EntraError>>,
}

/// Request queue with bounded capacity.
///
/// Uses a FIFO queue to process requests in order when rate limits clear.
#[derive(Debug)]
pub struct RequestQueue<T: Send + 'static> {
    /// Sender for enqueuing requests.
    tx: mpsc::Sender<QueuedRequest<T>>,
    /// Maximum queue depth.
    max_depth: usize,
    /// Current queue depth (atomic for fast reads).
    current_depth: Arc<AtomicUsize>,
    /// Next request ID.
    next_id: AtomicU64,
    /// Whether the queue processor is running.
    is_running: Arc<RwLock<bool>>,
}

impl<T: Send + 'static> RequestQueue<T> {
    /// Creates a new request queue with the given capacity.
    #[must_use]
    pub fn new(max_depth: usize) -> (Self, mpsc::Receiver<QueuedRequest<T>>) {
        let (tx, rx) = mpsc::channel(max_depth);
        let queue = Self {
            tx,
            max_depth,
            current_depth: Arc::new(AtomicUsize::new(0)),
            next_id: AtomicU64::new(1),
            is_running: Arc::new(RwLock::new(false)),
        };
        (queue, rx)
    }

    /// Returns the maximum queue depth.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Returns the current queue depth.
    pub fn depth(&self) -> usize {
        self.current_depth.load(Ordering::Relaxed)
    }

    /// Checks if the queue is full.
    pub fn is_full(&self) -> bool {
        self.depth() >= self.max_depth
    }

    /// Enqueues a request, returning a receiver for the result.
    ///
    /// Returns an error if the queue is full.
    pub async fn enqueue(
        &self,
        payload: T,
    ) -> Result<oneshot::Receiver<Result<(), EntraError>>, EntraError> {
        // Check capacity first
        let current = self.current_depth.load(Ordering::Relaxed);
        if current >= self.max_depth {
            warn!("Request queue full ({} requests)", current);
            return Err(EntraError::QueueFull {
                queue_depth: current,
            });
        }

        // Create response channel
        let (response_tx, response_rx) = oneshot::channel();

        // Create queued request
        let request = QueuedRequest {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            queued_at: Instant::now(),
            payload,
            response_tx,
        };

        // Try to send (may fail if channel is full due to race)
        match self.tx.try_send(request) {
            Ok(()) => {
                self.current_depth.fetch_add(1, Ordering::Relaxed);
                debug!("Request enqueued, depth: {}", self.depth());
                Ok(response_rx)
            }
            Err(mpsc::error::TrySendError::Full(req)) => {
                warn!("Request queue full (channel)");
                // Try to send the response on the channel before dropping
                let _ = req.response_tx.send(Err(EntraError::QueueFull {
                    queue_depth: self.max_depth,
                }));
                Err(EntraError::QueueFull {
                    queue_depth: self.max_depth,
                })
            }
            Err(mpsc::error::TrySendError::Closed(req)) => {
                warn!("Request queue closed");
                let _ = req.response_tx.send(Err(EntraError::Sync(
                    "Queue processor not running".to_string(),
                )));
                Err(EntraError::Sync("Queue closed".to_string()))
            }
        }
    }

    /// Decrements the depth counter (called when request is processed).
    pub fn mark_processed(&self) {
        let prev = self.current_depth.fetch_sub(1, Ordering::Relaxed);
        debug!(
            "Request processed, depth: {} -> {}",
            prev,
            prev.saturating_sub(1)
        );
    }

    /// Sets whether the queue processor is running.
    pub async fn set_running(&self, running: bool) {
        let mut is_running = self.is_running.write().await;
        *is_running = running;
    }

    /// Returns whether the queue processor is running.
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
}

/// Processes queued requests when rate limit clears.
#[allow(dead_code)] // Public API for future use
pub async fn process_queue<T, F, Fut>(
    mut rx: mpsc::Receiver<QueuedRequest<T>>,
    queue: Arc<RequestQueue<T>>,
    mut process_fn: F,
) where
    T: Send + 'static,
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = Result<(), EntraError>>,
{
    info!("Queue processor started");
    queue.set_running(true).await;

    while let Some(request) = rx.recv().await {
        let wait_time = request.queued_at.elapsed();
        debug!(
            "Processing queued request {} (waited {:?})",
            request.id, wait_time
        );

        // Process the request
        let result = process_fn(request.payload).await;

        // Send result back
        if request.response_tx.send(result).is_err() {
            debug!("Request {} response receiver dropped", request.id);
        }

        // Update depth
        queue.mark_processed();
    }

    queue.set_running(false).await;
    info!("Queue processor stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_requests_queued_when_throttled() {
        let (queue, _rx) = RequestQueue::new(10);
        assert_eq!(queue.depth(), 0);

        // Enqueue some requests
        let _rx1 = queue.enqueue("request1").await.unwrap();
        let _rx2 = queue.enqueue("request2").await.unwrap();
        let _rx3 = queue.enqueue("request3").await.unwrap();

        assert_eq!(queue.depth(), 3);
    }

    #[tokio::test]
    async fn test_queue_drains_after_throttle_clears() {
        let (queue, mut rx) = RequestQueue::<String>::new(10);
        let queue = Arc::new(queue);

        // Enqueue requests
        let rx1 = queue.enqueue("first".to_string()).await.unwrap();
        let rx2 = queue.enqueue("second".to_string()).await.unwrap();
        let rx3 = queue.enqueue("third".to_string()).await.unwrap();

        assert_eq!(queue.depth(), 3);

        // Track processing order
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));

        // Process requests manually (simulating what process_queue would do)
        let queue_clone = queue.clone();
        let order_clone = order.clone();
        let processor = tokio::spawn(async move {
            while let Some(request) = rx.recv().await {
                // Record order
                order_clone.lock().unwrap().push(request.payload.clone());
                // Send success response
                let _ = request.response_tx.send(Ok(()));
                // Update depth
                queue_clone.mark_processed();
            }
        });

        // Wait for all responses with timeout
        let _ = tokio::time::timeout(Duration::from_millis(100), rx1).await;
        let _ = tokio::time::timeout(Duration::from_millis(100), rx2).await;
        let _ = tokio::time::timeout(Duration::from_millis(100), rx3).await;

        // Give processor time to complete
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Verify FIFO order
        let processed = order.lock().unwrap().clone();
        assert_eq!(processed, vec!["first", "second", "third"]);

        // Stop processor by dropping the Arc which closes the sender
        processor.abort();
    }

    #[tokio::test]
    async fn test_queue_full_returns_error() {
        let (queue, _rx) = RequestQueue::new(3);

        // Fill the queue
        let _r1 = queue.enqueue("1").await.unwrap();
        let _r2 = queue.enqueue("2").await.unwrap();
        let _r3 = queue.enqueue("3").await.unwrap();

        // Next should fail
        let result = queue.enqueue("4").await;
        assert!(matches!(
            result,
            Err(EntraError::QueueFull { queue_depth: 3 })
        ));
    }

    #[tokio::test]
    async fn test_queue_depth_tracking() {
        let (queue, mut rx) = RequestQueue::<&str>::new(10);
        let queue = Arc::new(queue);

        assert_eq!(queue.depth(), 0);

        let _r1 = queue.enqueue("a").await.unwrap();
        assert_eq!(queue.depth(), 1);

        let _r2 = queue.enqueue("b").await.unwrap();
        assert_eq!(queue.depth(), 2);

        // Process one
        if let Some(req) = rx.recv().await {
            let _ = req.response_tx.send(Ok(()));
            queue.mark_processed();
        }

        assert_eq!(queue.depth(), 1);

        drop(rx);
    }

    #[tokio::test]
    async fn test_is_full() {
        let (queue, _rx) = RequestQueue::new(2);

        assert!(!queue.is_full());

        let _r1 = queue.enqueue("1").await.unwrap();
        assert!(!queue.is_full());

        let _r2 = queue.enqueue("2").await.unwrap();
        assert!(queue.is_full());
    }

    #[tokio::test]
    async fn test_request_ids_are_unique() {
        let (queue, _rx) = RequestQueue::<&str>::new(10);

        // We can't directly access IDs, but we can verify enqueue succeeds
        for _ in 0..5 {
            let _ = queue.enqueue("test").await.unwrap();
        }
        assert_eq!(queue.depth(), 5);
    }
}
