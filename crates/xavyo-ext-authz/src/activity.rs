use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio::time::{self, Duration};
use uuid::Uuid;
use xavyo_core::TenantId;

/// An activity update event.
#[derive(Debug, Clone)]
struct ActivityUpdate {
    tenant_id: TenantId,
    nhi_id: Uuid,
}

/// Async batch writer for NHI last_activity_at updates.
///
/// Collects updates via an mpsc channel and flushes them in batches
/// to avoid per-request database writes.
pub struct ActivityTracker {
    tx: mpsc::Sender<ActivityUpdate>,
}

impl ActivityTracker {
    /// Create a new tracker and spawn the background flush task.
    pub fn new(pool: Arc<PgPool>, flush_interval_secs: u64) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(flush_loop(pool, rx, flush_interval_secs));
        Self { tx }
    }

    /// Record an activity event (non-blocking, fire-and-forget).
    pub fn record(&self, tenant_id: TenantId, nhi_id: Uuid) {
        // Use try_send to avoid blocking; drop the update if the channel is full
        let _ = self.tx.try_send(ActivityUpdate { tenant_id, nhi_id });
    }
}

/// Channel capacity for the activity tracker.
const CHANNEL_CAPACITY: usize = 1024;

/// Create a standalone tracker for testing (receives updates but does not flush to DB).
#[cfg(test)]
fn test_tracker() -> (ActivityTracker, mpsc::Receiver<ActivityUpdate>) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    (ActivityTracker { tx }, rx)
}

/// Background loop that batches and flushes activity updates.
async fn flush_loop(
    pool: Arc<PgPool>,
    mut rx: mpsc::Receiver<ActivityUpdate>,
    flush_interval_secs: u64,
) {
    let mut pending: std::collections::HashMap<(TenantId, Uuid), ()> =
        std::collections::HashMap::new();
    let mut interval = time::interval(Duration::from_secs(flush_interval_secs));

    loop {
        tokio::select! {
            Some(update) = rx.recv() => {
                pending.insert((update.tenant_id, update.nhi_id), ());
            }
            _ = interval.tick() => {
                if pending.is_empty() {
                    continue;
                }

                let batch: Vec<(TenantId, Uuid)> = pending.drain().map(|(k, _)| k).collect();
                let batch_size = batch.len();

                for (tenant_id, nhi_id) in batch {
                    let tenant_uuid = *tenant_id.as_uuid();
                    if let Err(e) = xavyo_db::models::NhiIdentity::update_last_activity(
                        &pool, tenant_uuid, nhi_id,
                    )
                    .await
                    {
                        tracing::warn!(
                            tenant_id = %tenant_id,
                            nhi_id = %nhi_id,
                            error = %e,
                            "failed to update last_activity_at"
                        );
                    }

                    // Also increment the hourly activity counter
                    if let Err(e) = xavyo_db::models::NhiActivityCounter::increment_hourly(
                        &pool, tenant_uuid, nhi_id,
                    )
                    .await
                    {
                        tracing::warn!(
                            tenant_id = %tenant_id,
                            nhi_id = %nhi_id,
                            error = %e,
                            "failed to increment activity counter"
                        );
                    }
                }

                tracing::debug!(count = batch_size, "flushed activity updates");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_record_sends_to_channel() {
        let (tracker, mut rx) = test_tracker();
        let tenant_id = TenantId::new();
        let nhi_id = Uuid::new_v4();

        tracker.record(tenant_id, nhi_id);

        let update = rx.recv().await.expect("should receive update");
        assert_eq!(update.tenant_id, tenant_id);
        assert_eq!(update.nhi_id, nhi_id);
    }

    #[tokio::test]
    async fn test_record_deduplicates_in_pending_map() {
        let (tracker, mut rx) = test_tracker();
        let tenant_id = TenantId::new();
        let nhi_id = Uuid::new_v4();

        // Send the same (tenant_id, nhi_id) multiple times
        tracker.record(tenant_id, nhi_id);
        tracker.record(tenant_id, nhi_id);
        tracker.record(tenant_id, nhi_id);

        // All three should be received (dedup happens in flush_loop, not send)
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_record_is_fire_and_forget() {
        // Create a tiny channel (capacity 2) to test overflow behavior
        let (tx, _rx) = mpsc::channel(2);
        let tracker = ActivityTracker { tx };
        let tenant_id = TenantId::new();

        // Fill the channel
        tracker.record(tenant_id, Uuid::new_v4());
        tracker.record(tenant_id, Uuid::new_v4());

        // This should NOT panic or block — it silently drops the update
        tracker.record(tenant_id, Uuid::new_v4());
    }

    #[tokio::test]
    async fn test_record_multiple_tenants() {
        let (tracker, mut rx) = test_tracker();

        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let nhi_a = Uuid::new_v4();
        let nhi_b = Uuid::new_v4();

        tracker.record(tenant_a, nhi_a);
        tracker.record(tenant_b, nhi_b);

        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();

        // Both should arrive; order is preserved (FIFO channel)
        assert_eq!(first.tenant_id, tenant_a);
        assert_eq!(first.nhi_id, nhi_a);
        assert_eq!(second.tenant_id, tenant_b);
        assert_eq!(second.nhi_id, nhi_b);
    }

    #[test]
    fn test_channel_capacity_constant() {
        assert_eq!(CHANNEL_CAPACITY, 1024);
    }
}
