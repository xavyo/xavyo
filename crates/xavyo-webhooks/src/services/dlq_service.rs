//! Dead Letter Queue service for failed webhooks.
//!
//! Manages webhooks that have exhausted all retry attempts, providing
//! functionality to query, replay, and manage failed deliveries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::WebhookError;
use xavyo_db::models::{
    CreateWebhookDlqEntry, DlqFilter, WebhookDelivery, WebhookDlqEntry, WebhookSubscription,
};

/// Service for managing dead letter queue entries.
#[derive(Clone)]
pub struct DlqService {
    pool: PgPool,
}

/// Summary of a DLQ entry for list responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqEntrySummary {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub subscription_url: String,
    pub event_id: Uuid,
    pub event_type: String,
    pub failure_reason: String,
    pub last_response_code: Option<i16>,
    pub attempt_count: i32,
    pub created_at: DateTime<Utc>,
    pub replayed_at: Option<DateTime<Utc>>,
}

/// Detailed view of a DLQ entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqEntryDetail {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub subscription_url: String,
    pub event_id: Uuid,
    pub event_type: String,
    pub failure_reason: String,
    pub last_response_code: Option<i16>,
    pub last_response_body: Option<String>,
    pub attempt_count: i32,
    pub request_payload: serde_json::Value,
    pub attempt_history: Vec<AttemptRecord>,
    pub created_at: DateTime<Utc>,
    pub replayed_at: Option<DateTime<Utc>>,
}

/// Record of a delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub attempt_number: i32,
    pub timestamp: DateTime<Utc>,
    pub error: String,
    pub response_code: Option<i16>,
    pub latency_ms: Option<i32>,
}

/// Paginated list of DLQ entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqEntryList {
    pub entries: Vec<DlqEntrySummary>,
    pub total: i64,
    pub has_more: bool,
}

/// Response from replay operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResponse {
    pub delivery_id: Uuid,
    pub status: String,
    pub message: String,
}

/// Response from bulk replay operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkReplayResponse {
    pub replayed_count: i64,
    pub delivery_ids: Vec<Uuid>,
    pub message: String,
}

/// Request for bulk replay.
#[derive(Debug, Clone, Deserialize)]
pub struct BulkReplayRequest {
    pub subscription_id: Option<Uuid>,
    pub event_type: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub ids: Option<Vec<Uuid>>,
}

impl DlqService {
    /// Create a new DLQ service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Add a failed delivery to the DLQ.
    pub async fn add_to_dlq(
        &self,
        tenant_id: Uuid,
        delivery: &WebhookDelivery,
        subscription: &WebhookSubscription,
        failure_reason: String,
        last_response_code: Option<i16>,
        last_response_body: Option<String>,
        attempt_history: Vec<AttemptRecord>,
    ) -> Result<WebhookDlqEntry, WebhookError> {
        let attempt_history_json = serde_json::to_value(&attempt_history).map_err(|e| {
            WebhookError::Internal(format!("Failed to serialize attempt history: {e}"))
        })?;

        let entry = WebhookDlqEntry::create(
            &self.pool,
            CreateWebhookDlqEntry {
                tenant_id,
                subscription_id: subscription.id,
                subscription_url: subscription.url.clone(),
                event_id: delivery.event_id,
                event_type: delivery.event_type.clone(),
                request_payload: delivery.request_payload.clone(),
                failure_reason,
                last_response_code,
                last_response_body,
                attempt_history: attempt_history_json,
            },
        )
        .await?;

        tracing::info!(
            target: "dlq",
            dlq_id = %entry.id,
            delivery_id = %delivery.id,
            subscription_id = %subscription.id,
            tenant_id = %tenant_id,
            event_id = %delivery.event_id,
            "Webhook moved to dead letter queue"
        );

        Ok(entry)
    }

    /// List DLQ entries with filtering and pagination.
    pub async fn list_entries(
        &self,
        tenant_id: Uuid,
        filter: DlqFilter,
        limit: i64,
        offset: i64,
    ) -> Result<DlqEntryList, WebhookError> {
        let limit = limit.clamp(1, 100);
        let offset = offset.max(0);

        let entries = WebhookDlqEntry::list(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = WebhookDlqEntry::count(&self.pool, tenant_id, &filter).await?;

        let summaries: Vec<DlqEntrySummary> = entries
            .into_iter()
            .map(|e| {
                let attempt_count = extract_attempt_count(&e.attempt_history);
                DlqEntrySummary {
                    id: e.id,
                    subscription_id: e.subscription_id,
                    subscription_url: e.subscription_url,
                    event_id: e.event_id,
                    event_type: e.event_type,
                    failure_reason: e.failure_reason,
                    last_response_code: e.last_response_code,
                    attempt_count,
                    created_at: e.created_at,
                    replayed_at: e.replayed_at,
                }
            })
            .collect();

        let has_more = (offset + limit) < total;

        Ok(DlqEntryList {
            entries: summaries,
            total,
            has_more,
        })
    }

    /// Get detailed information about a DLQ entry.
    pub async fn get_entry_detail(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<DlqEntryDetail, WebhookError> {
        let entry = WebhookDlqEntry::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(WebhookError::DlqEntryNotFound)?;

        let attempt_history: Vec<AttemptRecord> =
            serde_json::from_value(entry.attempt_history.clone()).unwrap_or_default();

        Ok(DlqEntryDetail {
            id: entry.id,
            subscription_id: entry.subscription_id,
            subscription_url: entry.subscription_url,
            event_id: entry.event_id,
            event_type: entry.event_type,
            failure_reason: entry.failure_reason,
            last_response_code: entry.last_response_code,
            last_response_body: entry.last_response_body,
            attempt_count: attempt_history.len() as i32,
            request_payload: entry.request_payload,
            attempt_history,
            created_at: entry.created_at,
            replayed_at: entry.replayed_at,
        })
    }

    /// Replay a single DLQ entry.
    ///
    /// Creates a new delivery record for the webhook and marks the DLQ entry as replayed.
    pub async fn replay_single(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<ReplayResponse, WebhookError> {
        let entry = WebhookDlqEntry::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(WebhookError::DlqEntryNotFound)?;

        if entry.replayed_at.is_some() {
            return Err(WebhookError::DlqEntryAlreadyReplayed);
        }

        // Verify subscription still exists and is enabled
        let subscription =
            WebhookSubscription::find_by_id(&self.pool, tenant_id, entry.subscription_id)
                .await?
                .ok_or(WebhookError::SubscriptionNotFound)?;

        if !subscription.enabled {
            return Err(WebhookError::Validation(
                "Cannot replay to disabled subscription".to_string(),
            ));
        }

        // Create a new delivery record
        let delivery = WebhookDelivery::create(
            &self.pool,
            xavyo_db::models::CreateWebhookDelivery {
                tenant_id,
                subscription_id: entry.subscription_id,
                event_id: entry.event_id,
                event_type: entry.event_type.clone(),
                request_payload: entry.request_payload.clone(),
                max_attempts: 6, // Default max attempts for replay
                next_attempt_at: Some(Utc::now()),
            },
        )
        .await?;

        // Mark the DLQ entry as replayed
        WebhookDlqEntry::mark_replayed(&self.pool, tenant_id, id).await?;

        tracing::info!(
            target: "dlq",
            dlq_id = %id,
            delivery_id = %delivery.id,
            subscription_id = %entry.subscription_id,
            tenant_id = %tenant_id,
            "DLQ entry replayed"
        );

        Ok(ReplayResponse {
            delivery_id: delivery.id,
            status: "pending".to_string(),
            message: "Webhook re-queued for delivery".to_string(),
        })
    }

    /// Replay multiple DLQ entries matching the filter criteria.
    pub async fn replay_bulk(
        &self,
        tenant_id: Uuid,
        request: BulkReplayRequest,
    ) -> Result<BulkReplayResponse, WebhookError> {
        // If specific IDs provided, use those
        if let Some(ids) = &request.ids {
            if ids.len() > 100 {
                return Err(WebhookError::InvalidDlqFilter(
                    "Maximum 100 IDs per bulk replay".to_string(),
                ));
            }

            let mut replayed_count = 0i64;
            let mut delivery_ids = Vec::new();

            for id in ids {
                match self.replay_single(tenant_id, *id).await {
                    Ok(response) => {
                        replayed_count += 1;
                        delivery_ids.push(response.delivery_id);
                    }
                    Err(WebhookError::DlqEntryNotFound | WebhookError::DlqEntryAlreadyReplayed) => {
                        // Skip entries that don't exist or are already replayed
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "dlq",
                            dlq_id = %id,
                            error = %e,
                            "Failed to replay DLQ entry"
                        );
                    }
                }
            }

            return Ok(BulkReplayResponse {
                replayed_count,
                delivery_ids,
                message: format!("Replayed {} webhooks", replayed_count),
            });
        }

        // Use subscription_id filter for bulk replay
        let subscription_id = request
            .subscription_id
            .ok_or(WebhookError::InvalidDlqFilter(
                "Either ids or subscription_id required for bulk replay".to_string(),
            ))?;

        // Verify subscription exists and is enabled
        let subscription = WebhookSubscription::find_by_id(&self.pool, tenant_id, subscription_id)
            .await?
            .ok_or(WebhookError::SubscriptionNotFound)?;

        if !subscription.enabled {
            return Err(WebhookError::Validation(
                "Cannot replay to disabled subscription".to_string(),
            ));
        }

        // Get unreplayed entries for the subscription
        let entries = WebhookDlqEntry::find_unreplayed_by_subscription(
            &self.pool,
            tenant_id,
            subscription_id,
            100, // Limit per batch
        )
        .await?;

        let mut replayed_count = 0i64;
        let mut delivery_ids = Vec::new();

        for entry in entries {
            // Apply additional filters if provided
            if let Some(ref event_type) = request.event_type {
                if &entry.event_type != event_type {
                    continue;
                }
            }
            if let Some(from) = request.from {
                if entry.created_at < from {
                    continue;
                }
            }
            if let Some(to) = request.to {
                if entry.created_at > to {
                    continue;
                }
            }

            match self.replay_single(tenant_id, entry.id).await {
                Ok(response) => {
                    replayed_count += 1;
                    delivery_ids.push(response.delivery_id);
                }
                Err(e) => {
                    tracing::warn!(
                        target: "dlq",
                        dlq_id = %entry.id,
                        error = %e,
                        "Failed to replay DLQ entry"
                    );
                }
            }
        }

        Ok(BulkReplayResponse {
            replayed_count,
            delivery_ids,
            message: format!(
                "Replayed {} webhooks for subscription {}",
                replayed_count, subscription_id
            ),
        })
    }

    /// Delete a DLQ entry.
    pub async fn delete_entry(&self, tenant_id: Uuid, id: Uuid) -> Result<bool, WebhookError> {
        let deleted = WebhookDlqEntry::delete(&self.pool, tenant_id, id).await?;

        if deleted {
            tracing::info!(
                target: "dlq",
                dlq_id = %id,
                tenant_id = %tenant_id,
                "DLQ entry deleted"
            );
        }

        Ok(deleted)
    }
}

/// Extract attempt count from attempt history JSON.
fn extract_attempt_count(history: &serde_json::Value) -> i32 {
    history.as_array().map(|arr| arr.len() as i32).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_attempt_count_array() {
        let history = serde_json::json!([
            {"attempt_number": 1},
            {"attempt_number": 2},
            {"attempt_number": 3}
        ]);
        assert_eq!(extract_attempt_count(&history), 3);
    }

    #[test]
    fn test_extract_attempt_count_empty() {
        let history = serde_json::json!([]);
        assert_eq!(extract_attempt_count(&history), 0);
    }

    #[test]
    fn test_extract_attempt_count_invalid() {
        let history = serde_json::json!({});
        assert_eq!(extract_attempt_count(&history), 0);
    }

    #[test]
    fn test_dlq_entry_summary() {
        let summary = DlqEntrySummary {
            id: Uuid::new_v4(),
            subscription_id: Uuid::new_v4(),
            subscription_url: "https://example.com/webhook".to_string(),
            event_id: Uuid::new_v4(),
            event_type: "user.created".to_string(),
            failure_reason: "Connection timeout".to_string(),
            last_response_code: Some(504),
            attempt_count: 6,
            created_at: Utc::now(),
            replayed_at: None,
        };

        assert_eq!(summary.attempt_count, 6);
        assert!(summary.replayed_at.is_none());
    }
}
