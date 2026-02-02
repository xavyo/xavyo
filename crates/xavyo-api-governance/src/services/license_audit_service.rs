//! License Audit Service (F065).
//!
//! Provides business logic for recording and querying license management
//! audit events for compliance reporting.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovLicenseAuditEvent, GovLicenseAuditEvent, GovLicensePool, LicenseAuditAction,
    LicenseAuditEventFilter, LicenseAuditEventWithDetails,
};
use xavyo_governance::error::Result;

/// Service for license audit operations.
pub struct LicenseAuditService {
    pool: PgPool,
}

/// Parameters for recording a pool-related audit event.
#[derive(Debug, Clone)]
pub struct RecordPoolEventParams {
    pub pool_id: Uuid,
    pub action: LicenseAuditAction,
    pub actor_id: Uuid,
    pub details: Option<serde_json::Value>,
}

/// Parameters for recording an assignment-related audit event.
#[derive(Debug, Clone)]
pub struct RecordAssignmentEventParams {
    pub pool_id: Uuid,
    pub assignment_id: Uuid,
    pub user_id: Uuid,
    pub action: LicenseAuditAction,
    pub actor_id: Uuid,
    pub details: Option<serde_json::Value>,
}

/// Parameters for recording a bulk operation audit event.
#[derive(Debug, Clone)]
pub struct RecordBulkEventParams {
    pub pool_id: Uuid,
    pub action: LicenseAuditAction,
    pub actor_id: Uuid,
    pub affected_user_ids: Option<Vec<Uuid>>,
    pub details: Option<serde_json::Value>,
}

/// Filter parameters for listing audit events.
#[derive(Debug, Clone, Default)]
pub struct ListAuditParams {
    pub pool_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub action: Option<LicenseAuditAction>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}

/// Audit event entry for API responses.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LicenseAuditEntry {
    pub id: Uuid,
    pub pool_id: Option<Uuid>,
    pub pool_name: Option<String>,
    pub assignment_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub user_email: Option<String>,
    pub action: String,
    pub actor_id: Uuid,
    pub actor_email: Option<String>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl LicenseAuditService {
    /// Create a new license audit service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Record a pool-related audit event (created, updated, archived, etc.).
    pub async fn record_pool_event(
        &self,
        tenant_id: Uuid,
        params: RecordPoolEventParams,
    ) -> Result<GovLicenseAuditEvent> {
        let input = CreateGovLicenseAuditEvent::pool_event(
            params.pool_id,
            params.action,
            params.actor_id,
            params.details.unwrap_or_else(|| serde_json::json!({})),
        );

        let saved = GovLicenseAuditEvent::create(&self.pool, tenant_id, input).await?;
        Ok(saved)
    }

    /// Record an assignment-related audit event (assigned, deallocated, reclaimed, etc.).
    pub async fn record_assignment_event(
        &self,
        tenant_id: Uuid,
        params: RecordAssignmentEventParams,
    ) -> Result<GovLicenseAuditEvent> {
        let input = CreateGovLicenseAuditEvent::assignment_event(
            params.pool_id,
            params.assignment_id,
            params.user_id,
            params.action,
            params.actor_id,
            params.details.unwrap_or_else(|| serde_json::json!({})),
        );

        let saved = GovLicenseAuditEvent::create(&self.pool, tenant_id, input).await?;
        Ok(saved)
    }

    /// Record a bulk operation audit event.
    pub async fn record_bulk_event(
        &self,
        tenant_id: Uuid,
        params: RecordBulkEventParams,
    ) -> Result<GovLicenseAuditEvent> {
        let details = params.details.unwrap_or_else(|| serde_json::json!({}));

        let input = CreateGovLicenseAuditEvent::bulk_event(
            params.pool_id,
            params.action,
            params.actor_id,
            params.affected_user_ids.unwrap_or_default(),
            details,
        );

        let saved = GovLicenseAuditEvent::create(&self.pool, tenant_id, input).await?;
        Ok(saved)
    }

    /// List audit events with filtering and pagination.
    pub async fn list_audit_events(
        &self,
        tenant_id: Uuid,
        params: ListAuditParams,
    ) -> Result<(Vec<LicenseAuditEntry>, i64)> {
        // Build the filter from params
        let filter = LicenseAuditEventFilter {
            license_pool_id: params.pool_id,
            user_id: params.user_id,
            action: params.action,
            actor_id: None,
            start_date: params.from_date,
            end_date: params.to_date,
        };

        // Use the with_details query for richer information
        let events = LicenseAuditEventWithDetails::list_with_details(
            &self.pool,
            tenant_id,
            &filter,
            params.limit,
            params.offset,
        )
        .await?;

        let total = GovLicenseAuditEvent::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        let entries = events.into_iter().map(Self::to_entry).collect();

        Ok((entries, total))
    }

    /// Get audit events for a specific pool.
    pub async fn list_by_pool(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<LicenseAuditEntry>, i64)> {
        self.list_audit_events(
            tenant_id,
            ListAuditParams {
                pool_id: Some(pool_id),
                limit,
                offset,
                ..Default::default()
            },
        )
        .await
    }

    /// Get audit events for a specific user.
    pub async fn list_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<LicenseAuditEntry>, i64)> {
        self.list_audit_events(
            tenant_id,
            ListAuditParams {
                user_id: Some(user_id),
                limit,
                offset,
                ..Default::default()
            },
        )
        .await
    }

    /// Get recent audit events (for dashboard).
    ///
    /// Uses a single batch query to resolve pool names instead of one query
    /// per event (avoids N+1).
    pub async fn get_recent(&self, tenant_id: Uuid, limit: i64) -> Result<Vec<LicenseAuditEntry>> {
        let events = GovLicenseAuditEvent::get_recent(&self.pool, tenant_id, limit).await?;

        // Collect unique non-null pool IDs for batch lookup
        let pool_ids: Vec<Uuid> = events
            .iter()
            .filter_map(|e| e.license_pool_id)
            .collect::<std::collections::HashSet<Uuid>>()
            .into_iter()
            .collect();

        // Single query to fetch all referenced pool names at once
        let pool_name_map = if pool_ids.is_empty() {
            HashMap::new()
        } else {
            Self::fetch_pool_names(&self.pool, tenant_id, &pool_ids).await?
        };

        let entries = events
            .into_iter()
            .map(|event| event_to_entry(event, &pool_name_map))
            .collect();

        Ok(entries)
    }

    /// Batch-fetch pool names for the given IDs in a single query.
    async fn fetch_pool_names(
        db: &PgPool,
        tenant_id: Uuid,
        pool_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, String>> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT id, name FROM gov_license_pools
            WHERE id = ANY($1) AND tenant_id = $2
            "#,
        )
        .bind(pool_ids)
        .bind(tenant_id)
        .fetch_all(db)
        .await?;

        Ok(rows.into_iter().collect())
    }

    /// Get a single audit event by ID.
    pub async fn get_by_id(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<LicenseAuditEntry>> {
        let event = GovLicenseAuditEvent::find_by_id(&self.pool, tenant_id, event_id).await?;

        match event {
            Some(e) => {
                let pool_name = if let Some(pool_id) = e.license_pool_id {
                    GovLicensePool::find_by_id(&self.pool, tenant_id, pool_id)
                        .await?
                        .map(|p| p.name)
                } else {
                    None
                };

                Ok(Some(LicenseAuditEntry {
                    id: e.id,
                    pool_id: e.license_pool_id,
                    pool_name,
                    assignment_id: e.license_assignment_id,
                    user_id: e.user_id,
                    user_email: None,
                    action: e.action.clone(),
                    actor_id: e.actor_id,
                    actor_email: None,
                    details: e.details,
                    created_at: e.created_at,
                }))
            }
            None => Ok(None),
        }
    }

    /// Convert a detailed event to an entry.
    fn to_entry(event: LicenseAuditEventWithDetails) -> LicenseAuditEntry {
        LicenseAuditEntry {
            id: event.id,
            pool_id: event.license_pool_id,
            pool_name: event.pool_name,
            assignment_id: event.license_assignment_id,
            user_id: event.user_id,
            user_email: event.user_email,
            action: event.action,
            actor_id: event.actor_id,
            actor_email: event.actor_email,
            details: event.details,
            created_at: event.created_at,
        }
    }

    /// Get database pool reference.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// Helper functions for convenience in other services
impl LicenseAuditService {
    /// Record pool creation.
    pub async fn log_pool_created(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        pool_name: &str,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_pool_event(
            tenant_id,
            RecordPoolEventParams {
                pool_id,
                action: LicenseAuditAction::PoolCreated,
                actor_id,
                details: Some(serde_json::json!({
                    "pool_name": pool_name
                })),
            },
        )
        .await
    }

    /// Record pool update.
    pub async fn log_pool_updated(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        changes: serde_json::Value,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_pool_event(
            tenant_id,
            RecordPoolEventParams {
                pool_id,
                action: LicenseAuditAction::PoolUpdated,
                actor_id,
                details: Some(serde_json::json!({
                    "changes": changes
                })),
            },
        )
        .await
    }

    /// Record pool archival.
    pub async fn log_pool_archived(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_pool_event(
            tenant_id,
            RecordPoolEventParams {
                pool_id,
                action: LicenseAuditAction::PoolArchived,
                actor_id,
                details: None,
            },
        )
        .await
    }

    /// Record pool deletion.
    pub async fn log_pool_deleted(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        pool_name: &str,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_pool_event(
            tenant_id,
            RecordPoolEventParams {
                pool_id,
                action: LicenseAuditAction::PoolDeleted,
                actor_id,
                details: Some(serde_json::json!({
                    "pool_name": pool_name
                })),
            },
        )
        .await
    }

    /// Record pool expiration.
    pub async fn log_pool_expired(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_pool_event(
            tenant_id,
            RecordPoolEventParams {
                pool_id,
                action: LicenseAuditAction::PoolExpired,
                actor_id,
                details: None,
            },
        )
        .await
    }

    /// Record license assignment.
    pub async fn log_license_assigned(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        assignment_id: Uuid,
        user_id: Uuid,
        actor_id: Uuid,
        source: &str,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_assignment_event(
            tenant_id,
            RecordAssignmentEventParams {
                pool_id,
                assignment_id,
                user_id,
                action: LicenseAuditAction::LicenseAssigned,
                actor_id,
                details: Some(serde_json::json!({
                    "source": source
                })),
            },
        )
        .await
    }

    /// Record license deallocation.
    pub async fn log_license_deallocated(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        assignment_id: Uuid,
        user_id: Uuid,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_assignment_event(
            tenant_id,
            RecordAssignmentEventParams {
                pool_id,
                assignment_id,
                user_id,
                action: LicenseAuditAction::LicenseDeallocated,
                actor_id,
                details: None,
            },
        )
        .await
    }

    /// Record license reclamation.
    pub async fn log_license_reclaimed(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        assignment_id: Uuid,
        user_id: Uuid,
        reason: &str,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_assignment_event(
            tenant_id,
            RecordAssignmentEventParams {
                pool_id,
                assignment_id,
                user_id,
                action: LicenseAuditAction::LicenseReclaimed,
                actor_id,
                details: Some(serde_json::json!({
                    "reason": reason
                })),
            },
        )
        .await
    }

    /// Record bulk assignment.
    pub async fn log_bulk_assign(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        affected_user_ids: Vec<Uuid>,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_bulk_event(
            tenant_id,
            RecordBulkEventParams {
                pool_id,
                action: LicenseAuditAction::BulkAssign,
                actor_id,
                affected_user_ids: Some(affected_user_ids),
                details: None,
            },
        )
        .await
    }

    /// Record bulk reclamation.
    pub async fn log_bulk_reclaim(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        affected_user_ids: Vec<Uuid>,
        reason: &str,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_bulk_event(
            tenant_id,
            RecordBulkEventParams {
                pool_id,
                action: LicenseAuditAction::BulkReclaim,
                actor_id,
                affected_user_ids: Some(affected_user_ids),
                details: Some(serde_json::json!({
                    "reason": reason
                })),
            },
        )
        .await
    }

    /// Record incompatibility rule created.
    pub async fn log_incompatibility_created(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        pool_a_id: Uuid,
        pool_b_id: Uuid,
        pool_a_name: &str,
        pool_b_name: &str,
        reason: &str,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_pool_event(
            tenant_id,
            RecordPoolEventParams {
                pool_id: pool_a_id,
                action: LicenseAuditAction::IncompatibilityCreated,
                actor_id,
                details: Some(serde_json::json!({
                    "rule_id": rule_id,
                    "pool_a_id": pool_a_id,
                    "pool_b_id": pool_b_id,
                    "pool_a_name": pool_a_name,
                    "pool_b_name": pool_b_name,
                    "reason": reason
                })),
            },
        )
        .await
    }

    /// Record incompatibility rule deleted.
    pub async fn log_incompatibility_deleted(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        pool_a_id: Uuid,
        pool_b_id: Uuid,
        pool_a_name: &str,
        pool_b_name: &str,
        actor_id: Uuid,
    ) -> Result<GovLicenseAuditEvent> {
        self.record_pool_event(
            tenant_id,
            RecordPoolEventParams {
                pool_id: pool_a_id,
                action: LicenseAuditAction::IncompatibilityDeleted,
                actor_id,
                details: Some(serde_json::json!({
                    "rule_id": rule_id,
                    "pool_a_id": pool_a_id,
                    "pool_b_id": pool_b_id,
                    "pool_a_name": pool_a_name,
                    "pool_b_name": pool_b_name
                })),
            },
        )
        .await
    }
}

/// Convert a `GovLicenseAuditEvent` to a `LicenseAuditEntry`, resolving
/// the pool name from the pre-fetched map.
fn event_to_entry(
    event: GovLicenseAuditEvent,
    pool_name_map: &HashMap<Uuid, String>,
) -> LicenseAuditEntry {
    let pool_name = event
        .license_pool_id
        .and_then(|pid| pool_name_map.get(&pid).cloned());

    LicenseAuditEntry {
        id: event.id,
        pool_id: event.license_pool_id,
        pool_name,
        assignment_id: event.license_assignment_id,
        user_id: event.user_id,
        user_email: None,
        action: event.action,
        actor_id: event.actor_id,
        actor_email: None,
        details: event.details,
        created_at: event.created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --------------- helpers ---------------

    /// Build a minimal `GovLicenseAuditEvent` for unit testing.
    fn make_event(
        pool_id: Option<Uuid>,
        assignment_id: Option<Uuid>,
        user_id: Option<Uuid>,
        action: &str,
    ) -> GovLicenseAuditEvent {
        GovLicenseAuditEvent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            license_pool_id: pool_id,
            license_assignment_id: assignment_id,
            user_id,
            action: action.to_string(),
            actor_id: Uuid::new_v4(),
            details: serde_json::json!({}),
            created_at: Utc::now(),
        }
    }

    // --------------- event_to_entry tests ---------------

    #[test]
    fn test_event_to_entry_with_pool_name() {
        let pool_id = Uuid::new_v4();
        let event = make_event(Some(pool_id), None, None, "pool_created");

        let mut map = HashMap::new();
        map.insert(pool_id, "Office 365 E3".to_string());

        let entry = event_to_entry(event, &map);

        assert_eq!(entry.pool_id, Some(pool_id));
        assert_eq!(entry.pool_name.as_deref(), Some("Office 365 E3"));
        assert_eq!(entry.action, "pool_created");
        assert!(entry.user_email.is_none());
        assert!(entry.actor_email.is_none());
    }

    #[test]
    fn test_event_to_entry_pool_id_not_in_map() {
        let pool_id = Uuid::new_v4();
        let event = make_event(Some(pool_id), None, None, "pool_updated");

        // Map is empty -- the pool may have been deleted between event
        // creation and lookup.
        let map = HashMap::new();

        let entry = event_to_entry(event, &map);

        assert_eq!(entry.pool_id, Some(pool_id));
        assert!(entry.pool_name.is_none());
    }

    #[test]
    fn test_event_to_entry_no_pool_id() {
        let event = make_event(None, None, None, "pool_created");
        let map = HashMap::new();

        let entry = event_to_entry(event, &map);

        assert!(entry.pool_id.is_none());
        assert!(entry.pool_name.is_none());
    }

    #[test]
    fn test_event_to_entry_preserves_all_fields() {
        let pool_id = Uuid::new_v4();
        let assignment_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let event = make_event(
            Some(pool_id),
            Some(assignment_id),
            Some(user_id),
            "license_assigned",
        );
        let event_id = event.id;
        let actor_id = event.actor_id;
        let created_at = event.created_at;

        let mut map = HashMap::new();
        map.insert(pool_id, "Jira Licenses".to_string());

        let entry = event_to_entry(event, &map);

        assert_eq!(entry.id, event_id);
        assert_eq!(entry.pool_id, Some(pool_id));
        assert_eq!(entry.pool_name.as_deref(), Some("Jira Licenses"));
        assert_eq!(entry.assignment_id, Some(assignment_id));
        assert_eq!(entry.user_id, Some(user_id));
        assert_eq!(entry.action, "license_assigned");
        assert_eq!(entry.actor_id, actor_id);
        assert_eq!(entry.created_at, created_at);
        assert_eq!(entry.details, serde_json::json!({}));
    }

    #[test]
    fn test_event_to_entry_multiple_events_share_pool_name() {
        let pool_id = Uuid::new_v4();
        let event1 = make_event(Some(pool_id), None, None, "pool_created");
        let event2 = make_event(Some(pool_id), None, None, "pool_updated");

        let mut map = HashMap::new();
        map.insert(pool_id, "Shared Pool".to_string());

        let entry1 = event_to_entry(event1, &map);
        let entry2 = event_to_entry(event2, &map);

        assert_eq!(entry1.pool_name.as_deref(), Some("Shared Pool"));
        assert_eq!(entry2.pool_name.as_deref(), Some("Shared Pool"));
    }

    // --------------- existing param tests ---------------

    #[test]
    fn test_list_audit_params_default() {
        let params = ListAuditParams::default();
        assert!(params.pool_id.is_none());
        assert!(params.user_id.is_none());
        assert!(params.action.is_none());
        assert!(params.from_date.is_none());
        assert!(params.to_date.is_none());
        assert_eq!(params.limit, 0);
        assert_eq!(params.offset, 0);
    }

    #[test]
    fn test_record_pool_event_params() {
        let params = RecordPoolEventParams {
            pool_id: Uuid::new_v4(),
            action: LicenseAuditAction::PoolCreated,
            actor_id: Uuid::new_v4(),
            details: Some(serde_json::json!({"test": true})),
        };

        assert!(params.details.is_some());
    }

    #[test]
    fn test_record_assignment_event_params() {
        let params = RecordAssignmentEventParams {
            pool_id: Uuid::new_v4(),
            assignment_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            action: LicenseAuditAction::LicenseAssigned,
            actor_id: Uuid::new_v4(),
            details: None,
        };

        assert!(params.details.is_none());
    }

    #[test]
    fn test_record_bulk_event_params() {
        let user_ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        let params = RecordBulkEventParams {
            pool_id: Uuid::new_v4(),
            action: LicenseAuditAction::BulkAssign,
            actor_id: Uuid::new_v4(),
            affected_user_ids: Some(user_ids.clone()),
            details: None,
        };

        assert_eq!(params.affected_user_ids.as_ref().unwrap().len(), 2);
    }
}
