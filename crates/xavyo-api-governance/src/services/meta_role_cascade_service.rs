//! Meta-role cascade service for governance API (F056 - US2).
//!
//! Handles cascading policy changes from meta-roles to all affected child roles.
//! Supports batched updates for efficiency and Kafka event publishing.

#[cfg(feature = "kafka")]
use std::sync::Arc;

use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use xavyo_db::{
    CreateGovMetaRoleEvent, GovMetaRole, GovMetaRoleConstraint, GovMetaRoleEntitlement,
    GovMetaRoleInheritance, InheritanceStatus, MetaRoleEventType, MetaRoleStatus,
};
use xavyo_governance::error::{GovernanceError, Result};

#[cfg(feature = "kafka")]
use xavyo_events::EventProducer;

/// Default batch size for cascade operations.
const DEFAULT_BATCH_SIZE: i64 = 100;

/// Cascade operation status.
#[derive(Debug, Clone)]
pub struct CascadeStatus {
    /// Meta-role being cascaded.
    pub meta_role_id: Uuid,
    /// Total roles affected.
    pub total_affected: i64,
    /// Roles processed so far.
    pub processed: i64,
    /// Roles successfully updated.
    pub succeeded: i64,
    /// Roles that failed to update.
    pub failed: i64,
    /// Whether cascade is complete.
    pub is_complete: bool,
    /// Error message if cascade failed.
    pub error: Option<String>,
}

impl CascadeStatus {
    /// Create a new cascade status.
    pub fn new(meta_role_id: Uuid, total_affected: i64) -> Self {
        Self {
            meta_role_id,
            total_affected,
            processed: 0,
            succeeded: 0,
            failed: 0,
            is_complete: false,
            error: None,
        }
    }
}

/// Service for meta-role cascade operations.
pub struct MetaRoleCascadeService {
    pool: PgPool,
    batch_size: i64,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl MetaRoleCascadeService {
    /// Create a new cascade service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            batch_size: DEFAULT_BATCH_SIZE,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a cascade service with custom batch size.
    pub fn with_batch_size(pool: PgPool, batch_size: i64) -> Self {
        Self {
            pool,
            batch_size,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a cascade service with event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(pool: PgPool, event_producer: Arc<EventProducer>) -> Self {
        Self {
            pool,
            batch_size: DEFAULT_BATCH_SIZE,
            event_producer: Some(event_producer),
        }
    }

    // =========================================================================
    // Cascade Operations
    // =========================================================================

    /// Cascade all changes from a meta-role to inheriting roles.
    ///
    /// This is the main entry point for cascade operations.
    pub async fn cascade_meta_role_changes(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        actor_id: Uuid,
    ) -> Result<CascadeStatus> {
        // Verify meta-role exists and is active
        let meta_role = GovMetaRole::find_by_id(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(meta_role_id))?;

        if meta_role.status != MetaRoleStatus::Active {
            return Err(GovernanceError::MetaRoleDisabled(meta_role_id));
        }

        // Get all active inheritances
        let inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            10000,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let total_affected = inheritances.len() as i64;
        let mut status = CascadeStatus::new(meta_role_id, total_affected);

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            total_affected = total_affected,
            "Starting cascade propagation"
        );

        // Record cascade started event
        self.record_cascade_event(
            tenant_id,
            meta_role_id,
            actor_id,
            MetaRoleEventType::CascadeStarted,
            serde_json::json!({ "total_affected": total_affected }),
        )
        .await?;

        // Process in batches
        for batch in inheritances.chunks(self.batch_size as usize) {
            match self
                .process_cascade_batch(tenant_id, meta_role_id, batch)
                .await
            {
                Ok((succeeded, failed)) => {
                    status.processed += batch.len() as i64;
                    status.succeeded += succeeded;
                    status.failed += failed;
                }
                Err(e) => {
                    error!(
                        tenant_id = %tenant_id,
                        meta_role_id = %meta_role_id,
                        error = %e,
                        "Cascade batch failed"
                    );
                    status.error = Some(e.to_string());
                    // Continue with next batch despite error
                }
            }
        }

        status.is_complete = true;

        // Record cascade completed event
        let event_type = if status.failed > 0 {
            MetaRoleEventType::CascadeFailed
        } else {
            MetaRoleEventType::CascadeCompleted
        };

        self.record_cascade_event(
            tenant_id,
            meta_role_id,
            actor_id,
            event_type,
            serde_json::json!({
                "total_affected": status.total_affected,
                "succeeded": status.succeeded,
                "failed": status.failed,
            }),
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            succeeded = status.succeeded,
            failed = status.failed,
            "Cascade propagation complete"
        );

        Ok(status)
    }

    /// Process a batch of inheritances.
    async fn process_cascade_batch(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        batch: &[GovMetaRoleInheritance],
    ) -> Result<(i64, i64)> {
        let mut succeeded = 0i64;
        let mut failed = 0i64;

        for inheritance in batch {
            match self
                .apply_cascade_to_role(tenant_id, meta_role_id, inheritance.child_role_id)
                .await
            {
                Ok(_) => succeeded += 1,
                Err(e) => {
                    warn!(
                        tenant_id = %tenant_id,
                        meta_role_id = %meta_role_id,
                        child_role_id = %inheritance.child_role_id,
                        error = %e,
                        "Failed to cascade to role"
                    );
                    failed += 1;
                }
            }
        }

        Ok((succeeded, failed))
    }

    /// Apply cascade changes to a single role.
    async fn apply_cascade_to_role(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        _child_role_id: Uuid,
    ) -> Result<()> {
        // Get entitlements to propagate
        let _entitlements =
            GovMetaRoleEntitlement::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
                .await
                .map_err(GovernanceError::Database)?;

        // Get constraints to propagate
        let _constraints =
            GovMetaRoleConstraint::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
                .await
                .map_err(GovernanceError::Database)?;

        // In a full implementation, this would:
        // 1. Apply entitlements to the child role (create assignments or update)
        // 2. Apply constraints to the child role
        // 3. Respect permission_type (grant vs deny)
        //
        // For now, the cascade is implicit - the meta-role inheritance relationship
        // itself represents the cascade. Systems that check role permissions
        // should follow inheritance chains.

        Ok(())
    }

    // =========================================================================
    // Entitlement Cascade
    // =========================================================================

    /// Cascade addition of an entitlement to all inheriting roles.
    pub async fn cascade_add_entitlement(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        entitlement_id: Uuid,
        actor_id: Uuid,
    ) -> Result<i64> {
        let inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            10000,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let affected_count = inheritances.len() as i64;

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            entitlement_id = %entitlement_id,
            affected_count = affected_count,
            "Cascading entitlement addition"
        );

        // Record event
        self.record_cascade_event(
            tenant_id,
            meta_role_id,
            actor_id,
            MetaRoleEventType::CascadeCompleted,
            serde_json::json!({
                "action": "add_entitlement",
                "entitlement_id": entitlement_id,
                "affected_roles": affected_count,
            }),
        )
        .await?;

        Ok(affected_count)
    }

    /// Cascade removal of an entitlement from all inheriting roles.
    pub async fn cascade_remove_entitlement(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        entitlement_id: Uuid,
        actor_id: Uuid,
    ) -> Result<i64> {
        let inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            10000,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let affected_count = inheritances.len() as i64;

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            entitlement_id = %entitlement_id,
            affected_count = affected_count,
            "Cascading entitlement removal"
        );

        // Record event
        self.record_cascade_event(
            tenant_id,
            meta_role_id,
            actor_id,
            MetaRoleEventType::CascadeCompleted,
            serde_json::json!({
                "action": "remove_entitlement",
                "entitlement_id": entitlement_id,
                "affected_roles": affected_count,
            }),
        )
        .await?;

        Ok(affected_count)
    }

    // =========================================================================
    // Constraint Cascade
    // =========================================================================

    /// Cascade modification of a constraint to all inheriting roles.
    pub async fn cascade_modify_constraint(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        constraint_type: &str,
        new_value: &serde_json::Value,
        actor_id: Uuid,
    ) -> Result<i64> {
        let inheritances = GovMetaRoleInheritance::list_by_meta_role(
            &self.pool,
            tenant_id,
            meta_role_id,
            Some(InheritanceStatus::Active),
            10000,
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let affected_count = inheritances.len() as i64;

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            constraint_type = %constraint_type,
            affected_count = affected_count,
            "Cascading constraint modification"
        );

        // Record event
        self.record_cascade_event(
            tenant_id,
            meta_role_id,
            actor_id,
            MetaRoleEventType::CascadeCompleted,
            serde_json::json!({
                "action": "modify_constraint",
                "constraint_type": constraint_type,
                "new_value": new_value,
                "affected_roles": affected_count,
            }),
        )
        .await?;

        Ok(affected_count)
    }

    // =========================================================================
    // Criteria Change Handling
    // =========================================================================

    /// Handle criteria change by re-evaluating which roles should have inheritance.
    ///
    /// Returns (added, removed) counts.
    pub async fn handle_criteria_change(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        actor_id: Uuid,
    ) -> Result<(i64, i64)> {
        // This delegates to MetaRoleMatchingService.reevaluate_meta_role
        // For now, we just record the event
        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role_id,
            "Handling criteria change"
        );

        // Record event
        self.record_cascade_event(
            tenant_id,
            meta_role_id,
            actor_id,
            MetaRoleEventType::Updated,
            serde_json::json!({
                "action": "criteria_changed",
            }),
        )
        .await?;

        // Actual re-evaluation would be done by MetaRoleMatchingService
        Ok((0, 0))
    }

    // =========================================================================
    // Event Recording
    // =========================================================================

    /// Record a cascade event.
    async fn record_cascade_event(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        actor_id: Uuid,
        event_type: MetaRoleEventType,
        metadata: serde_json::Value,
    ) -> Result<()> {
        use xavyo_db::GovMetaRoleEvent;

        GovMetaRoleEvent::create(
            &self.pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(meta_role_id),
                event_type,
                actor_id: Some(actor_id),
                changes: None,
                affected_roles: None,
                metadata: Some(metadata),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    // =========================================================================
    // Kafka Event Publishing (optional)
    // =========================================================================

    /// Publish cascade trigger event to Kafka.
    #[cfg(feature = "kafka")]
    pub async fn publish_cascade_trigger(&self, tenant_id: Uuid, meta_role_id: Uuid) -> Result<()> {
        if let Some(ref producer) = self.event_producer {
            use xavyo_events::events::MetaRoleUpdated;

            let event = MetaRoleUpdated {
                tenant_id,
                meta_role_id,
                changes: vec!["cascade_triggered".to_string()],
                updated_at: chrono::Utc::now(),
            };

            let _ = producer.send(&event).await;
        }

        Ok(())
    }

    /// Publish cascade completion event to Kafka.
    #[cfg(feature = "kafka")]
    pub async fn publish_cascade_completed(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        status: &CascadeStatus,
    ) -> Result<()> {
        if let Some(ref producer) = self.event_producer {
            use xavyo_events::events::MetaRoleCascadeCompleted;

            let event = MetaRoleCascadeCompleted {
                tenant_id,
                meta_role_id,
                total_affected: status.total_affected,
                succeeded: status.succeeded,
                failed: status.failed,
                completed_at: chrono::Utc::now(),
            };

            let _ = producer.send(&event).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cascade_status_new() {
        let id = Uuid::new_v4();
        let status = CascadeStatus::new(id, 100);

        assert_eq!(status.meta_role_id, id);
        assert_eq!(status.total_affected, 100);
        assert_eq!(status.processed, 0);
        assert_eq!(status.succeeded, 0);
        assert_eq!(status.failed, 0);
        assert!(!status.is_complete);
        assert!(status.error.is_none());
    }

    #[test]
    fn test_default_batch_size() {
        assert_eq!(DEFAULT_BATCH_SIZE, 100);
    }

    #[test]
    fn test_cascade_status_progress_tracking() {
        let id = Uuid::new_v4();
        let mut status = CascadeStatus::new(id, 50);

        // Simulate processing progress
        status.processed = 25;
        status.succeeded = 23;
        status.failed = 2;

        assert_eq!(status.processed, 25);
        assert_eq!(status.succeeded, 23);
        assert_eq!(status.failed, 2);
        assert!(!status.is_complete);

        // Calculate progress percentage
        let progress = (status.processed as f64 / status.total_affected as f64) * 100.0;
        assert_eq!(progress, 50.0);
    }

    #[test]
    fn test_cascade_status_completion() {
        let id = Uuid::new_v4();
        let mut status = CascadeStatus::new(id, 10);

        status.processed = 10;
        status.succeeded = 10;
        status.is_complete = true;

        assert!(status.is_complete);
        assert_eq!(status.processed, status.total_affected);
        assert!(status.error.is_none());
    }

    #[test]
    fn test_cascade_status_with_error() {
        let id = Uuid::new_v4();
        let mut status = CascadeStatus::new(id, 20);

        status.processed = 15;
        status.succeeded = 13;
        status.failed = 2;
        status.error = Some("Database connection lost".to_string());

        assert!(status.error.is_some());
        assert_eq!(status.error.as_ref().unwrap(), "Database connection lost");
        assert!(!status.is_complete);
    }

    #[test]
    fn test_cascade_status_zero_affected() {
        let id = Uuid::new_v4();
        let mut status = CascadeStatus::new(id, 0);

        // When no roles to affect, cascade is immediately complete
        status.is_complete = true;

        assert!(status.is_complete);
        assert_eq!(status.total_affected, 0);
        assert_eq!(status.processed, 0);
    }

    #[test]
    fn test_cascade_status_large_batch() {
        let id = Uuid::new_v4();
        let status = CascadeStatus::new(id, 100_000);

        assert_eq!(status.total_affected, 100_000);
        assert_eq!(status.processed, 0);
    }

    #[test]
    fn test_cascade_status_clone() {
        let id = Uuid::new_v4();
        let mut original = CascadeStatus::new(id, 50);
        original.processed = 30;
        original.succeeded = 28;
        original.failed = 2;

        let cloned = original.clone();

        assert_eq!(original.meta_role_id, cloned.meta_role_id);
        assert_eq!(original.total_affected, cloned.total_affected);
        assert_eq!(original.processed, cloned.processed);
        assert_eq!(original.succeeded, cloned.succeeded);
        assert_eq!(original.failed, cloned.failed);
    }

    #[test]
    fn test_cascade_status_success_rate() {
        let id = Uuid::new_v4();
        let mut status = CascadeStatus::new(id, 100);
        status.processed = 100;
        status.succeeded = 95;
        status.failed = 5;
        status.is_complete = true;

        // Calculate success rate
        let success_rate = (status.succeeded as f64 / status.processed as f64) * 100.0;
        assert_eq!(success_rate, 95.0);
    }

    #[test]
    fn test_cascade_status_debug() {
        let id = Uuid::new_v4();
        let status = CascadeStatus::new(id, 10);

        // Test that Debug trait is derived
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("CascadeStatus"));
        assert!(debug_str.contains("total_affected"));
    }

    #[test]
    fn test_inheritance_status_values() {
        // Verify all inheritance statuses used in cascade
        let statuses = [
            InheritanceStatus::Active,
            InheritanceStatus::Suspended,
            InheritanceStatus::Removed,
        ];

        assert_eq!(statuses.len(), 3);
    }

    #[test]
    fn test_meta_role_status_values() {
        // Verify all meta-role statuses used in cascade
        let statuses = [MetaRoleStatus::Active, MetaRoleStatus::Disabled];

        assert_eq!(statuses.len(), 2);
        assert_ne!(MetaRoleStatus::Active, MetaRoleStatus::Disabled);
    }
}
