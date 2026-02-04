//! NHI (Non-Human Identity) service for managing machine-to-machine accounts.
//!
//! F061 - NHI Lifecycle Management
//!
//! Provides comprehensive lifecycle management for NHIs including:
//! - Create, read, update, delete NHI accounts
//! - Owner and backup owner management
//! - Expiration and status management
//! - Integration with credential rotation (separate service)
//! - Integration with risk scoring (separate service)

use chrono::{DateTime, Utc};
use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::{
    CreateGovNhiAuditEvent, CreateGovServiceAccount, GovNhiAuditEvent, GovServiceAccount,
    NhiAuditEventType, NhiSuspensionReason, ServiceAccountFilter, ServiceAccountStatus,
    UpdateGovServiceAccount, User,
};
#[cfg(feature = "kafka")]
use xavyo_events::{
    events::nhi::{
        NhiCreated, NhiDeleted, NhiOwnershipTransferred, NhiReactivated, NhiSuspended, NhiUpdated,
    },
    EventProducer,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    CreateNhiRequest, ListNhisQuery, NhiListResponse, NhiResponse, NhiSummary, UpdateNhiRequest,
};

/// Service for managing Non-Human Identities (NHIs).
pub struct NhiService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl NhiService {
    /// Create a new NHI service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Get the database pool reference.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Set the event producer for publishing events.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    // =========================================================================
    // Core CRUD Operations
    // =========================================================================

    /// List NHIs with filtering and pagination.
    pub async fn list(&self, tenant_id: Uuid, query: &ListNhisQuery) -> Result<NhiListResponse> {
        let filter = ServiceAccountFilter {
            status: query.status,
            owner_id: query.owner_id,
            expiring_within_days: query.expiring_within_days,
            needs_certification: query.needs_certification,
            backup_owner_id: None, // Not exposed in query params
            // Convert inactive_only bool to inactive_days (90 day default threshold)
            inactive_days: if query.inactive_only == Some(true) {
                Some(90)
            } else {
                None
            },
            needs_rotation: query.needs_rotation,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let accounts = GovServiceAccount::list(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovServiceAccount::count(&self.pool, tenant_id, &filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(NhiListResponse {
            items: accounts.into_iter().map(NhiResponse::from).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get an NHI by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<NhiResponse> {
        let account = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        Ok(NhiResponse::from(account))
    }

    /// Get an NHI by user ID.
    pub async fn get_by_user_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<NhiResponse>> {
        let account = GovServiceAccount::find_by_user_id(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(account.map(NhiResponse::from))
    }

    /// Create a new NHI.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        request: CreateNhiRequest,
    ) -> Result<NhiResponse> {
        // Validate rotation interval if provided
        if let Some(interval) = request.rotation_interval_days {
            if !(1..=365).contains(&interval) {
                return Err(GovernanceError::NhiInvalidRotationInterval(interval));
            }
        }

        // Validate inactivity threshold if provided
        if let Some(threshold) = request.inactivity_threshold_days {
            if !(1..=365).contains(&threshold) {
                return Err(GovernanceError::NhiInvalidInactivityThreshold(threshold));
            }
        }

        // Validate expiration date is in the future (if provided)
        if let Some(expires_at) = request.expires_at {
            if expires_at <= Utc::now() {
                return Err(GovernanceError::InvalidExpirationDate);
            }
        }

        // Validate owner exists in tenant
        if !User::exists_in_tenant(&self.pool, tenant_id, request.owner_id)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::NhiOwnerNotFound(request.owner_id));
        }

        // Validate backup owner is different from primary owner
        if let Some(backup_id) = request.backup_owner_id {
            if backup_id == request.owner_id {
                return Err(GovernanceError::NhiBackupOwnerSameAsPrimary);
            }
            // Validate backup owner exists in tenant
            if !User::exists_in_tenant(&self.pool, tenant_id, backup_id)
                .await
                .map_err(GovernanceError::Database)?
            {
                return Err(GovernanceError::NhiOwnerNotFound(backup_id));
            }
        }

        // Check if user is already registered as an NHI
        if GovServiceAccount::is_service_account(&self.pool, tenant_id, request.user_id)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::NhiUserAlreadyRegistered(request.user_id));
        }

        // Check if name already exists
        if GovServiceAccount::name_exists(&self.pool, tenant_id, &request.name)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::NhiNameExists(request.name));
        }

        let input = CreateGovServiceAccount {
            user_id: request.user_id,
            name: request.name,
            purpose: request.purpose,
            owner_id: request.owner_id,
            expires_at: request.expires_at,
            backup_owner_id: request.backup_owner_id,
            rotation_interval_days: request.rotation_interval_days,
            inactivity_threshold_days: request.inactivity_threshold_days,
        };

        let account = GovServiceAccount::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id: account.id,
            event_type: NhiAuditEventType::Created,
            actor_id: Some(actor_id),
            changes: None,
            metadata: Some(serde_json::json!({
                "name": account.name,
                "owner_id": account.owner_id,
                "backup_owner_id": account.backup_owner_id,
                "expires_at": account.expires_at,
            })),
            source_ip: None,
        };

        if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
            tracing::warn!(error = %e, "Failed to create NHI audit event");
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %account.id,
            user_id = %account.user_id,
            name = %account.name,
            "NHI created"
        );

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_created_event(tenant_id, &account, actor_id).await;

        Ok(NhiResponse::from(account))
    }

    /// Update an NHI.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        request: UpdateNhiRequest,
    ) -> Result<NhiResponse> {
        // Get existing NHI to validate changes
        let existing = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        // Validate rotation interval if provided
        if let Some(interval) = request.rotation_interval_days {
            if !(1..=365).contains(&interval) {
                return Err(GovernanceError::NhiInvalidRotationInterval(interval));
            }
        }

        // Validate inactivity threshold if provided
        if let Some(threshold) = request.inactivity_threshold_days {
            if !(1..=365).contains(&threshold) {
                return Err(GovernanceError::NhiInvalidInactivityThreshold(threshold));
            }
        }

        // Validate new owner exists (if changing owner)
        let new_owner = request.owner_id.unwrap_or(existing.owner_id);
        if let Some(owner_id) = request.owner_id {
            if !User::exists_in_tenant(&self.pool, tenant_id, owner_id)
                .await
                .map_err(GovernanceError::Database)?
            {
                return Err(GovernanceError::NhiOwnerNotFound(owner_id));
            }
        }

        // Validate backup owner is different from primary owner
        if let Some(backup_id) = request.backup_owner_id {
            if backup_id == new_owner {
                return Err(GovernanceError::NhiBackupOwnerSameAsPrimary);
            }
            // Validate backup owner exists in tenant
            if !User::exists_in_tenant(&self.pool, tenant_id, backup_id)
                .await
                .map_err(GovernanceError::Database)?
            {
                return Err(GovernanceError::NhiOwnerNotFound(backup_id));
            }
        }

        // Check if new name already exists (if changing name)
        if let Some(ref new_name) = request.name {
            if *new_name != existing.name
                && GovServiceAccount::name_exists(&self.pool, tenant_id, new_name)
                    .await
                    .map_err(GovernanceError::Database)?
            {
                return Err(GovernanceError::NhiNameExists(new_name.clone()));
            }
        }

        let update = UpdateGovServiceAccount {
            name: request.name.clone(),
            purpose: request.purpose.clone(),
            owner_id: request.owner_id,
            status: None, // Status changes go through dedicated methods
            expires_at: request.expires_at,
            backup_owner_id: request.backup_owner_id,
            rotation_interval_days: request.rotation_interval_days,
            inactivity_threshold_days: request.inactivity_threshold_days,
            ..Default::default()
        };

        let updated = GovServiceAccount::update(&self.pool, tenant_id, id, update)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id: id,
            event_type: NhiAuditEventType::Updated,
            actor_id: Some(actor_id),
            changes: Some(serde_json::json!({
                "name": request.name,
                "purpose": request.purpose,
                "owner_id": request.owner_id,
                "backup_owner_id": request.backup_owner_id,
                "expires_at": request.expires_at,
                "rotation_interval_days": request.rotation_interval_days,
                "inactivity_threshold_days": request.inactivity_threshold_days,
            })),
            metadata: None,
            source_ip: None,
        };

        if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
            tracing::warn!(error = %e, "Failed to create NHI audit event");
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            "NHI updated"
        );

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_updated_event(tenant_id, &updated, actor_id, &request)
            .await;

        Ok(NhiResponse::from(updated))
    }

    /// Delete an NHI.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid, actor_id: Uuid) -> Result<()> {
        // Get existing NHI
        let existing = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        // Record audit event before deletion
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id: id,
            event_type: NhiAuditEventType::Deleted,
            actor_id: Some(actor_id),
            changes: None,
            metadata: Some(serde_json::json!({
                "name": existing.name,
                "owner_id": existing.owner_id,
            })),
            source_ip: None,
        };

        if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
            tracing::warn!(error = %e, "Failed to create NHI audit event");
        }

        let deleted = GovServiceAccount::delete(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::NhiNotFound(id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            "NHI deleted"
        );

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_deleted_event(tenant_id, id, &existing.name, actor_id, None)
            .await;

        Ok(())
    }

    // =========================================================================
    // Status Management
    // =========================================================================

    /// Suspend an NHI.
    pub async fn suspend(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        reason: NhiSuspensionReason,
        notes: Option<String>,
    ) -> Result<NhiResponse> {
        let existing = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        if existing.status == ServiceAccountStatus::Suspended {
            return Err(GovernanceError::NhiAlreadySuspended(id));
        }

        let update = UpdateGovServiceAccount {
            status: Some(ServiceAccountStatus::Suspended),
            suspension_reason: Some(reason),
            ..Default::default()
        };

        let updated = GovServiceAccount::update(&self.pool, tenant_id, id, update)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id: id,
            event_type: NhiAuditEventType::Suspended,
            actor_id: Some(actor_id),
            changes: Some(serde_json::json!({
                "previous_status": existing.status,
            })),
            metadata: Some(serde_json::json!({
                "reason": reason,
                "notes": notes,
            })),
            source_ip: None,
        };

        if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
            tracing::warn!(error = %e, "Failed to create NHI audit event");
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            reason = ?reason,
            "NHI suspended"
        );

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_suspended_event(tenant_id, &updated, reason, notes, Some(actor_id))
            .await;

        Ok(NhiResponse::from(updated))
    }

    /// Reactivate a suspended NHI.
    pub async fn reactivate(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        notes: Option<String>,
    ) -> Result<NhiResponse> {
        let existing = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        if existing.status != ServiceAccountStatus::Suspended {
            return Err(GovernanceError::NhiNotSuspended(id));
        }

        // Check if NHI can be reactivated (not expired)
        if existing.is_expired() {
            return Err(GovernanceError::NhiCannotReactivate {
                nhi_id: id,
                reason: "NHI has expired".to_string(),
            });
        }

        let update = UpdateGovServiceAccount {
            status: Some(ServiceAccountStatus::Active),
            suspension_reason: None,
            ..Default::default()
        };

        let updated = GovServiceAccount::update(&self.pool, tenant_id, id, update)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id: id,
            event_type: NhiAuditEventType::Reactivated,
            actor_id: Some(actor_id),
            changes: Some(serde_json::json!({
                "previous_suspension_reason": existing.suspension_reason,
            })),
            metadata: Some(serde_json::json!({
                "notes": notes,
            })),
            source_ip: None,
        };

        if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
            tracing::warn!(error = %e, "Failed to create NHI audit event");
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            "NHI reactivated"
        );

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_reactivated_event(tenant_id, &updated, notes, actor_id)
            .await;

        Ok(NhiResponse::from(updated))
    }

    // =========================================================================
    // Ownership Management
    // =========================================================================

    /// Transfer ownership of an NHI.
    pub async fn transfer_ownership(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        new_owner_id: Uuid,
        notes: Option<String>,
    ) -> Result<NhiResponse> {
        let existing = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        if existing.owner_id == new_owner_id {
            return Err(GovernanceError::NhiOwnershipTransferToSelf);
        }

        // Validate new owner exists in tenant
        if !User::exists_in_tenant(&self.pool, tenant_id, new_owner_id)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::NhiOwnerNotFound(new_owner_id));
        }

        let update = UpdateGovServiceAccount {
            owner_id: Some(new_owner_id),
            ..Default::default()
        };

        let updated = GovServiceAccount::update(&self.pool, tenant_id, id, update)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id: id,
            event_type: NhiAuditEventType::OwnershipTransferred,
            actor_id: Some(actor_id),
            changes: Some(serde_json::json!({
                "previous_owner_id": existing.owner_id,
                "new_owner_id": new_owner_id,
            })),
            metadata: Some(serde_json::json!({
                "notes": notes,
            })),
            source_ip: None,
        };

        if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
            tracing::warn!(error = %e, "Failed to create NHI audit event");
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            previous_owner = %existing.owner_id,
            new_owner = %new_owner_id,
            "NHI ownership transferred"
        );

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_ownership_transferred_event(
            tenant_id,
            &updated,
            existing.owner_id,
            new_owner_id,
            notes,
            actor_id,
        )
        .await;

        Ok(NhiResponse::from(updated))
    }

    // =========================================================================
    // Certification
    // =========================================================================

    /// Certify an NHI (confirm ownership and purpose are still valid).
    pub async fn certify(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        certified_by: Uuid,
        notes: Option<String>,
    ) -> Result<NhiResponse> {
        let certified = GovServiceAccount::certify(&self.pool, tenant_id, id, certified_by)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id: id,
            event_type: NhiAuditEventType::Certified,
            actor_id: Some(certified_by),
            changes: None,
            metadata: Some(serde_json::json!({
                "notes": notes,
            })),
            source_ip: None,
        };

        if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
            tracing::warn!(error = %e, "Failed to create NHI audit event");
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            certified_by = %certified_by,
            "NHI certified"
        );

        Ok(NhiResponse::from(certified))
    }

    // =========================================================================
    // Summary and Statistics
    // =========================================================================

    /// Get summary statistics for NHIs.
    pub async fn get_summary(&self, tenant_id: Uuid) -> Result<NhiSummary> {
        // Get counts by status
        let active = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                status: Some(ServiceAccountStatus::Active),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let expired = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                status: Some(ServiceAccountStatus::Expired),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let suspended = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                status: Some(ServiceAccountStatus::Suspended),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let total = active + expired + suspended;

        // Needs certification count
        let needs_certification = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                needs_certification: Some(true),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Needs rotation count
        let needs_rotation = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                needs_rotation: Some(true),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Inactive count (using default 90 days threshold)
        let inactive = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                inactive_days: Some(90),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Expiring within 30 days
        let expiring_soon = GovServiceAccount::count(
            &self.pool,
            tenant_id,
            &ServiceAccountFilter {
                expiring_within_days: Some(30),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        Ok(NhiSummary {
            total,
            active,
            expired,
            suspended,
            needs_certification,
            needs_rotation,
            inactive,
            expiring_soon,
            by_risk_level: None, // Risk scoring is handled by a separate service
        })
    }

    // =========================================================================
    // Scheduled Tasks
    // =========================================================================

    /// Mark expired NHIs.
    pub async fn mark_expired(&self, tenant_id: Uuid) -> Result<u64> {
        let count = GovServiceAccount::mark_expired(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        if count > 0 {
            tracing::info!(
                tenant_id = %tenant_id,
                count = count,
                "Marked NHIs as expired"
            );
        }

        Ok(count)
    }

    /// Get NHIs approaching expiration (for notifications).
    pub async fn get_expiring(
        &self,
        tenant_id: Uuid,
        within_days: i32,
    ) -> Result<Vec<NhiResponse>> {
        let filter = ServiceAccountFilter {
            expiring_within_days: Some(within_days),
            status: Some(ServiceAccountStatus::Active),
            ..Default::default()
        };

        let accounts = GovServiceAccount::list(&self.pool, tenant_id, &filter, 1000, 0)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(accounts.into_iter().map(NhiResponse::from).collect())
    }

    /// Get inactive NHIs (for suspension warnings).
    pub async fn get_inactive(
        &self,
        tenant_id: Uuid,
        inactive_days: i32,
    ) -> Result<Vec<NhiResponse>> {
        let filter = ServiceAccountFilter {
            inactive_days: Some(inactive_days),
            status: Some(ServiceAccountStatus::Active),
            ..Default::default()
        };

        let accounts = GovServiceAccount::list(&self.pool, tenant_id, &filter, 1000, 0)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(accounts.into_iter().map(NhiResponse::from).collect())
    }

    /// Record usage activity for an NHI.
    pub async fn record_usage(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        let update = UpdateGovServiceAccount {
            last_used_at: Some(Utc::now()),
            ..Default::default()
        };

        GovServiceAccount::update(&self.pool, tenant_id, id, update)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        Ok(())
    }

    /// Start grace period for an NHI before suspension.
    pub async fn start_grace_period(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        grace_period_ends_at: DateTime<Utc>,
    ) -> Result<NhiResponse> {
        let existing = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        // Don't start grace period if already in one
        if existing.is_in_grace_period() {
            return Err(GovernanceError::NhiInGracePeriod(
                existing.grace_period_ends_at.unwrap().to_rfc3339(),
            ));
        }

        // Update using raw SQL since we don't have a direct method for grace_period_ends_at
        let updated = sqlx::query_as::<_, GovServiceAccount>(
            r"
            UPDATE gov_service_accounts
            SET grace_period_ends_at = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(grace_period_ends_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::NhiNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            grace_period_ends_at = %grace_period_ends_at,
            "NHI grace period started"
        );

        Ok(NhiResponse::from(updated))
    }

    // =========================================================================
    // F108: US7 - Service Account Anomaly Detection
    // =========================================================================

    /// Set anomaly detection baseline for an NHI (F108 US7).
    ///
    /// The baseline contains statistical metrics about normal behavior patterns
    /// that will be used for anomaly detection (e.g., usage frequency, access times).
    pub async fn set_anomaly_baseline(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        baseline: serde_json::Value,
    ) -> Result<NhiResponse> {
        let _ = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        // Update baseline using raw SQL since UpdateGovServiceAccount doesn't have this field yet
        let updated = sqlx::query_as::<_, GovServiceAccount>(
            r"
            UPDATE gov_service_accounts
            SET anomaly_baseline = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&baseline)
        .fetch_optional(&self.pool)
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::NhiNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            "NHI anomaly baseline updated"
        );

        Ok(NhiResponse::from(updated))
    }

    /// Set anomaly threshold for an NHI (F108 US7).
    ///
    /// The threshold is the z-score value above which behavior is considered anomalous.
    /// Default is 2.5 (approximately 99% confidence).
    pub async fn set_anomaly_threshold(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        threshold: rust_decimal::Decimal,
    ) -> Result<NhiResponse> {
        let _ = GovServiceAccount::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        let updated = sqlx::query_as::<_, GovServiceAccount>(
            r"
            UPDATE gov_service_accounts
            SET anomaly_threshold = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(threshold)
        .fetch_optional(&self.pool)
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::NhiNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            threshold = %threshold,
            "NHI anomaly threshold updated"
        );

        Ok(NhiResponse::from(updated))
    }

    /// Record anomaly check timestamp for an NHI (F108 US7).
    ///
    /// Called after running anomaly detection to track when the check was performed.
    pub async fn record_anomaly_check(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        sqlx::query(
            r"
            UPDATE gov_service_accounts
            SET last_anomaly_check_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// Get NHIs that need anomaly detection check (F108 US7).
    ///
    /// Returns NHIs where:
    /// - `anomaly_threshold` is configured
    /// - `last_anomaly_check_at` is NULL or older than the specified interval
    pub async fn get_needing_anomaly_check(
        &self,
        tenant_id: Uuid,
        check_interval_hours: i64,
    ) -> Result<Vec<NhiResponse>> {
        let cutoff = Utc::now() - chrono::Duration::hours(check_interval_hours);

        let accounts = sqlx::query_as::<_, GovServiceAccount>(
            r"
            SELECT * FROM gov_service_accounts
            WHERE tenant_id = $1
              AND deleted_at IS NULL
              AND status = 'active'
              AND anomaly_threshold IS NOT NULL
              AND (last_anomaly_check_at IS NULL OR last_anomaly_check_at < $2)
            ORDER BY last_anomaly_check_at ASC NULLS FIRST
            LIMIT 100
            ",
        )
        .bind(tenant_id)
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(accounts.into_iter().map(NhiResponse::from).collect())
    }

    // =========================================================================
    // Event Emission (Kafka)
    // =========================================================================

    #[cfg(feature = "kafka")]
    async fn emit_created_event(
        &self,
        tenant_id: Uuid,
        account: &GovServiceAccount,
        created_by: Uuid,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiCreated {
                nhi_id: account.id,
                tenant_id,
                name: account.name.clone(),
                purpose: Some(account.purpose.clone()),
                owner_id: account.owner_id,
                backup_owner_id: account.backup_owner_id,
                expires_at: account.expires_at,
                created_by,
                created_at: account.created_at,
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                tracing::warn!(
                    nhi_id = %account.id,
                    error = %e,
                    "Failed to publish NhiCreated event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_updated_event(
        &self,
        tenant_id: Uuid,
        account: &GovServiceAccount,
        updated_by: Uuid,
        request: &UpdateNhiRequest,
    ) {
        if let Some(ref producer) = self.event_producer {
            // Determine which fields were changed
            let mut changed_fields = Vec::new();
            if request.name.is_some() {
                changed_fields.push("name".to_string());
            }
            if request.purpose.is_some() {
                changed_fields.push("purpose".to_string());
            }
            if request.owner_id.is_some() {
                changed_fields.push("owner_id".to_string());
            }
            if request.backup_owner_id.is_some() {
                changed_fields.push("backup_owner_id".to_string());
            }
            if request.expires_at.is_some() {
                changed_fields.push("expires_at".to_string());
            }
            if request.rotation_interval_days.is_some() {
                changed_fields.push("rotation_interval_days".to_string());
            }
            if request.inactivity_threshold_days.is_some() {
                changed_fields.push("inactivity_threshold_days".to_string());
            }

            let event = NhiUpdated {
                nhi_id: account.id,
                tenant_id,
                name: account.name.clone(),
                changed_fields,
                updated_by,
                updated_at: account.updated_at,
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                tracing::warn!(
                    nhi_id = %account.id,
                    error = %e,
                    "Failed to publish NhiUpdated event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_deleted_event(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        name: &str,
        deleted_by: Uuid,
        reason: Option<String>,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiDeleted {
                nhi_id,
                tenant_id,
                name: name.to_string(),
                deleted_by,
                reason,
                deleted_at: Utc::now(),
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                tracing::warn!(
                    nhi_id = %nhi_id,
                    error = %e,
                    "Failed to publish NhiDeleted event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_suspended_event(
        &self,
        tenant_id: Uuid,
        account: &GovServiceAccount,
        reason: NhiSuspensionReason,
        details: Option<String>,
        suspended_by: Option<Uuid>,
    ) {
        use xavyo_events::events::nhi::NhiSuspensionReason as EventSuspensionReason;

        if let Some(ref producer) = self.event_producer {
            // Convert DB suspension reason to event suspension reason
            let event_reason = match reason {
                NhiSuspensionReason::Expired => EventSuspensionReason::Expired,
                NhiSuspensionReason::Inactive => EventSuspensionReason::Inactive,
                NhiSuspensionReason::CertificationRevoked => {
                    EventSuspensionReason::CertificationRevoked
                }
                NhiSuspensionReason::Emergency => EventSuspensionReason::Emergency,
                NhiSuspensionReason::Manual => EventSuspensionReason::Manual,
            };

            let event = NhiSuspended {
                nhi_id: account.id,
                tenant_id,
                name: account.name.clone(),
                reason: event_reason,
                details,
                suspended_by,
                suspended_at: Utc::now(),
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                tracing::warn!(
                    nhi_id = %account.id,
                    error = %e,
                    "Failed to publish NhiSuspended event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_reactivated_event(
        &self,
        tenant_id: Uuid,
        account: &GovServiceAccount,
        reason: Option<String>,
        reactivated_by: Uuid,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiReactivated {
                nhi_id: account.id,
                tenant_id,
                name: account.name.clone(),
                reason,
                reactivated_by,
                reactivated_at: Utc::now(),
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                tracing::warn!(
                    nhi_id = %account.id,
                    error = %e,
                    "Failed to publish NhiReactivated event"
                );
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_ownership_transferred_event(
        &self,
        tenant_id: Uuid,
        account: &GovServiceAccount,
        from_owner_id: Uuid,
        to_owner_id: Uuid,
        reason: Option<String>,
        transferred_by: Uuid,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiOwnershipTransferred {
                nhi_id: account.id,
                tenant_id,
                name: account.name.clone(),
                from_owner_id,
                to_owner_id,
                reason,
                transferred_by,
                transferred_at: Utc::now(),
            };
            if let Err(e) = producer.publish(event, tenant_id, None).await {
                tracing::warn!(
                    nhi_id = %account.id,
                    error = %e,
                    "Failed to publish NhiOwnershipTransferred event"
                );
            }
        }
    }
}

// =============================================================================
// Orphan Detection Service
// =============================================================================

/// Response for orphaned NHI detection.
#[derive(Debug, Clone)]
pub struct OrphanedNhiInfo {
    /// The NHI ID.
    pub nhi_id: Uuid,
    /// The NHI name.
    pub name: String,
    /// The inactive owner ID.
    pub owner_id: Uuid,
    /// Whether backup owner is available.
    pub has_backup_owner: bool,
    /// The backup owner ID (if any).
    pub backup_owner_id: Option<Uuid>,
    /// Recommended action.
    pub recommended_action: OrphanedNhiAction,
}

/// Recommended action for orphaned NHI.
#[derive(Debug, Clone, PartialEq)]
pub enum OrphanedNhiAction {
    /// Promote backup owner to primary.
    PromoteBackupOwner,
    /// Require manual assignment of new owner.
    RequireOwnerAssignment,
    /// Suspend NHI if no action taken.
    SuspendAfterGracePeriod,
}

impl NhiService {
    /// Detect orphaned NHIs where owner is inactive or deleted.
    ///
    /// This should be called by a scheduled job to identify NHIs that need
    /// owner reassignment or suspension.
    pub async fn detect_orphaned(&self, tenant_id: Uuid) -> Result<Vec<OrphanedNhiInfo>> {
        // Find all active NHIs where owner is inactive
        let orphaned = sqlx::query_as::<_, (Uuid, String, Uuid, Option<Uuid>)>(
            r"
            SELECT sa.id, sa.name, sa.owner_id, sa.backup_owner_id
            FROM gov_service_accounts sa
            LEFT JOIN users u ON sa.owner_id = u.id AND u.tenant_id = sa.tenant_id
            WHERE sa.tenant_id = $1
              AND sa.status = 'active'
              AND (u.id IS NULL OR u.is_active = false)
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let mut results = Vec::new();
        for (nhi_id, name, owner_id, backup_owner_id) in orphaned {
            let has_backup = backup_owner_id.is_some();

            // If backup owner exists, check if they're still active
            let backup_is_active = if let Some(backup_id) = backup_owner_id {
                User::exists_in_tenant(&self.pool, tenant_id, backup_id)
                    .await
                    .unwrap_or(false)
            } else {
                false
            };

            let recommended_action = if has_backup && backup_is_active {
                OrphanedNhiAction::PromoteBackupOwner
            } else {
                OrphanedNhiAction::RequireOwnerAssignment
            };

            results.push(OrphanedNhiInfo {
                nhi_id,
                name,
                owner_id,
                has_backup_owner: has_backup,
                backup_owner_id,
                recommended_action,
            });
        }

        if !results.is_empty() {
            tracing::info!(
                tenant_id = %tenant_id,
                count = results.len(),
                "Detected orphaned NHIs"
            );
        }

        Ok(results)
    }

    /// Automatically promote backup owners for orphaned NHIs.
    ///
    /// Returns the count of NHIs that were updated.
    pub async fn promote_backup_owners(&self, tenant_id: Uuid, actor_id: Uuid) -> Result<u64> {
        let orphaned = self.detect_orphaned(tenant_id).await?;

        let mut promoted = 0u64;
        for orphan in orphaned {
            if orphan.recommended_action == OrphanedNhiAction::PromoteBackupOwner {
                if let Some(backup_id) = orphan.backup_owner_id {
                    // Transfer ownership to backup
                    if let Err(e) = self
                        .transfer_ownership(
                            tenant_id,
                            orphan.nhi_id,
                            actor_id,
                            backup_id,
                            Some("Automatic promotion: primary owner inactive".to_string()),
                        )
                        .await
                    {
                        tracing::warn!(
                            nhi_id = %orphan.nhi_id,
                            error = %e,
                            "Failed to promote backup owner"
                        );
                    } else {
                        promoted += 1;
                    }
                }
            }
        }

        if promoted > 0 {
            tracing::info!(
                tenant_id = %tenant_id,
                count = promoted,
                "Promoted backup owners for orphaned NHIs"
            );
        }

        Ok(promoted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_summary_total_equals_statuses() {
        let summary = NhiSummary {
            total: 15,
            active: 10,
            expired: 3,
            suspended: 2,
            needs_certification: 5,
            needs_rotation: 3,
            inactive: 4,
            expiring_soon: 2,
            by_risk_level: None,
        };

        // Total should equal active + expired + suspended
        assert_eq!(
            summary.total,
            summary.active + summary.expired + summary.suspended
        );
    }

    #[test]
    fn test_nhi_summary_default() {
        let summary = NhiSummary {
            total: 0,
            active: 0,
            expired: 0,
            suspended: 0,
            needs_certification: 0,
            needs_rotation: 0,
            inactive: 0,
            expiring_soon: 0,
            by_risk_level: None,
        };

        assert_eq!(summary.total, 0);
    }
}
