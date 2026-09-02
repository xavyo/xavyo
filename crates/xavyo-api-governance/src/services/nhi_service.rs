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
    CreateGovNhiAuditEvent, CreateNhiIdentity, CreateNhiServiceAccount, GovNhiAuditEvent,
    NhiAuditEventType, NhiIdentity, NhiServiceAccount as NhiServiceAccountModel,
    NhiServiceAccountFilter, NhiServiceAccountWithIdentity, NhiSuspensionReason, UpdateNhiIdentity,
    UpdateNhiServiceAccount, User,
};
#[cfg(feature = "kafka")]
use xavyo_events::{
    events::nhi::{
        NhiCreated, NhiDeleted, NhiOwnershipTransferred, NhiReactivated, NhiSuspended, NhiUpdated,
    },
    EventProducer,
};
use xavyo_governance::error::{GovernanceError, Result};
use xavyo_nhi::{NhiLifecycleState, NhiType};

use crate::models::{
    sa_status_to_lifecycle, suspension_reason_str, CreateNhiRequest, ListNhisQuery,
    NhiListResponse, NhiResponse, NhiSummary, UpdateNhiRequest,
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
        let filter = list_filter(query);

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0).max(0);

        let accounts = NhiServiceAccountModel::list(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = NhiServiceAccountModel::count(&self.pool, tenant_id, &filter)
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
        Ok(NhiResponse::from(self.load_sa(tenant_id, id).await?))
    }

    /// Get an NHI by identity ID (unified NHIs are not linked users).
    pub async fn get_by_user_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<NhiResponse>> {
        let account = NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(account.map(NhiResponse::from))
    }

    async fn load_sa(&self, tenant_id: Uuid, id: Uuid) -> Result<NhiServiceAccountWithIdentity> {
        NhiServiceAccountModel::find_by_nhi_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))
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

        if NhiIdentity::name_exists(&self.pool, tenant_id, &request.name)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::NhiNameExists(request.name));
        }

        // Create the base NHI identity row
        let identity_input = CreateNhiIdentity {
            nhi_type: NhiType::ServiceAccount,
            name: request.name.clone(),
            description: Some(request.purpose.clone()),
            owner_id: Some(request.owner_id),
            backup_owner_id: request.backup_owner_id,
            expires_at: request.expires_at,
            inactivity_threshold_days: request.inactivity_threshold_days,
            rotation_interval_days: request.rotation_interval_days,
            created_by: Some(actor_id),
        };

        let identity = NhiIdentity::create(&self.pool, tenant_id, identity_input)
            .await
            .map_err(GovernanceError::Database)?;

        // Create the service account extension row
        let sa_input = CreateNhiServiceAccount {
            nhi_id: identity.id,
            purpose: request.purpose.clone(),
            environment: None,
        };

        NhiServiceAccountModel::create(&self.pool, sa_input)
            .await
            .map_err(GovernanceError::Database)?;

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id: identity.id,
            event_type: NhiAuditEventType::Created,
            actor_id: Some(actor_id),
            changes: None,
            metadata: Some(serde_json::json!({
                "name": identity.name,
                "owner_id": identity.owner_id,
                "backup_owner_id": identity.backup_owner_id,
                "expires_at": identity.expires_at,
            })),
            source_ip: None,
        };

        GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %identity.id,
            name = %identity.name,
            "NHI created"
        );

        Ok(NhiResponse::from(
            self.load_sa(tenant_id, identity.id).await?,
        ))
    }

    /// Update an NHI.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        request: UpdateNhiRequest,
    ) -> Result<NhiResponse> {
        let existing = self.load_sa(tenant_id, id).await?;

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

        let new_owner = request
            .owner_id
            .or(existing.owner_id)
            .unwrap_or(existing.id);
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
                && NhiIdentity::name_exists(&self.pool, tenant_id, new_name)
                    .await
                    .map_err(GovernanceError::Database)?
            {
                return Err(GovernanceError::NhiNameExists(new_name.clone()));
            }
        }

        let identity_update = UpdateNhiIdentity {
            name: request.name.clone(),
            description: request.purpose.clone(),
            owner_id: request.owner_id.map(Some),
            backup_owner_id: request.backup_owner_id.map(Some),
            expires_at: request.expires_at.map(Some),
            inactivity_threshold_days: request.inactivity_threshold_days.map(Some),
            rotation_interval_days: request.rotation_interval_days.map(Some),
        };

        NhiIdentity::update(&self.pool, tenant_id, id, identity_update)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;

        if request.purpose.is_some() {
            NhiServiceAccountModel::update(
                &self.pool,
                tenant_id,
                id,
                UpdateNhiServiceAccount {
                    purpose: request.purpose.clone(),
                    environment: None,
                },
            )
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(id))?;
        }

        let updated = self.load_sa(tenant_id, id).await?;

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

        GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event)
            .await
            .map_err(GovernanceError::Database)?;

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
        let existing = self.load_sa(tenant_id, id).await?;

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

        GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event)
            .await
            .map_err(GovernanceError::Database)?;

        let deleted = NhiIdentity::delete(&self.pool, tenant_id, id)
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
        let existing = self.load_sa(tenant_id, id).await?;

        if existing.lifecycle_state == NhiLifecycleState::Suspended {
            return Err(GovernanceError::NhiAlreadySuspended(id));
        }

        NhiIdentity::update_lifecycle_state(
            &self.pool,
            tenant_id,
            id,
            NhiLifecycleState::Suspended,
            Some(suspension_reason_str(reason).to_string()),
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::NhiNotFound(id))?;

        let updated = self.load_sa(tenant_id, id).await?;

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id: id,
            event_type: NhiAuditEventType::Suspended,
            actor_id: Some(actor_id),
            changes: Some(serde_json::json!({
                "previous_status": existing.lifecycle_state.as_str(),
            })),
            metadata: Some(serde_json::json!({
                "reason": reason,
                "notes": notes,
            })),
            source_ip: None,
        };

        GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event)
            .await
            .map_err(GovernanceError::Database)?;

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
        let existing = self.load_sa(tenant_id, id).await?;

        if existing.lifecycle_state != NhiLifecycleState::Suspended {
            return Err(GovernanceError::NhiNotSuspended(id));
        }

        if existing.expires_at.is_some_and(|exp| exp <= Utc::now()) {
            return Err(GovernanceError::NhiCannotReactivate {
                nhi_id: id,
                reason: "NHI has expired".to_string(),
            });
        }

        NhiIdentity::update_lifecycle_state(
            &self.pool,
            tenant_id,
            id,
            NhiLifecycleState::Active,
            None,
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::NhiNotFound(id))?;

        let updated = self.load_sa(tenant_id, id).await?;

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

        GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event)
            .await
            .map_err(GovernanceError::Database)?;

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
        let existing = self.load_sa(tenant_id, id).await?;

        if existing.owner_id == Some(new_owner_id) {
            return Err(GovernanceError::NhiOwnershipTransferToSelf);
        }

        // Validate new owner exists in tenant
        if !User::exists_in_tenant(&self.pool, tenant_id, new_owner_id)
            .await
            .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::NhiOwnerNotFound(new_owner_id));
        }

        NhiIdentity::update(
            &self.pool,
            tenant_id,
            id,
            UpdateNhiIdentity {
                owner_id: Some(Some(new_owner_id)),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::NhiNotFound(id))?;

        let updated = self.load_sa(tenant_id, id).await?;

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

        GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            previous_owner = ?existing.owner_id,
            new_owner = %new_owner_id,
            "NHI ownership transferred"
        );

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_ownership_transferred_event(
            tenant_id,
            &updated,
            existing.owner_id.unwrap_or(existing.id),
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
        let certified_ok = NhiIdentity::update_certification(
            &self.pool,
            tenant_id,
            id,
            certified_by,
            Some(Utc::now() + chrono::Duration::days(365)),
        )
        .await
        .map_err(GovernanceError::Database)?;
        if !certified_ok {
            return Err(GovernanceError::NhiNotFound(id));
        }
        let certified = self.load_sa(tenant_id, id).await?;

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

        GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event)
            .await
            .map_err(GovernanceError::Database)?;

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
        let active = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                lifecycle_state: Some(NhiLifecycleState::Active),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let expired = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                lifecycle_state: Some(NhiLifecycleState::Inactive),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let suspended = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                lifecycle_state: Some(NhiLifecycleState::Suspended),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let total = active + expired + suspended;

        let needs_certification = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                needs_certification: Some(true),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let needs_rotation = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                needs_rotation: Some(true),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let inactive = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
                inactive_days: Some(90),
                ..Default::default()
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        let expiring_soon = NhiServiceAccountModel::count(
            &self.pool,
            tenant_id,
            &NhiServiceAccountFilter {
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
        let count = NhiIdentity::mark_expired(&self.pool, tenant_id)
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
        let filter = NhiServiceAccountFilter {
            expiring_within_days: Some(within_days),
            lifecycle_state: Some(NhiLifecycleState::Active),
            ..Default::default()
        };

        let accounts = NhiServiceAccountModel::list(&self.pool, tenant_id, &filter, 1000, 0)
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
        let filter = NhiServiceAccountFilter {
            inactive_days: Some(inactive_days),
            lifecycle_state: Some(NhiLifecycleState::Active),
            ..Default::default()
        };

        let accounts = NhiServiceAccountModel::list(&self.pool, tenant_id, &filter, 1000, 0)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(accounts.into_iter().map(NhiResponse::from).collect())
    }

    /// Record usage activity for an NHI.
    pub async fn record_usage(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        let touched = NhiIdentity::update_last_activity(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;
        if !touched {
            return Err(GovernanceError::NhiNotFound(id));
        }

        Ok(())
    }

    /// Start grace period for an NHI before suspension.
    pub async fn start_grace_period(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        grace_period_ends_at: DateTime<Utc>,
    ) -> Result<NhiResponse> {
        let existing = self.load_sa(tenant_id, id).await?;

        if existing
            .grace_period_ends_at
            .is_some_and(|ends_at| ends_at > Utc::now())
        {
            return Err(GovernanceError::NhiInGracePeriod(
                existing
                    .grace_period_ends_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| "active".to_string()),
            ));
        }

        let result = sqlx::query(
            r"
            UPDATE nhi_identities
            SET grace_period_ends_at = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(grace_period_ends_at)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;
        if result.rows_affected() == 0 {
            return Err(GovernanceError::NhiNotFound(id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %id,
            grace_period_ends_at = %grace_period_ends_at,
            "NHI grace period started"
        );

        Ok(NhiResponse::from(self.load_sa(tenant_id, id).await?))
    }

    // =========================================================================
    // Event Emission (Kafka)
    // =========================================================================

    #[cfg(feature = "kafka")]
    async fn emit_created_event(
        &self,
        tenant_id: Uuid,
        account: &NhiServiceAccountWithIdentity,
        created_by: Uuid,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiCreated {
                nhi_id: account.id,
                tenant_id,
                name: account.name.clone(),
                purpose: Some(account.purpose.clone()),
                owner_id: account.owner_id.unwrap_or(account.id),
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
        account: &NhiServiceAccountWithIdentity,
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
        account: &NhiServiceAccountWithIdentity,
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
        account: &NhiServiceAccountWithIdentity,
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
        account: &NhiServiceAccountWithIdentity,
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
        let orphaned = sqlx::query_as::<_, (Uuid, String, Option<Uuid>, Option<Uuid>)>(
            r"
            SELECT i.id, i.name, i.owner_id, i.backup_owner_id
            FROM nhi_identities i
            LEFT JOIN users u ON i.owner_id = u.id AND u.tenant_id = i.tenant_id
            WHERE i.tenant_id = $1
              AND i.lifecycle_state = 'active'
              AND i.nhi_type = 'service_account'
              AND (u.id IS NULL OR u.is_active = false)
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let mut results = Vec::new();
        for (nhi_id, name, owner_id, backup_owner_id) in orphaned {
            let Some(owner_id) = owner_id else {
                continue;
            };
            let has_backup = backup_owner_id.is_some();

            // If backup owner exists, check if they're still active
            let backup_is_active = if let Some(backup_id) = backup_owner_id {
                User::exists_in_tenant(&self.pool, tenant_id, backup_id)
                    .await
                    .map_err(GovernanceError::Database)?
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

fn list_filter(query: &ListNhisQuery) -> NhiServiceAccountFilter {
    NhiServiceAccountFilter {
        environment: None,
        lifecycle_state: query.status.map(sa_status_to_lifecycle),
        owner_id: query.owner_id,
        ids: None,
        expiring_within_days: query.expiring_within_days,
        needs_certification: query.needs_certification,
        needs_rotation: query.needs_rotation,
        inactive_days: if query.inactive_only == Some(true) {
            Some(90)
        } else {
            None
        },
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
    fn detect_orphaned_does_not_fail_open_on_backup_owner_lookup() {
        let src = include_str!("nhi_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let detect = production
            .split("pub async fn detect_orphaned")
            .nth(1)
            .and_then(|s| s.split("    pub async fn ").next())
            .expect("detect_orphaned");
        assert!(
            !detect.contains("unwrap_or(false)"),
            "orphaned NHI detection must not treat backup-owner lookup errors as inactive"
        );
        assert!(
            detect.contains("exists_in_tenant")
                && detect.contains("map_err(GovernanceError::Database)?"),
            "orphaned NHI detection must propagate backup-owner lookup errors"
        );
    }

    #[test]
    fn nhi_mutations_do_not_swallow_extension_or_audit_writes() {
        let src = include_str!("nhi_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("Failed to create NHI service account extension row"),
            "NHI create must not swallow service-account extension writes"
        );
        assert!(
            !production.contains("Failed to create NHI audit event"),
            "NHI mutations must not swallow audit writes"
        );
        assert!(
            production.matches("GovNhiAuditEvent::create(").count() >= 7
                && production.contains("NhiServiceAccountModel::create")
                && production.contains("map_err(GovernanceError::Database)?"),
            "NHI mutations must fail when extension or audit rows cannot be written"
        );
    }

    #[test]
    fn list_nhis_passes_rotation_and_inactivity_filters() {
        let src = include_str!("nhi_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("needs_rotation: query.needs_rotation")
                && production.contains("inactive_days: if query.inactive_only == Some(true)"),
            "GET /governance/nhis must pass advertised needs_rotation and inactive_only filters"
        );
    }

    #[test]
    fn nhi_crud_queries_unified_nhi_identities() {
        let src = include_str!("nhi_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("NhiServiceAccountModel::list")
                && production.contains("NhiServiceAccountModel::find_by_nhi_id")
                && production.contains("NhiIdentity::update")
                && production.contains("NhiIdentity::delete")
                && production.contains("FROM nhi_identities")
                && !production.contains("GovServiceAccount")
                && !production.contains("gov_service_accounts"),
            "GET/PUT/DELETE /governance/nhis must use nhi_identities, not the dropped gov_service_accounts table"
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
