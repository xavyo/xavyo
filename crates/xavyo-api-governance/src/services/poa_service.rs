//! Power of Attorney service (F-061).
//!
//! Handles Power of Attorney grant, revocation, and identity assumption operations.
//! Enables users to grant another user the ability to act on their behalf.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreatePoaAssumedSession, CreatePoaAuditEvent, CreatePowerOfAttorney, PoaAssumedSession,
    PoaAuditEvent, PoaAuditEventFilter, PoaEventType, PoaFilter, PoaStatus, PowerOfAttorney, User,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::power_of_attorney::{GrantPoaRequest, PoaDirection, PoaScopeRequest};

/// Service for Power of Attorney operations.
pub struct PoaService {
    pool: PgPool,
}

impl PoaService {
    /// Create a new PoA service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Grant a Power of Attorney from the donor to the attorney.
    ///
    /// # Validations
    /// - Self-delegation is not allowed (T015)
    /// - Duration must not exceed 90 days (T016)
    /// - Start date must not be in the past (T017)
    /// - Both donor and attorney must be active users (T018)
    pub async fn grant_poa(
        &self,
        tenant_id: Uuid,
        donor_id: Uuid,
        request: GrantPoaRequest,
    ) -> Result<PowerOfAttorney> {
        // T015: Self-delegation prevention
        if donor_id == request.attorney_id {
            return Err(GovernanceError::PoaSelfDelegationNotAllowed);
        }

        // T017: Start date validation
        let now = Utc::now();
        if request.starts_at < now - Duration::minutes(5) {
            // Allow 5 minute grace period for clock skew
            return Err(GovernanceError::PoaStartDateInPast);
        }

        // Ensure end date is after start date
        if request.ends_at <= request.starts_at {
            return Err(GovernanceError::PoaInvalidPeriod);
        }

        // T016: 90-day maximum duration validation
        if !PowerOfAttorney::validate_duration(request.starts_at, request.ends_at) {
            return Err(GovernanceError::PoaDurationExceedsMaximum);
        }

        // T018: Validate donor is an active user
        let donor = User::find_by_id_in_tenant(&self.pool, tenant_id, donor_id)
            .await?
            .ok_or(GovernanceError::PoaDonorNotFound(donor_id))?;

        if !donor.is_active {
            return Err(GovernanceError::PoaDonorNotActive(donor_id));
        }

        // T018: Validate attorney is an active user
        let attorney = User::find_by_id_in_tenant(&self.pool, tenant_id, request.attorney_id)
            .await?
            .ok_or(GovernanceError::PoaAttorneyNotFound(request.attorney_id))?;

        if !attorney.is_active {
            return Err(GovernanceError::PoaAttorneyNotActive(request.attorney_id));
        }

        // Handle scope if provided
        let scope_id = if let Some(scope_request) = &request.scope {
            self.create_or_find_scope(tenant_id, scope_request).await?
        } else {
            None
        };

        // Create the PoA
        let create_request = CreatePowerOfAttorney {
            attorney_id: request.attorney_id,
            starts_at: request.starts_at,
            ends_at: request.ends_at,
            scope_id,
            reason: request.reason.clone(),
        };

        let poa = PowerOfAttorney::create(&self.pool, tenant_id, donor_id, create_request).await?;

        // T025: Create audit event for grant
        self.create_audit_event(
            tenant_id,
            poa.id,
            donor_id,
            Some(request.attorney_id),
            PoaEventType::GrantCreated,
            request.reason.as_deref(),
            None,
        )
        .await?;

        tracing::info!(
            poa_id = %poa.id,
            tenant_id = %tenant_id,
            donor_id = %donor_id,
            attorney_id = %request.attorney_id,
            starts_at = %poa.starts_at,
            ends_at = %poa.ends_at,
            "Power of Attorney granted"
        );

        Ok(poa)
    }

    /// Get a Power of Attorney by ID.
    pub async fn get_poa(&self, tenant_id: Uuid, poa_id: Uuid) -> Result<PowerOfAttorney> {
        PowerOfAttorney::find_by_id(&self.pool, tenant_id, poa_id)
            .await?
            .ok_or(GovernanceError::PoaNotFound(poa_id))
    }

    /// List Power of Attorney grants with optional direction filter.
    ///
    /// - `direction`: "incoming" (where user is attorney), "outgoing" (where user is donor)
    pub async fn list_poa(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        direction: Option<PoaDirection>,
        status: Option<PoaStatus>,
        active_now: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<PowerOfAttorney>, i64)> {
        let filter = match direction {
            Some(PoaDirection::Incoming) => PoaFilter {
                attorney_id: Some(user_id),
                status,
                active_now,
                ..Default::default()
            },
            Some(PoaDirection::Outgoing) => PoaFilter {
                donor_id: Some(user_id),
                status,
                active_now,
                ..Default::default()
            },
            None => PoaFilter {
                // Show all where user is either donor or attorney
                // We'll need to make two queries and merge
                donor_id: Some(user_id),
                status,
                active_now,
                ..Default::default()
            },
        };

        if direction.is_none() {
            // When no direction specified, get both incoming and outgoing
            let outgoing_filter = PoaFilter {
                donor_id: Some(user_id),
                status,
                active_now,
                ..Default::default()
            };
            let incoming_filter = PoaFilter {
                attorney_id: Some(user_id),
                status,
                active_now,
                ..Default::default()
            };

            let outgoing = PowerOfAttorney::list_by_tenant(
                &self.pool,
                tenant_id,
                &outgoing_filter,
                limit,
                offset,
            )
            .await?;
            let outgoing_count =
                PowerOfAttorney::count_by_tenant(&self.pool, tenant_id, &outgoing_filter).await?;

            let incoming = PowerOfAttorney::list_by_tenant(
                &self.pool,
                tenant_id,
                &incoming_filter,
                limit,
                offset,
            )
            .await?;
            let incoming_count =
                PowerOfAttorney::count_by_tenant(&self.pool, tenant_id, &incoming_filter).await?;

            // Merge and dedupe (in case user is both donor and attorney somehow)
            let mut all_poas = outgoing;
            for poa in incoming {
                if !all_poas.iter().any(|p| p.id == poa.id) {
                    all_poas.push(poa);
                }
            }

            // Sort by created_at descending
            all_poas.sort_by(|a, b| b.created_at.cmp(&a.created_at));

            // Apply pagination to merged result
            let total = outgoing_count + incoming_count;
            let poas: Vec<PowerOfAttorney> =
                all_poas.into_iter().take(limit.max(0) as usize).collect();

            Ok((poas, total))
        } else {
            let poas =
                PowerOfAttorney::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                    .await?;
            let total = PowerOfAttorney::count_by_tenant(&self.pool, tenant_id, &filter).await?;

            Ok((poas, total))
        }
    }

    /// Revoke a Power of Attorney.
    ///
    /// Only the donor can revoke their own PoA.
    /// Admins can use `admin_revoke_poa`.
    pub async fn revoke_poa(
        &self,
        tenant_id: Uuid,
        poa_id: Uuid,
        revoked_by: Uuid,
        reason: Option<String>,
    ) -> Result<PowerOfAttorney> {
        // First verify the PoA exists and belongs to this user as donor
        let poa = self.get_poa(tenant_id, poa_id).await?;

        if poa.donor_id != revoked_by {
            // User is not the donor - check if they're an admin (handled by admin_revoke_poa)
            return Err(GovernanceError::PoaNotFound(poa_id));
        }

        // Check if already in terminal state
        if poa.status.is_terminal() {
            return Err(GovernanceError::PoaAlreadyRevoked(poa_id));
        }

        // Revoke the PoA
        let revoked =
            PowerOfAttorney::revoke(&self.pool, tenant_id, poa_id, revoked_by, reason.clone())
                .await?
                .ok_or(GovernanceError::PoaNotFound(poa_id))?;

        // T042: Terminate any active assumed sessions
        let terminated_count =
            PoaAssumedSession::terminate_all_for_poa(&self.pool, tenant_id, poa_id, "poa_revoked")
                .await?;

        if terminated_count > 0 {
            tracing::info!(
                poa_id = %poa_id,
                terminated_sessions = %terminated_count,
                "Terminated active assumed sessions due to PoA revocation"
            );
        }

        // Record the audit event
        self.create_audit_event(
            tenant_id,
            poa_id,
            revoked_by,
            Some(poa.attorney_id),
            PoaEventType::GrantRevoked,
            reason.as_deref(),
            None,
        )
        .await?;

        tracing::info!(
            poa_id = %poa_id,
            tenant_id = %tenant_id,
            revoked_by = %revoked_by,
            "Power of Attorney revoked"
        );

        Ok(revoked)
    }

    /// Admin revoke a Power of Attorney.
    ///
    /// Admins can revoke any PoA in the tenant.
    pub async fn admin_revoke_poa(
        &self,
        tenant_id: Uuid,
        poa_id: Uuid,
        admin_id: Uuid,
        reason: Option<String>,
    ) -> Result<PowerOfAttorney> {
        let poa = self.get_poa(tenant_id, poa_id).await?;

        if poa.status.is_terminal() {
            return Err(GovernanceError::PoaAlreadyRevoked(poa_id));
        }

        let revoked =
            PowerOfAttorney::revoke(&self.pool, tenant_id, poa_id, admin_id, reason.clone())
                .await?
                .ok_or(GovernanceError::PoaNotFound(poa_id))?;

        // T042: Terminate any active assumed sessions
        let terminated_count = PoaAssumedSession::terminate_all_for_poa(
            &self.pool,
            tenant_id,
            poa_id,
            "admin_revoked",
        )
        .await?;

        if terminated_count > 0 {
            tracing::info!(
                poa_id = %poa_id,
                admin_id = %admin_id,
                terminated_sessions = %terminated_count,
                "Terminated active assumed sessions due to admin PoA revocation"
            );
        }

        self.create_audit_event(
            tenant_id,
            poa_id,
            admin_id,
            Some(poa.attorney_id),
            PoaEventType::GrantRevoked,
            reason.as_deref(),
            Some(serde_json::json!({ "admin_revoke": true, "terminated_sessions": terminated_count })),
        )
        .await?;

        tracing::info!(
            poa_id = %poa_id,
            tenant_id = %tenant_id,
            admin_id = %admin_id,
            "Power of Attorney admin-revoked"
        );

        Ok(revoked)
    }

    /// Extend a Power of Attorney's end date.
    ///
    /// The new end date must be after the current end date but not exceed 90 days
    /// from the original start date.
    pub async fn extend_poa(
        &self,
        tenant_id: Uuid,
        poa_id: Uuid,
        user_id: Uuid,
        new_ends_at: DateTime<Utc>,
    ) -> Result<PowerOfAttorney> {
        let poa = self.get_poa(tenant_id, poa_id).await?;

        // Only donor can extend
        if poa.donor_id != user_id {
            return Err(GovernanceError::PoaNotFound(poa_id));
        }

        // Cannot extend expired PoA
        if poa.status == PoaStatus::Expired {
            return Err(GovernanceError::PoaCannotExtendExpired(poa_id));
        }

        // Cannot extend revoked PoA
        if poa.status == PoaStatus::Revoked {
            return Err(GovernanceError::PoaCannotExtendRevoked(poa_id));
        }

        // New end date must be after current end date
        if new_ends_at <= poa.ends_at {
            return Err(GovernanceError::PoaInvalidExtension);
        }

        // Validate new duration doesn't exceed 90 days from original start
        if !PowerOfAttorney::validate_duration(poa.starts_at, new_ends_at) {
            return Err(GovernanceError::PoaExtensionExceedsMaximum);
        }

        let extended = PowerOfAttorney::extend(&self.pool, tenant_id, poa_id, new_ends_at)
            .await?
            .ok_or(GovernanceError::PoaExtensionExceedsMaximum)?;

        self.create_audit_event(
            tenant_id,
            poa_id,
            user_id,
            Some(poa.attorney_id),
            PoaEventType::GrantExtended,
            None,
            Some(serde_json::json!({
                "previous_ends_at": poa.ends_at,
                "new_ends_at": new_ends_at
            })),
        )
        .await?;

        tracing::info!(
            poa_id = %poa_id,
            tenant_id = %tenant_id,
            previous_ends_at = %poa.ends_at,
            new_ends_at = %new_ends_at,
            "Power of Attorney extended"
        );

        Ok(extended)
    }

    /// Admin list all PoA grants in the tenant.
    pub async fn admin_list_poa(
        &self,
        tenant_id: Uuid,
        donor_id: Option<Uuid>,
        attorney_id: Option<Uuid>,
        status: Option<PoaStatus>,
        active_now: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<PowerOfAttorney>, i64)> {
        let filter = PoaFilter {
            donor_id,
            attorney_id,
            status,
            active_now,
            ..Default::default()
        };

        let poas =
            PowerOfAttorney::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = PowerOfAttorney::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((poas, total))
    }

    // =========================================================================
    // Identity Assumption Operations (T028-T030)
    // =========================================================================

    /// Assume the identity of the donor using a valid PoA.
    ///
    /// # Requirements
    /// - The attorney must be the one assuming
    /// - The PoA must be active and within its time window
    /// - The attorney must not already be assuming another identity
    ///
    /// # Returns
    /// The assumed session and the donor_id to include in JWT claims.
    pub async fn assume_identity(
        &self,
        tenant_id: Uuid,
        attorney_id: Uuid,
        poa_id: Uuid,
        session_jti: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(PoaAssumedSession, Uuid)> {
        // Validate the PoA exists and is valid
        let poa = self.get_poa(tenant_id, poa_id).await?;

        // Verify the requester is the attorney
        if poa.attorney_id != attorney_id {
            return Err(GovernanceError::PoaNotFound(poa_id));
        }

        // Verify the PoA is currently active
        let now = Utc::now();
        if !poa.is_currently_active(now) {
            return Err(GovernanceError::PoaNotActive(poa_id));
        }

        // Check if the attorney is already assuming another identity
        if PoaAssumedSession::find_active_for_attorney(&self.pool, tenant_id, attorney_id)
            .await?
            .is_some()
        {
            return Err(GovernanceError::PoaAlreadyAssuming);
        }

        // Create the assumed session
        let create_request = CreatePoaAssumedSession {
            poa_id,
            attorney_id,
            session_token_jti: session_jti,
            ip_address,
            user_agent,
        };

        let session = PoaAssumedSession::create(&self.pool, tenant_id, create_request).await?;

        // T036: Create audit event for identity_assumed
        self.create_audit_event(
            tenant_id,
            poa_id,
            attorney_id,
            Some(poa.donor_id),
            PoaEventType::IdentityAssumed,
            None,
            Some(serde_json::json!({
                "session_id": session.id,
                "donor_id": poa.donor_id
            })),
        )
        .await?;

        tracing::info!(
            session_id = %session.id,
            poa_id = %poa_id,
            attorney_id = %attorney_id,
            donor_id = %poa.donor_id,
            tenant_id = %tenant_id,
            "Identity assumed"
        );

        Ok((session, poa.donor_id))
    }

    /// Drop the currently assumed identity.
    ///
    /// # Requirements
    /// - The attorney must have an active assumed session
    pub async fn drop_identity(
        &self,
        tenant_id: Uuid,
        attorney_id: Uuid,
    ) -> Result<PoaAssumedSession> {
        // Find the active session
        let session =
            PoaAssumedSession::find_active_for_attorney(&self.pool, tenant_id, attorney_id)
                .await?
                .ok_or(GovernanceError::PoaNotAssuming)?;

        // Drop the session
        let dropped = PoaAssumedSession::drop_session(&self.pool, tenant_id, session.id)
            .await?
            .ok_or(GovernanceError::PoaAssumedSessionNotFound(session.id))?;

        // Get the PoA for audit event
        if let Ok(poa) = self.get_poa(tenant_id, session.poa_id).await {
            // T037: Create audit event for identity_dropped
            self.create_audit_event(
                tenant_id,
                session.poa_id,
                attorney_id,
                Some(poa.donor_id),
                PoaEventType::IdentityDropped,
                None,
                Some(serde_json::json!({
                    "session_id": session.id,
                    "reason": "user_initiated"
                })),
            )
            .await?;
        }

        tracing::info!(
            session_id = %session.id,
            poa_id = %session.poa_id,
            attorney_id = %attorney_id,
            tenant_id = %tenant_id,
            "Identity dropped"
        );

        Ok(dropped)
    }

    /// Get the current assumed identity session for an attorney.
    pub async fn get_current_assumption(
        &self,
        tenant_id: Uuid,
        attorney_id: Uuid,
    ) -> Result<Option<(PoaAssumedSession, PowerOfAttorney)>> {
        let session =
            PoaAssumedSession::find_active_for_attorney(&self.pool, tenant_id, attorney_id).await?;

        match session {
            Some(s) => {
                let poa = self.get_poa(tenant_id, s.poa_id).await?;
                Ok(Some((s, poa)))
            }
            None => Ok(None),
        }
    }

    /// Get an assumed session by ID.
    pub async fn get_assumed_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> Result<PoaAssumedSession> {
        PoaAssumedSession::find_by_id(&self.pool, tenant_id, session_id)
            .await?
            .ok_or(GovernanceError::PoaAssumedSessionNotFound(session_id))
    }

    // =========================================================================
    // Audit Trail Operations (T049-T053)
    // =========================================================================

    /// List audit events for a specific PoA.
    pub async fn list_poa_audit_events(
        &self,
        tenant_id: Uuid,
        poa_id: Uuid,
        filter: PoaAuditEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<PoaAuditEvent>, i64)> {
        // Verify the PoA exists
        let _poa = self.get_poa(tenant_id, poa_id).await?;

        // Build filter with PoA ID
        let full_filter = PoaAuditEventFilter {
            poa_id: Some(poa_id),
            ..filter
        };

        let events =
            PoaAuditEvent::list_by_tenant(&self.pool, tenant_id, &full_filter, limit, offset)
                .await?;

        // For total count, we fetch one more page to estimate if there are more
        // In production, we'd add count_by_tenant to the model
        let total = events.len() as i64;

        Ok((events, total))
    }

    /// List all audit events for the tenant (admin).
    pub async fn admin_list_audit_events(
        &self,
        tenant_id: Uuid,
        filter: PoaAuditEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<PoaAuditEvent>, i64)> {
        let events =
            PoaAuditEvent::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = events.len() as i64;

        Ok((events, total))
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Create or find an existing delegation scope.
    async fn create_or_find_scope(
        &self,
        _tenant_id: Uuid,
        _scope_request: &PoaScopeRequest,
    ) -> Result<Option<Uuid>> {
        // For now, we reuse the GovDelegationScope from F053
        // This will be implemented when scope handling is added (T056-T060)
        Ok(None)
    }

    /// Create an audit event for PoA operations.
    async fn create_audit_event(
        &self,
        tenant_id: Uuid,
        poa_id: Uuid,
        actor_id: Uuid,
        affected_user_id: Option<Uuid>,
        event_type: PoaEventType,
        _reason: Option<&str>,
        details: Option<serde_json::Value>,
    ) -> Result<PoaAuditEvent> {
        let event = CreatePoaAuditEvent {
            poa_id,
            event_type,
            actor_id,
            affected_user_id,
            details,
            ip_address: None,
            user_agent: None,
        };

        let audit_event = PoaAuditEvent::create(&self.pool, tenant_id, event).await?;

        tracing::debug!(
            audit_id = %audit_event.id,
            poa_id = %poa_id,
            event_type = ?event_type,
            actor_id = %actor_id,
            "PoA audit event created"
        );

        Ok(audit_event)
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_poa_service_creation() {
        // This is a placeholder test - actual tests require database
        // The unit tests are in power_of_attorney_tests.rs
    }
}
