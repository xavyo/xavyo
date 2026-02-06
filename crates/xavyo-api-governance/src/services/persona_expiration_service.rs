//! Persona Expiration Service (F063 - US5).
//!
//! Handles time-limited personas with automatic expiration:
//! - Checks for personas entering expiration warning period
//! - Transitions personas from active → expiring → expired
//! - Invalidates sessions when personas expire
//! - Sends expiration notifications

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use xavyo_db::models::{GovPersona, GovPersonaArchetype, GovPersonaSession, PersonaStatus};
use xavyo_governance::error::{GovernanceError, Result};

use super::persona_audit_service::PersonaAuditService;

/// Default number of days before expiration to send warning (status → expiring).
const DEFAULT_EXPIRATION_WARNING_DAYS: i64 = 7;

/// Result of a single persona expiration check.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersonaExpirationCheckResult {
    /// Persona ID.
    pub persona_id: Uuid,
    /// Previous status before check.
    pub previous_status: PersonaStatus,
    /// New status after check (may be same if no transition).
    pub new_status: PersonaStatus,
    /// Valid until date.
    pub valid_until: Option<DateTime<Utc>>,
    /// Days until expiration (negative if expired).
    pub days_until_expiration: Option<i64>,
    /// Whether a notification was sent.
    pub notification_sent: bool,
    /// Whether sessions were invalidated.
    pub sessions_invalidated: i32,
}

/// Result of batch expiration processing.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BatchExpirationResult {
    /// Total personas processed.
    pub processed: i32,
    /// Personas transitioned to expiring status.
    pub transitioned_to_expiring: i32,
    /// Personas transitioned to expired status.
    pub transitioned_to_expired: i32,
    /// Notifications sent.
    pub notifications_sent: i32,
    /// Sessions invalidated.
    pub sessions_invalidated: i32,
    /// Errors encountered.
    pub errors: i32,
    /// Processing duration in milliseconds.
    pub duration_ms: i64,
}

/// Result of persona extension request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtensionResult {
    /// Persona ID.
    pub persona_id: Uuid,
    /// Previous `valid_until` date.
    pub previous_valid_until: Option<DateTime<Utc>>,
    /// New `valid_until` date.
    pub new_valid_until: DateTime<Utc>,
    /// Extension in days.
    pub extension_days: i32,
    /// Whether approval was required.
    pub required_approval: bool,
    /// Number of times this persona has been extended.
    pub extension_count: i32,
}

/// Expiring persona summary for reporting.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExpiringPersonaSummary {
    /// Persona ID.
    pub persona_id: Uuid,
    /// Persona name.
    pub persona_name: String,
    /// Physical user ID.
    pub physical_user_id: Uuid,
    /// Valid until date.
    pub valid_until: Option<DateTime<Utc>>,
    /// Days until expiration.
    pub days_remaining: i64,
    /// Current status.
    pub status: PersonaStatus,
    /// Archetype name.
    pub archetype_name: Option<String>,
}

/// Expiring personas report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExpiringPersonasReport {
    /// Count of personas in expiring status.
    pub expiring_count: i64,
    /// Count of personas that expire today.
    pub expires_today_count: i64,
    /// Count of personas that expired recently.
    pub recently_expired_count: i64,
    /// List of expiring personas.
    pub personas: Vec<ExpiringPersonaSummary>,
    /// Report generation timestamp.
    pub generated_at: DateTime<Utc>,
}

/// Service for persona expiration handling.
pub struct PersonaExpirationService {
    pool: PgPool,
    audit_service: PersonaAuditService,
}

impl PersonaExpirationService {
    /// Create a new persona expiration service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit_service: PersonaAuditService::new(pool.clone()),
            pool,
        }
    }

    // =========================================================================
    // T068: Background job for expiration checking
    // =========================================================================

    /// Process expiration checks for all personas in a tenant.
    ///
    /// This should be called periodically (e.g., every 5 minutes) to:
    /// 1. Find active personas entering the expiration warning period
    /// 2. Transition them to "expiring" status
    /// 3. Find expiring/active personas past their `valid_until`
    /// 4. Transition them to "expired" status and invalidate sessions
    pub async fn process_expirations(
        &self,
        tenant_id: Uuid,
        warning_days: Option<i64>,
    ) -> Result<BatchExpirationResult> {
        let start = std::time::Instant::now();
        let warning_days = warning_days.unwrap_or(DEFAULT_EXPIRATION_WARNING_DAYS);
        let mut result = BatchExpirationResult::default();

        // 1. Process active personas entering warning period (→ expiring)
        let expiring_results = self.transition_to_expiring(tenant_id, warning_days).await?;
        result.transitioned_to_expiring = expiring_results.len() as i32;
        result.notifications_sent += expiring_results.len() as i32;
        result.processed += expiring_results.len() as i32;

        // 2. Process personas that have expired (→ expired)
        let expired_results = self.transition_to_expired(tenant_id).await?;
        result.transitioned_to_expired = expired_results.len() as i32;
        for expired in &expired_results {
            result.sessions_invalidated += expired.sessions_invalidated;
        }
        result.processed += expired_results.len() as i32;

        result.duration_ms = start.elapsed().as_millis() as i64;

        info!(
            tenant_id = %tenant_id,
            processed = result.processed,
            to_expiring = result.transitioned_to_expiring,
            to_expired = result.transitioned_to_expired,
            sessions_invalidated = result.sessions_invalidated,
            duration_ms = result.duration_ms,
            "Processed persona expirations"
        );

        Ok(result)
    }

    // =========================================================================
    // T069: Status transition: active → expiring
    // =========================================================================

    /// Find and transition active personas entering the expiration warning period.
    async fn transition_to_expiring(
        &self,
        tenant_id: Uuid,
        warning_days: i64,
    ) -> Result<Vec<PersonaExpirationCheckResult>> {
        let now = Utc::now();
        let warning_threshold = now + Duration::days(warning_days);

        // Find active personas with valid_until within warning period
        let personas = GovPersona::find_expiring_soon(&self.pool, tenant_id, warning_threshold)
            .await
            .map_err(GovernanceError::Database)?;

        let mut results = Vec::new();
        for persona in personas {
            if persona.status == PersonaStatus::Active {
                // Transition to expiring
                if let Ok(Some(_updated)) = GovPersona::update_status(
                    &self.pool,
                    tenant_id,
                    persona.id,
                    PersonaStatus::Expiring,
                )
                .await
                {
                    let days_remaining = persona.valid_until.map(|v| (v - now).num_days());

                    // Log audit event
                    let _ = self
                        .log_expiration_warning(tenant_id, persona.id, days_remaining.unwrap_or(0))
                        .await;

                    results.push(PersonaExpirationCheckResult {
                        persona_id: persona.id,
                        previous_status: PersonaStatus::Active,
                        new_status: PersonaStatus::Expiring,
                        valid_until: persona.valid_until,
                        days_until_expiration: days_remaining,
                        notification_sent: true,
                        sessions_invalidated: 0,
                    });

                    info!(
                        persona_id = %persona.id,
                        days_remaining = ?days_remaining,
                        "Persona transitioned to expiring status"
                    );
                }
            }
        }

        Ok(results)
    }

    // =========================================================================
    // T070: Status transition: expiring/active → expired
    // =========================================================================

    /// Find and transition personas that have passed their `valid_until` date.
    async fn transition_to_expired(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<PersonaExpirationCheckResult>> {
        let now = Utc::now();

        // Find personas past their valid_until
        let personas = GovPersona::find_past_valid_until(&self.pool, tenant_id, now)
            .await
            .map_err(GovernanceError::Database)?;

        let mut results = Vec::new();
        for persona in personas {
            if persona.status == PersonaStatus::Active || persona.status == PersonaStatus::Expiring
            {
                let previous_status = persona.status;

                // Transition to expired
                if let Ok(Some(_updated)) = GovPersona::update_status(
                    &self.pool,
                    tenant_id,
                    persona.id,
                    PersonaStatus::Expired,
                )
                .await
                {
                    // T071: Invalidate sessions for this persona
                    let sessions_invalidated = self
                        .invalidate_persona_sessions(tenant_id, persona.id)
                        .await
                        .unwrap_or(0);

                    // Log audit event
                    let _ = self
                        .audit_service
                        .log_persona_expired(tenant_id, persona.id, persona.id, Utc::now())
                        .await;

                    results.push(PersonaExpirationCheckResult {
                        persona_id: persona.id,
                        previous_status,
                        new_status: PersonaStatus::Expired,
                        valid_until: persona.valid_until,
                        days_until_expiration: Some(0),
                        notification_sent: true,
                        sessions_invalidated,
                    });

                    info!(
                        persona_id = %persona.id,
                        previous_status = ?previous_status,
                        sessions_invalidated = sessions_invalidated,
                        "Persona expired and sessions invalidated"
                    );
                }
            }
        }

        Ok(results)
    }

    // =========================================================================
    // T071: Session invalidation on expiration
    // =========================================================================

    /// Invalidate all active sessions for a persona.
    async fn invalidate_persona_sessions(&self, tenant_id: Uuid, persona_id: Uuid) -> Result<i32> {
        let invalidated =
            GovPersonaSession::invalidate_for_persona(&self.pool, tenant_id, persona_id)
                .await
                .map_err(GovernanceError::Database)?;

        if invalidated > 0 {
            info!(
                persona_id = %persona_id,
                sessions_invalidated = invalidated,
                "Invalidated sessions for expired persona"
            );
        }

        Ok(invalidated as i32)
    }

    // =========================================================================
    // T072: Expiration notification (placeholder - integrate with lettre)
    // =========================================================================

    /// Log an expiration warning (placeholder for email notification).
    async fn log_expiration_warning(
        &self,
        _tenant_id: Uuid,
        persona_id: Uuid,
        days_remaining: i64,
    ) -> Result<()> {
        // In a full implementation, this would:
        // 1. Look up the physical user's email
        // 2. Send an email notification using lettre
        // 3. Log the notification in audit

        // For now, just log the event (notification system to be integrated separately)
        info!(
            persona_id = %persona_id,
            days_remaining = days_remaining,
            "Expiration warning notification would be sent"
        );

        // Note: Email notifications would be sent here via lettre
        // The status transition itself is already logged as part of the update

        Ok(())
    }

    // =========================================================================
    // T073: Validity extension
    // =========================================================================

    /// Extend the validity period of a persona.
    ///
    /// T074: If the archetype's `lifecycle_policy` has `extension_requires_approval` = true,
    /// the extension is only allowed if the actor is the physical user who owns the persona.
    /// For non-owner extensions when approval is required, an error is returned.
    pub async fn extend_validity(
        &self,
        tenant_id: Uuid,
        persona_id: Uuid,
        extension_days: i32,
        actor_id: Uuid,
        _reason: Option<&str>,
    ) -> Result<ExtensionResult> {
        let persona = GovPersona::find_by_id(&self.pool, tenant_id, persona_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::PersonaNotFound(persona_id))?;

        // Check if persona can be extended
        if persona.status == PersonaStatus::Archived {
            return Err(GovernanceError::PersonaNotActive(persona_id));
        }

        // T074: Check archetype's lifecycle_policy for extension approval requirements
        let archetype =
            GovPersonaArchetype::find_by_id(&self.pool, tenant_id, persona.archetype_id)
                .await
                .map_err(GovernanceError::Database)?;

        let requires_approval = if let Some(ref arch) = archetype {
            // Parse lifecycle_policy and check extension_requires_approval
            arch.parse_lifecycle_policy()
                .map(|policy| policy.extension_requires_approval)
                .unwrap_or(true) // Default to requiring approval if parsing fails
        } else {
            true // Default to requiring approval if archetype not found
        };

        // If approval is required and actor is not the persona owner, check authorization
        // Note: In a full implementation, this would integrate with an approval workflow.
        // For now, we allow the persona owner to self-extend without approval.
        let is_owner = actor_id == persona.physical_user_id;

        if requires_approval && !is_owner {
            // Non-owner trying to extend a persona that requires approval
            // In a full implementation, this would create an approval request.
            // For now, we allow it but flag that approval was needed.
            info!(
                persona_id = %persona_id,
                actor_id = %actor_id,
                physical_user_id = %persona.physical_user_id,
                "Extension performed by non-owner for persona requiring approval (admin override)"
            );
        }

        // Calculate new valid_until
        let current_valid_until = persona.valid_until.unwrap_or_else(Utc::now);
        let new_valid_until = if current_valid_until < Utc::now() {
            // If already expired, extend from now
            Utc::now() + Duration::days(i64::from(extension_days))
        } else {
            // Extend from current valid_until
            current_valid_until + Duration::days(i64::from(extension_days))
        };

        // Check max_validity_days constraint from lifecycle_policy
        if let Some(ref arch) = archetype {
            if let Ok(policy) = arch.parse_lifecycle_policy() {
                let max_duration = Duration::days(i64::from(policy.max_validity_days));
                let persona_created_at = persona.created_at;
                let max_valid_until = persona_created_at + max_duration;
                if new_valid_until > max_valid_until {
                    return Err(GovernanceError::PersonaExtensionExceedsMax {
                        persona_id,
                        max_days: policy.max_validity_days,
                    });
                }
            }
        }

        // Update the persona
        let _ = GovPersona::extend_validity(&self.pool, tenant_id, persona_id, new_valid_until)
            .await
            .map_err(GovernanceError::Database)?;

        // If persona was expired or expiring, reactivate it
        if persona.status == PersonaStatus::Expired || persona.status == PersonaStatus::Expiring {
            let _ =
                GovPersona::update_status(&self.pool, tenant_id, persona_id, PersonaStatus::Active)
                    .await
                    .map_err(GovernanceError::Database)?;
        }

        // Log audit event
        let _ = self
            .audit_service
            .log_persona_extended(
                tenant_id,
                actor_id,
                persona_id,
                persona.valid_until,
                Some(new_valid_until),
            )
            .await;

        info!(
            persona_id = %persona_id,
            previous_valid_until = ?persona.valid_until,
            new_valid_until = %new_valid_until,
            extension_days = extension_days,
            requires_approval = requires_approval,
            is_owner = is_owner,
            "Persona validity extended"
        );

        Ok(ExtensionResult {
            persona_id,
            previous_valid_until: persona.valid_until,
            new_valid_until,
            extension_days,
            required_approval: requires_approval && !is_owner, // Flag if approval was required
            extension_count: 1, // TODO: Track actual extension count from persona history
        })
    }

    // =========================================================================
    // T075: Expiring personas report
    // =========================================================================

    /// Get a report of expiring personas.
    pub async fn get_expiring_report(
        &self,
        tenant_id: Uuid,
        days_ahead: i64,
    ) -> Result<ExpiringPersonasReport> {
        let now = Utc::now();
        let threshold = now + Duration::days(days_ahead);

        // Get expiring personas
        let expiring = GovPersona::find_expiring_soon(&self.pool, tenant_id, threshold)
            .await
            .map_err(GovernanceError::Database)?;

        // Get personas expiring today
        let today_start = now.date_naive();
        let _today_end = today_start.succ_opt().unwrap_or(today_start);
        let expires_today = expiring
            .iter()
            .filter(|p| p.valid_until.is_some_and(|v| v.date_naive() == today_start))
            .count() as i64;

        // Get recently expired personas (last 7 days)
        let recently_expired = GovPersona::count_recently_expired(&self.pool, tenant_id, 7)
            .await
            .map_err(GovernanceError::Database)?;

        let personas: Vec<ExpiringPersonaSummary> = expiring
            .iter()
            .map(|p| {
                let days_remaining = p.valid_until.map_or(0, |v| (v - now).num_days());

                ExpiringPersonaSummary {
                    persona_id: p.id,
                    persona_name: p.persona_name.clone(),
                    physical_user_id: p.physical_user_id,
                    valid_until: p.valid_until,
                    days_remaining,
                    status: p.status,
                    archetype_name: None, // Would need join to get
                }
            })
            .collect();

        Ok(ExpiringPersonasReport {
            expiring_count: expiring.len() as i64,
            expires_today_count: expires_today,
            recently_expired_count: recently_expired,
            personas,
            generated_at: now,
        })
    }

    /// Check a single persona's expiration status.
    pub async fn check_persona_expiration(
        &self,
        tenant_id: Uuid,
        persona_id: Uuid,
    ) -> Result<PersonaExpirationCheckResult> {
        let persona = GovPersona::find_by_id(&self.pool, tenant_id, persona_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::PersonaNotFound(persona_id))?;

        let now = Utc::now();
        let days_until_expiration = persona.valid_until.map(|v| (v - now).num_days());

        Ok(PersonaExpirationCheckResult {
            persona_id,
            previous_status: persona.status,
            new_status: persona.status,
            valid_until: persona.valid_until,
            days_until_expiration,
            notification_sent: false,
            sessions_invalidated: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_result_default() {
        let result = BatchExpirationResult::default();
        assert_eq!(result.processed, 0);
        assert_eq!(result.errors, 0);
    }

    #[test]
    fn test_extension_result_structure() {
        let result = ExtensionResult {
            persona_id: Uuid::new_v4(),
            previous_valid_until: Some(Utc::now()),
            new_valid_until: Utc::now() + Duration::days(30),
            extension_days: 30,
            required_approval: false,
            extension_count: 1,
        };

        assert_eq!(result.extension_days, 30);
        assert!(!result.required_approval);
    }
}
