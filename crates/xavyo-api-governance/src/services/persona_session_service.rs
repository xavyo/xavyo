//! Persona session service for governance API (F063).
//!
//! Handles context switching between personas, session management,
//! and tracking which persona is currently active for a user.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use xavyo_db::models::{GovPersona, GovPersonaArchetype, GovPersonaSession, UpsertPersonaSession};
use xavyo_governance::error::{GovernanceError, Result};

use super::PersonaAuditService;

/// Default session duration in hours.
const DEFAULT_SESSION_DURATION_HOURS: i64 = 8;

/// Context information returned after a switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextInfo {
    /// User ID (physical).
    pub user_id: Uuid,
    /// Operating mode: "persona" or "physical".
    pub operating_as: String,
    /// Active persona ID (None if operating as physical user).
    pub persona_id: Option<Uuid>,
    /// Active persona name (None if operating as physical user).
    pub persona_name: Option<String>,
    /// Active persona archetype name (None if operating as physical user).
    pub persona_archetype: Option<String>,
    /// Session ID.
    pub session_id: Uuid,
    /// Session expiration time.
    pub session_expires_at: chrono::DateTime<Utc>,
    /// Previous persona ID (if any).
    pub previous_persona_id: Option<Uuid>,
}

/// Claims to add to JWT when persona is active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaClaims {
    /// Active persona ID.
    pub active_persona_id: Uuid,
    /// Persona archetype name.
    pub persona_archetype: String,
    /// Persona name.
    pub persona_name: String,
    /// Effective identity ID for access checks.
    pub effective_identity_id: Uuid,
}

/// Service for persona session and context switching operations.
pub struct PersonaSessionService {
    pool: PgPool,
    audit_service: PersonaAuditService,
}

impl PersonaSessionService {
    /// Create a new persona session service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit_service: PersonaAuditService::new(pool.clone()),
            pool,
        }
    }

    // =========================================================================
    // T037: Core session operations
    // =========================================================================

    /// Switch context to a persona.
    ///
    /// Steps:
    /// 1. Validate persona exists and belongs to the user
    /// 2. Validate persona is in a switchable state (active)
    /// 3. Validate persona validity period
    /// 4. Create/update session record
    /// 5. Log audit event
    ///
    /// Returns context info for JWT enhancement.
    pub async fn switch_to_persona(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        persona_id: Uuid,
        reason: Option<String>,
        session_duration_hours: Option<i64>,
    ) -> Result<ContextInfo> {
        // 1. Get and validate persona
        let persona = self
            .get_persona_for_user(tenant_id, user_id, persona_id)
            .await?;

        // 2. Validate persona status (T038)
        if !persona.status.can_switch_to() {
            return Err(GovernanceError::PersonaNotActive(persona_id));
        }

        // 3. Validate validity period (T043)
        if let Some(valid_until) = persona.valid_until {
            if Utc::now() > valid_until {
                return Err(GovernanceError::PersonaExpired(persona_id));
            }
        }

        // Check valid_from
        if Utc::now() < persona.valid_from {
            return Err(GovernanceError::Validation(format!(
                "Persona {} is not yet valid (valid from: {})",
                persona_id, persona.valid_from
            )));
        }

        // Get current session to capture previous persona
        let current_session =
            GovPersonaSession::find_active_for_user(&self.pool, tenant_id, user_id).await?;
        let previous_persona_id = current_session.and_then(|s| s.active_persona_id);

        // 4. Create session (T040)
        let duration = session_duration_hours.unwrap_or(DEFAULT_SESSION_DURATION_HOURS);
        let expires_at = Utc::now() + Duration::hours(duration);

        let session_input = UpsertPersonaSession {
            active_persona_id: Some(persona_id),
            switch_reason: reason.clone(),
            expires_at,
        };

        let session =
            GovPersonaSession::upsert(&self.pool, tenant_id, user_id, session_input).await?;

        // Get archetype for context info
        let archetype =
            GovPersonaArchetype::find_by_id(&self.pool, tenant_id, persona.archetype_id)
                .await?
                .ok_or(GovernanceError::PersonaArchetypeNotFound(
                    persona.archetype_id,
                ))?;

        // 5. Log audit event (T042)
        self.audit_service
            .log_context_switched(
                tenant_id,
                user_id,                             // actor_id
                session.id,                          // session_id
                previous_persona_id,                 // from_persona_id
                Some(persona_id),                    // to_persona_id
                None,                                // from_persona_name (would need to look up)
                Some(persona.persona_name.as_str()), // to_persona_name
                reason.as_deref(),                   // switch_reason
                true,                                // new_jwt_issued
            )
            .await?;

        info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            persona_id = %persona_id,
            previous_persona_id = ?previous_persona_id,
            "User switched to persona context"
        );

        Ok(ContextInfo {
            user_id,
            operating_as: "persona".to_string(),
            persona_id: Some(persona_id),
            persona_name: Some(persona.persona_name),
            persona_archetype: Some(archetype.name),
            session_id: session.id,
            session_expires_at: session.expires_at,
            previous_persona_id,
        })
    }

    // =========================================================================
    // T041: Switch back to physical user
    // =========================================================================

    /// Switch back to operating as the physical user.
    ///
    /// Steps:
    /// 1. Get current session to find active persona
    /// 2. Create new session with no active persona
    /// 3. Log audit event
    pub async fn switch_back_to_physical(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        reason: Option<String>,
    ) -> Result<ContextInfo> {
        // Get current session
        let current_session =
            GovPersonaSession::find_active_for_user(&self.pool, tenant_id, user_id).await?;

        let previous_persona_id = current_session.and_then(|s| s.active_persona_id);

        // Create new session without active persona
        let session_input = UpsertPersonaSession {
            active_persona_id: None,
            switch_reason: reason.clone(),
            expires_at: Utc::now() + Duration::hours(DEFAULT_SESSION_DURATION_HOURS),
        };

        let session =
            GovPersonaSession::upsert(&self.pool, tenant_id, user_id, session_input).await?;

        // Log audit event
        if let Some(prev_id) = previous_persona_id {
            // Get persona name for audit
            let prev_persona = GovPersona::find_by_id(&self.pool, tenant_id, prev_id).await?;
            let prev_name = prev_persona.map(|p| p.persona_name).unwrap_or_default();

            self.audit_service
                .log_context_switched_back(
                    tenant_id,
                    user_id,           // actor_id
                    session.id,        // session_id
                    prev_id,           // from_persona_id
                    &prev_name,        // from_persona_name
                    reason.as_deref(), // switch_reason
                    true,              // new_jwt_issued
                )
                .await?;
        }

        info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            previous_persona_id = ?previous_persona_id,
            "User switched back to physical context"
        );

        Ok(ContextInfo {
            user_id,
            operating_as: "physical".to_string(),
            persona_id: None,
            persona_name: None,
            persona_archetype: None,
            session_id: session.id,
            session_expires_at: session.expires_at,
            previous_persona_id,
        })
    }

    // =========================================================================
    // Session queries
    // =========================================================================

    /// Get the current context for a user.
    pub async fn get_current_context(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ContextInfo>> {
        let session =
            GovPersonaSession::find_active_for_user(&self.pool, tenant_id, user_id).await?;

        let Some(session) = session else {
            return Ok(None);
        };

        // If persona is active, get its details
        let (persona_id, persona_name, persona_archetype) =
            if let Some(pid) = session.active_persona_id {
                let persona = GovPersona::find_by_id(&self.pool, tenant_id, pid)
                    .await?
                    .ok_or(GovernanceError::PersonaNotFound(pid))?;

                let archetype =
                    GovPersonaArchetype::find_by_id(&self.pool, tenant_id, persona.archetype_id)
                        .await?
                        .map(|a| a.name);

                (Some(pid), Some(persona.persona_name), archetype)
            } else {
                (None, None, None)
            };

        Ok(Some(ContextInfo {
            user_id,
            operating_as: if persona_id.is_some() {
                "persona".to_string()
            } else {
                "physical".to_string()
            },
            persona_id,
            persona_name,
            persona_archetype,
            session_id: session.id,
            session_expires_at: session.expires_at,
            previous_persona_id: session.previous_persona_id,
        }))
    }

    /// Get session history for a user.
    pub async fn get_session_history(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovPersonaSession>> {
        let sessions =
            GovPersonaSession::find_history_for_user(&self.pool, tenant_id, user_id, limit, offset)
                .await?;
        Ok(sessions)
    }

    /// Get sessions for a specific persona (for audit purposes).
    pub async fn get_sessions_for_persona(
        &self,
        tenant_id: Uuid,
        persona_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovPersonaSession>> {
        let sessions =
            GovPersonaSession::find_by_persona(&self.pool, tenant_id, persona_id, limit, offset)
                .await?;
        Ok(sessions)
    }

    // =========================================================================
    // T039: JWT enhancement helpers
    // =========================================================================

    /// Get persona claims for JWT enhancement.
    ///
    /// Returns None if user is operating as physical identity.
    pub async fn get_persona_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<PersonaClaims>> {
        let session =
            GovPersonaSession::find_active_for_user(&self.pool, tenant_id, user_id).await?;

        let Some(session) = session else {
            return Ok(None);
        };

        let Some(persona_id) = session.active_persona_id else {
            return Ok(None);
        };

        let persona = GovPersona::find_by_id(&self.pool, tenant_id, persona_id)
            .await?
            .ok_or(GovernanceError::PersonaNotFound(persona_id))?;

        let archetype =
            GovPersonaArchetype::find_by_id(&self.pool, tenant_id, persona.archetype_id)
                .await?
                .ok_or(GovernanceError::PersonaArchetypeNotFound(
                    persona.archetype_id,
                ))?;

        Ok(Some(PersonaClaims {
            active_persona_id: persona_id,
            persona_archetype: archetype.name,
            persona_name: persona.persona_name,
            effective_identity_id: persona_id,
        }))
    }

    /// Get the effective identity ID for access checks.
    ///
    /// Returns the active persona ID if one is active, otherwise the user ID.
    pub async fn get_effective_identity(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Uuid> {
        let session =
            GovPersonaSession::find_active_for_user(&self.pool, tenant_id, user_id).await?;

        let effective_id = session.and_then(|s| s.active_persona_id).unwrap_or(user_id);

        Ok(effective_id)
    }

    // =========================================================================
    // Session invalidation
    // =========================================================================

    /// Invalidate all sessions for a persona.
    ///
    /// Called when a persona is deactivated or archived.
    pub async fn invalidate_persona_sessions(
        &self,
        tenant_id: Uuid,
        persona_id: Uuid,
    ) -> Result<u64> {
        let count =
            GovPersonaSession::invalidate_by_persona(&self.pool, tenant_id, persona_id).await?;

        info!(
            tenant_id = %tenant_id,
            persona_id = %persona_id,
            sessions_invalidated = count,
            "Invalidated sessions for persona"
        );

        Ok(count)
    }

    /// Invalidate all sessions for a user.
    ///
    /// Called when a user is deactivated.
    pub async fn invalidate_user_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> Result<u64> {
        let count = GovPersonaSession::invalidate_by_user(&self.pool, tenant_id, user_id).await?;

        info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            sessions_invalidated = count,
            "Invalidated all sessions for user"
        );

        Ok(count)
    }

    /// Clean up expired sessions older than specified days.
    pub async fn cleanup_expired_sessions(&self, older_than_days: i32) -> Result<u64> {
        let count = GovPersonaSession::cleanup_expired(&self.pool, older_than_days).await?;

        info!(
            older_than_days = older_than_days,
            sessions_deleted = count,
            "Cleaned up expired persona sessions"
        );

        Ok(count)
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /// Get and validate that a persona belongs to the user.
    async fn get_persona_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        persona_id: Uuid,
    ) -> Result<GovPersona> {
        let persona = GovPersona::find_by_id(&self.pool, tenant_id, persona_id)
            .await?
            .ok_or(GovernanceError::PersonaNotFound(persona_id))?;

        // Validate persona belongs to this user
        if persona.physical_user_id != user_id {
            return Err(GovernanceError::PersonaNotOwnedByUser);
        }

        Ok(persona)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_info_serialization() {
        let context = ContextInfo {
            user_id: Uuid::new_v4(),
            operating_as: "persona".to_string(),
            persona_id: Some(Uuid::new_v4()),
            persona_name: Some("admin.john.doe".to_string()),
            persona_archetype: Some("Admin Persona".to_string()),
            session_id: Uuid::new_v4(),
            session_expires_at: Utc::now() + Duration::hours(8),
            previous_persona_id: None,
        };

        let json = serde_json::to_string(&context).unwrap();
        assert!(json.contains("admin.john.doe"));
        assert!(json.contains("persona"));
    }

    #[test]
    fn test_persona_claims_serialization() {
        let claims = PersonaClaims {
            active_persona_id: Uuid::new_v4(),
            persona_archetype: "Admin Persona".to_string(),
            persona_name: "admin.john.doe".to_string(),
            effective_identity_id: Uuid::new_v4(),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("active_persona_id"));
        assert!(json.contains("effective_identity_id"));
    }

    #[test]
    fn test_physical_context() {
        let context = ContextInfo {
            user_id: Uuid::new_v4(),
            operating_as: "physical".to_string(),
            persona_id: None,
            persona_name: None,
            persona_archetype: None,
            session_id: Uuid::new_v4(),
            session_expires_at: Utc::now() + Duration::hours(8),
            previous_persona_id: Some(Uuid::new_v4()),
        };

        assert_eq!(context.operating_as, "physical");
        assert!(context.persona_id.is_none());
        assert!(context.previous_persona_id.is_some());
    }
}
