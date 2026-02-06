//! Persona audit service for governance API (F063).
//!
//! Provides audit trail operations for persona-related actions including
//! logging events and querying audit history.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use xavyo_db::models::{
    ArchetypeEventData, AttributesPropagatedEventData, ContextSwitchedEventData,
    CreatePersonaAuditEvent, GovPersonaAuditEvent, PersonaAuditEventFilter, PersonaAuditEventType,
    PersonaCreatedEventData,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for persona audit event operations.
pub struct PersonaAuditService {
    pool: PgPool,
}

impl PersonaAuditService {
    /// Create a new audit service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // =========================================================================
    // Query methods
    // =========================================================================

    /// Get an audit event by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<GovPersonaAuditEvent> {
        GovPersonaAuditEvent::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::PersonaAuditEventNotFound(id))
    }

    /// List audit events with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &PersonaAuditEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovPersonaAuditEvent>, i64)> {
        let items =
            GovPersonaAuditEvent::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await?;
        let total = GovPersonaAuditEvent::count_by_tenant(&self.pool, tenant_id, filter).await?;
        Ok((items, total))
    }

    /// List audit events for a specific persona.
    pub async fn list_for_persona(
        &self,
        tenant_id: Uuid,
        persona_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovPersonaAuditEvent>> {
        let events =
            GovPersonaAuditEvent::find_by_persona(&self.pool, tenant_id, persona_id, limit, offset)
                .await?;
        Ok(events)
    }

    /// List audit events for a specific archetype.
    pub async fn list_for_archetype(
        &self,
        tenant_id: Uuid,
        archetype_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovPersonaAuditEvent>> {
        let events = GovPersonaAuditEvent::find_by_archetype(
            &self.pool,
            tenant_id,
            archetype_id,
            limit,
            offset,
        )
        .await?;
        Ok(events)
    }

    /// List audit events by actor (who performed actions).
    pub async fn list_by_actor(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovPersonaAuditEvent>, i64)> {
        let filter = PersonaAuditEventFilter {
            actor_id: Some(actor_id),
            ..Default::default()
        };
        self.list(tenant_id, &filter, limit, offset).await
    }

    /// List audit events within a date range.
    pub async fn list_by_date_range(
        &self,
        tenant_id: Uuid,
        from_date: DateTime<Utc>,
        to_date: DateTime<Utc>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovPersonaAuditEvent>, i64)> {
        let filter = PersonaAuditEventFilter {
            from_date: Some(from_date),
            to_date: Some(to_date),
            ..Default::default()
        };
        self.list(tenant_id, &filter, limit, offset).await
    }

    /// List audit events by event type.
    pub async fn list_by_event_type(
        &self,
        tenant_id: Uuid,
        event_type: PersonaAuditEventType,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovPersonaAuditEvent>, i64)> {
        let filter = PersonaAuditEventFilter {
            event_type: Some(event_type),
            ..Default::default()
        };
        self.list(tenant_id, &filter, limit, offset).await
    }

    // =========================================================================
    // Logging methods - Persona lifecycle events
    // =========================================================================

    /// Log a persona creation event.
    pub async fn log_persona_created(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        archetype_id: Uuid,
        physical_user_id: Uuid,
        persona_name: &str,
        initial_attributes: serde_json::Value,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<GovPersonaAuditEvent> {
        let data = PersonaCreatedEventData {
            persona_id,
            archetype_id,
            physical_user_id,
            persona_name: persona_name.to_string(),
            initial_attributes,
            valid_from,
            valid_until,
        };

        let event =
            GovPersonaAuditEvent::log_persona_created(&self.pool, tenant_id, actor_id, data)
                .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            event_type = "persona_created",
            "Persona audit event logged"
        );

        Ok(event)
    }

    /// Log a persona activation event.
    pub async fn log_persona_activated(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        reason: Option<&str>,
    ) -> Result<GovPersonaAuditEvent> {
        let event = self
            .log_persona_event(
                tenant_id,
                actor_id,
                persona_id,
                PersonaAuditEventType::PersonaActivated,
                serde_json::json!({
                    "reason": reason.unwrap_or("Manual activation")
                }),
            )
            .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            event_type = "persona_activated",
            "Persona audit event logged"
        );

        Ok(event)
    }

    /// Log a persona deactivation event.
    pub async fn log_persona_deactivated(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        reason: &str,
    ) -> Result<GovPersonaAuditEvent> {
        let event = self
            .log_persona_event(
                tenant_id,
                actor_id,
                persona_id,
                PersonaAuditEventType::PersonaDeactivated,
                serde_json::json!({
                    "reason": reason
                }),
            )
            .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            event_type = "persona_deactivated",
            "Persona audit event logged"
        );

        Ok(event)
    }

    /// Log a persona suspension event.
    ///
    /// Note: Suspension is logged as a deactivation with suspension-specific details.
    pub async fn log_persona_suspended(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        reason: &str,
        suspended_until: Option<DateTime<Utc>>,
    ) -> Result<GovPersonaAuditEvent> {
        let event = self
            .log_persona_event(
                tenant_id,
                actor_id,
                persona_id,
                PersonaAuditEventType::PersonaDeactivated,
                serde_json::json!({
                    "action": "suspended",
                    "reason": reason,
                    "suspended_until": suspended_until
                }),
            )
            .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            event_type = "persona_suspended",
            "Persona audit event logged"
        );

        Ok(event)
    }

    /// Log a persona expiration event.
    pub async fn log_persona_expired(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        expired_at: DateTime<Utc>,
    ) -> Result<GovPersonaAuditEvent> {
        let event = self
            .log_persona_event(
                tenant_id,
                actor_id,
                persona_id,
                PersonaAuditEventType::PersonaExpired,
                serde_json::json!({
                    "expired_at": expired_at.to_rfc3339()
                }),
            )
            .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            event_type = "persona_expired",
            "Persona audit event logged"
        );

        Ok(event)
    }

    /// Log a persona extension event.
    pub async fn log_persona_extended(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        old_valid_until: Option<DateTime<Utc>>,
        new_valid_until: Option<DateTime<Utc>>,
    ) -> Result<GovPersonaAuditEvent> {
        let event = self
            .log_persona_event(
                tenant_id,
                actor_id,
                persona_id,
                PersonaAuditEventType::PersonaExtended,
                serde_json::json!({
                    "old_valid_until": old_valid_until.map(|d| d.to_rfc3339()),
                    "new_valid_until": new_valid_until.map(|d| d.to_rfc3339())
                }),
            )
            .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            event_type = "persona_extended",
            "Persona audit event logged"
        );

        Ok(event)
    }

    /// Log a persona archive event.
    pub async fn log_persona_archived(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        reason: &str,
    ) -> Result<GovPersonaAuditEvent> {
        let event = self
            .log_persona_event(
                tenant_id,
                actor_id,
                persona_id,
                PersonaAuditEventType::PersonaArchived,
                serde_json::json!({
                    "reason": reason
                }),
            )
            .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            event_type = "persona_archived",
            "Persona audit event logged"
        );

        Ok(event)
    }

    // =========================================================================
    // Logging methods - Context switching events
    // =========================================================================

    /// Log a context switch event (user switches to a persona).
    pub async fn log_context_switched(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        session_id: Uuid,
        from_persona_id: Option<Uuid>,
        to_persona_id: Option<Uuid>,
        from_persona_name: Option<&str>,
        to_persona_name: Option<&str>,
        switch_reason: Option<&str>,
        new_jwt_issued: bool,
    ) -> Result<GovPersonaAuditEvent> {
        let data = ContextSwitchedEventData {
            session_id,
            from_persona_id,
            to_persona_id,
            from_persona_name: from_persona_name.map(std::string::ToString::to_string),
            to_persona_name: to_persona_name.map(std::string::ToString::to_string),
            switch_reason: switch_reason.map(std::string::ToString::to_string),
            new_jwt_issued,
        };

        let event =
            GovPersonaAuditEvent::log_context_switched(&self.pool, tenant_id, actor_id, data)
                .await?;

        info!(
            event_id = %event.id,
            from_persona = ?from_persona_id,
            to_persona = ?to_persona_id,
            event_type = "context_switched",
            "Context switch audit event logged"
        );

        Ok(event)
    }

    /// Log a context switch back event (user returns from persona to physical identity).
    pub async fn log_context_switched_back(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        session_id: Uuid,
        from_persona_id: Uuid,
        from_persona_name: &str,
        switch_reason: Option<&str>,
        new_jwt_issued: bool,
    ) -> Result<GovPersonaAuditEvent> {
        let data = ContextSwitchedEventData {
            session_id,
            from_persona_id: Some(from_persona_id),
            to_persona_id: None,
            from_persona_name: Some(from_persona_name.to_string()),
            to_persona_name: None,
            switch_reason: switch_reason.map(std::string::ToString::to_string),
            new_jwt_issued,
        };

        let event =
            GovPersonaAuditEvent::log_context_switched_back(&self.pool, tenant_id, actor_id, data)
                .await?;

        info!(
            event_id = %event.id,
            from_persona = %from_persona_id,
            event_type = "context_switched_back",
            "Context switch back audit event logged"
        );

        Ok(event)
    }

    // =========================================================================
    // Logging methods - Attribute propagation events
    // =========================================================================

    /// Log an attributes propagated event.
    pub async fn log_attributes_propagated(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        physical_user_id: Uuid,
        changed_attributes: serde_json::Map<String, serde_json::Value>,
        trigger: &str,
    ) -> Result<GovPersonaAuditEvent> {
        let data = AttributesPropagatedEventData {
            physical_user_id,
            persona_id,
            changed_attributes,
            trigger: trigger.to_string(),
        };

        let event =
            GovPersonaAuditEvent::log_attributes_propagated(&self.pool, tenant_id, actor_id, data)
                .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            trigger = %trigger,
            event_type = "attributes_propagated",
            "Attributes propagation audit event logged"
        );

        Ok(event)
    }

    // =========================================================================
    // Logging methods - Archetype events
    // =========================================================================

    /// Log an archetype creation event.
    pub async fn log_archetype_created(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        archetype_id: Uuid,
        name: &str,
    ) -> Result<GovPersonaAuditEvent> {
        let data = ArchetypeEventData {
            archetype_id,
            name: name.to_string(),
            changes: None,
        };

        let event = GovPersonaAuditEvent::log_archetype_event(
            &self.pool,
            tenant_id,
            actor_id,
            PersonaAuditEventType::ArchetypeCreated,
            data,
        )
        .await?;

        info!(
            event_id = %event.id,
            archetype_id = %archetype_id,
            event_type = "archetype_created",
            "Archetype audit event logged"
        );

        Ok(event)
    }

    /// Log an archetype update event.
    pub async fn log_archetype_updated(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        archetype_id: Uuid,
        name: &str,
        changes: serde_json::Value,
    ) -> Result<GovPersonaAuditEvent> {
        let data = ArchetypeEventData {
            archetype_id,
            name: name.to_string(),
            changes: Some(changes),
        };

        let event = GovPersonaAuditEvent::log_archetype_event(
            &self.pool,
            tenant_id,
            actor_id,
            PersonaAuditEventType::ArchetypeUpdated,
            data,
        )
        .await?;

        info!(
            event_id = %event.id,
            archetype_id = %archetype_id,
            event_type = "archetype_updated",
            "Archetype audit event logged"
        );

        Ok(event)
    }

    /// Log an archetype deletion event.
    pub async fn log_archetype_deleted(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        archetype_id: Uuid,
        name: &str,
    ) -> Result<GovPersonaAuditEvent> {
        let data = ArchetypeEventData {
            archetype_id,
            name: name.to_string(),
            changes: None,
        };

        let event = GovPersonaAuditEvent::log_archetype_event(
            &self.pool,
            tenant_id,
            actor_id,
            PersonaAuditEventType::ArchetypeDeleted,
            data,
        )
        .await?;

        info!(
            event_id = %event.id,
            archetype_id = %archetype_id,
            event_type = "archetype_deleted",
            "Archetype audit event logged"
        );

        Ok(event)
    }

    // =========================================================================
    // Logging methods - Link events
    // =========================================================================

    /// Log an entitlement added event.
    pub async fn log_entitlement_added(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        entitlement_id: Uuid,
        entitlement_name: &str,
    ) -> Result<GovPersonaAuditEvent> {
        let event = self
            .log_persona_event(
                tenant_id,
                actor_id,
                persona_id,
                PersonaAuditEventType::EntitlementAdded,
                serde_json::json!({
                    "entitlement_id": entitlement_id,
                    "entitlement_name": entitlement_name
                }),
            )
            .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            entitlement_id = %entitlement_id,
            event_type = "entitlement_added",
            "Entitlement added audit event logged"
        );

        Ok(event)
    }

    /// Log an entitlement removed event.
    pub async fn log_entitlement_removed(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        entitlement_id: Uuid,
        entitlement_name: &str,
        reason: &str,
    ) -> Result<GovPersonaAuditEvent> {
        let event = self
            .log_persona_event(
                tenant_id,
                actor_id,
                persona_id,
                PersonaAuditEventType::EntitlementRemoved,
                serde_json::json!({
                    "entitlement_id": entitlement_id,
                    "entitlement_name": entitlement_name,
                    "reason": reason
                }),
            )
            .await?;

        info!(
            event_id = %event.id,
            persona_id = %persona_id,
            entitlement_id = %entitlement_id,
            event_type = "entitlement_removed",
            "Entitlement removed audit event logged"
        );

        Ok(event)
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /// Generic helper to log a persona-related event.
    async fn log_persona_event(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
        event_type: PersonaAuditEventType,
        event_data: serde_json::Value,
    ) -> Result<GovPersonaAuditEvent> {
        let input = CreatePersonaAuditEvent {
            persona_id: Some(persona_id),
            archetype_id: None,
            event_type,
            actor_id,
            event_data,
        };

        let event = GovPersonaAuditEvent::create(&self.pool, tenant_id, input).await?;
        Ok(event)
    }

    /// Get reference to the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_service_creation() {
        // Just verify the service can be constructed (will panic without Tokio for actual DB)
        // This is a compile-time check that the service structure is correct
        let _service_type: fn(PgPool) -> PersonaAuditService = PersonaAuditService::new;
    }

    #[test]
    fn test_persona_created_event_data_structure() {
        let data = PersonaCreatedEventData {
            persona_id: Uuid::new_v4(),
            archetype_id: Uuid::new_v4(),
            physical_user_id: Uuid::new_v4(),
            persona_name: "admin.test.user".to_string(),
            initial_attributes: serde_json::json!({"department": "IT"}),
            valid_from: Utc::now(),
            valid_until: Some(Utc::now() + chrono::Duration::days(365)),
        };

        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["persona_name"], "admin.test.user");
        assert!(json["valid_until"].is_string());
    }

    #[test]
    fn test_context_switched_event_data_structure() {
        let data = ContextSwitchedEventData {
            session_id: Uuid::new_v4(),
            from_persona_id: None,
            to_persona_id: Some(Uuid::new_v4()),
            from_persona_name: None,
            to_persona_name: Some("admin.user".to_string()),
            switch_reason: Some("Administrative task".to_string()),
            new_jwt_issued: true,
        };

        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["new_jwt_issued"], true);
        assert!(json["from_persona_id"].is_null());
        assert!(json["to_persona_id"].is_string());
    }

    #[test]
    fn test_attributes_propagated_event_data_structure() {
        let mut changed = serde_json::Map::new();
        changed.insert("surname".to_string(), serde_json::json!("NewSurname"));

        let data = AttributesPropagatedEventData {
            physical_user_id: Uuid::new_v4(),
            persona_id: Uuid::new_v4(),
            changed_attributes: changed,
            trigger: "user_update".to_string(),
        };

        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["trigger"], "user_update");
        assert_eq!(json["changed_attributes"]["surname"], "NewSurname");
    }

    #[test]
    fn test_archetype_event_data_structure() {
        let data = ArchetypeEventData {
            archetype_id: Uuid::new_v4(),
            name: "Admin Persona".to_string(),
            changes: Some(serde_json::json!({"naming_pattern": "admin.{username}"})),
        };

        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["name"], "Admin Persona");
        assert!(json["changes"].is_object());
    }

    #[test]
    fn test_filter_construction() {
        let filter = PersonaAuditEventFilter {
            persona_id: Some(Uuid::new_v4()),
            event_type: Some(PersonaAuditEventType::PersonaCreated),
            from_date: Some(Utc::now() - chrono::Duration::days(7)),
            to_date: Some(Utc::now()),
            ..Default::default()
        };

        assert!(filter.persona_id.is_some());
        assert!(filter.event_type.is_some());
        assert!(filter.from_date.is_some());
        assert!(filter.to_date.is_some());
        assert!(filter.archetype_id.is_none());
        assert!(filter.actor_id.is_none());
    }
}
