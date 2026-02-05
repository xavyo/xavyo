//! Script Audit Service (F066).
//!
//! Records audit events for all script lifecycle actions.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{CreateScriptAuditEvent, GovScriptAuditEvent, ScriptAuditAction};
use xavyo_governance::error::Result;

/// Service for script audit trail operations.
pub struct ScriptAuditService {
    pool: PgPool,
}

/// Parameters for recording a script audit event.
#[derive(Debug, Clone)]
pub struct RecordScriptAuditParams {
    pub script_id: Option<Uuid>,
    pub action: ScriptAuditAction,
    pub actor_id: Uuid,
    pub details: Option<serde_json::Value>,
}

/// Parameters for listing audit events.
#[derive(Debug, Clone, Default)]
pub struct ListScriptAuditParams {
    pub script_id: Option<Uuid>,
    pub action: Option<ScriptAuditAction>,
    pub actor_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}

impl ScriptAuditService {
    /// Create a new script audit service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Record a script lifecycle audit event.
    pub async fn record_event(
        &self,
        tenant_id: Uuid,
        params: RecordScriptAuditParams,
    ) -> Result<GovScriptAuditEvent> {
        let input = CreateScriptAuditEvent {
            tenant_id,
            script_id: params.script_id,
            action: params.action,
            actor_id: params.actor_id,
            details: params.details,
        };

        let event = GovScriptAuditEvent::create(&self.pool, &input).await?;
        Ok(event)
    }

    /// Record a script creation event.
    pub async fn record_created(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        actor_id: Uuid,
        script_name: &str,
    ) -> Result<GovScriptAuditEvent> {
        self.record_event(
            tenant_id,
            RecordScriptAuditParams {
                script_id: Some(script_id),
                action: ScriptAuditAction::Created,
                actor_id,
                details: Some(serde_json::json!({
                    "script_name": script_name,
                })),
            },
        )
        .await
    }

    /// Record a script update event.
    pub async fn record_updated(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        actor_id: Uuid,
        changes: serde_json::Value,
    ) -> Result<GovScriptAuditEvent> {
        self.record_event(
            tenant_id,
            RecordScriptAuditParams {
                script_id: Some(script_id),
                action: ScriptAuditAction::Updated,
                actor_id,
                details: Some(changes),
            },
        )
        .await
    }

    /// Record a script deletion event.
    pub async fn record_deleted(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        actor_id: Uuid,
        script_name: &str,
    ) -> Result<GovScriptAuditEvent> {
        self.record_event(
            tenant_id,
            RecordScriptAuditParams {
                script_id: Some(script_id),
                action: ScriptAuditAction::Deleted,
                actor_id,
                details: Some(serde_json::json!({
                    "script_name": script_name,
                })),
            },
        )
        .await
    }

    /// Record a script activation event.
    pub async fn record_activated(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        actor_id: Uuid,
    ) -> Result<GovScriptAuditEvent> {
        self.record_event(
            tenant_id,
            RecordScriptAuditParams {
                script_id: Some(script_id),
                action: ScriptAuditAction::Activated,
                actor_id,
                details: None,
            },
        )
        .await
    }

    /// Record a script deactivation event.
    pub async fn record_deactivated(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        actor_id: Uuid,
    ) -> Result<GovScriptAuditEvent> {
        self.record_event(
            tenant_id,
            RecordScriptAuditParams {
                script_id: Some(script_id),
                action: ScriptAuditAction::Deactivated,
                actor_id,
                details: None,
            },
        )
        .await
    }

    /// Record a version creation event.
    pub async fn record_version_created(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        actor_id: Uuid,
        version_number: i32,
        change_description: Option<&str>,
    ) -> Result<GovScriptAuditEvent> {
        self.record_event(
            tenant_id,
            RecordScriptAuditParams {
                script_id: Some(script_id),
                action: ScriptAuditAction::VersionCreated,
                actor_id,
                details: Some(serde_json::json!({
                    "version_number": version_number,
                    "change_description": change_description,
                })),
            },
        )
        .await
    }

    /// Record a rollback event.
    pub async fn record_rollback(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        actor_id: Uuid,
        from_version: i32,
        to_version: i32,
        reason: Option<&str>,
    ) -> Result<GovScriptAuditEvent> {
        self.record_event(
            tenant_id,
            RecordScriptAuditParams {
                script_id: Some(script_id),
                action: ScriptAuditAction::Rollback,
                actor_id,
                details: Some(serde_json::json!({
                    "from_version": from_version,
                    "to_version": to_version,
                    "reason": reason,
                })),
            },
        )
        .await
    }

    /// Record a script binding event.
    pub async fn record_bound(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        actor_id: Uuid,
        binding_id: Uuid,
        connector_id: Uuid,
    ) -> Result<GovScriptAuditEvent> {
        self.record_event(
            tenant_id,
            RecordScriptAuditParams {
                script_id: Some(script_id),
                action: ScriptAuditAction::Bound,
                actor_id,
                details: Some(serde_json::json!({
                    "binding_id": binding_id,
                    "connector_id": connector_id,
                })),
            },
        )
        .await
    }

    /// Record a script unbinding event.
    pub async fn record_unbound(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        actor_id: Uuid,
        binding_id: Uuid,
        connector_id: Uuid,
    ) -> Result<GovScriptAuditEvent> {
        self.record_event(
            tenant_id,
            RecordScriptAuditParams {
                script_id: Some(script_id),
                action: ScriptAuditAction::Unbound,
                actor_id,
                details: Some(serde_json::json!({
                    "binding_id": binding_id,
                    "connector_id": connector_id,
                })),
            },
        )
        .await
    }

    /// List audit events for a tenant with optional filters.
    pub async fn list_events(
        &self,
        tenant_id: Uuid,
        params: &ListScriptAuditParams,
    ) -> Result<(Vec<GovScriptAuditEvent>, i64)> {
        use xavyo_db::models::ScriptAuditFilter;

        let filter = ScriptAuditFilter {
            script_id: params.script_id,
            action: params.action,
            actor_id: params.actor_id,
            from_date: params.from_date,
            to_date: params.to_date,
        };

        let result = GovScriptAuditEvent::list_by_tenant(
            &self.pool,
            tenant_id,
            &filter,
            params.limit,
            params.offset,
        )
        .await?;

        Ok(result)
    }

    /// List audit events for a specific script.
    pub async fn list_by_script(
        &self,
        tenant_id: Uuid,
        script_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovScriptAuditEvent>, i64)> {
        let result =
            GovScriptAuditEvent::list_by_script(&self.pool, script_id, tenant_id, limit, offset)
                .await?;
        Ok(result)
    }
}
