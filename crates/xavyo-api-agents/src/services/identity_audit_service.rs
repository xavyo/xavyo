//! Identity Audit Service for Workload Identity Federation (F121).
//!
//! Provides audit logging for all IAM operations related to workload identity federation.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::{info, instrument};
use uuid::Uuid;

use xavyo_db::models::{
    CreateIdentityAuditEvent, IdentityAuditEvent, IdentityAuditEventFilter, IdentityAuditEventType,
    IdentityAuditOutcome,
};

use crate::error::ApiAgentsError;

/// Service for identity audit operations.
#[derive(Clone)]
pub struct IdentityAuditService {
    pool: PgPool,
}

impl IdentityAuditService {
    /// Create a new identity audit service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Log a credential request event.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, agent_id = %agent_id))]
    pub async fn log_credential_request(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        provider_type: &str,
        role_identifier: &str,
        outcome: IdentityAuditOutcome,
        error_message: Option<&str>,
    ) -> Result<IdentityAuditEvent, ApiAgentsError> {
        let event_type = match outcome {
            IdentityAuditOutcome::Success => IdentityAuditEventType::CredentialIssued,
            IdentityAuditOutcome::Failure => IdentityAuditEventType::CredentialDenied,
        };

        let mut details = serde_json::json!({
            "role_identifier": role_identifier,
        });

        if let Some(err) = error_message {
            details["error"] = serde_json::json!(err);
        }

        let request = CreateIdentityAuditEvent {
            event_type,
            agent_id: Some(agent_id),
            user_id: None,
            provider_type: Some(provider_type.to_string()),
            operation: "assume_role".to_string(),
            resource_type: Some("role".to_string()),
            resource_id: None,
            details,
            outcome,
        };

        let event = IdentityAuditEvent::create(&self.pool, tenant_id, &request).await?;

        info!(
            event_id = %event.id,
            event_type = %event.event_type,
            outcome = %event.outcome,
            "Logged credential request event"
        );

        Ok(event)
    }

    /// Log a token verification event.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self), fields(tenant_id = %tenant_id, agent_id = ?agent_id))]
    pub async fn log_token_verification(
        &self,
        tenant_id: Uuid,
        agent_id: Option<Uuid>,
        provider_type: &str,
        outcome: IdentityAuditOutcome,
        subject: Option<&str>,
        issuer: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<IdentityAuditEvent, ApiAgentsError> {
        let event_type = match outcome {
            IdentityAuditOutcome::Success => IdentityAuditEventType::TokenVerified,
            IdentityAuditOutcome::Failure => IdentityAuditEventType::TokenRejected,
        };

        let mut details = serde_json::json!({});

        if let Some(sub) = subject {
            details["subject"] = serde_json::json!(sub);
        }
        if let Some(iss) = issuer {
            details["issuer"] = serde_json::json!(iss);
        }
        if let Some(err) = error_message {
            details["error"] = serde_json::json!(err);
        }

        let request = CreateIdentityAuditEvent {
            event_type,
            agent_id,
            user_id: None,
            provider_type: Some(provider_type.to_string()),
            operation: "verify_token".to_string(),
            resource_type: Some("token".to_string()),
            resource_id: None,
            details,
            outcome,
        };

        let event = IdentityAuditEvent::create(&self.pool, tenant_id, &request).await?;

        info!(
            event_id = %event.id,
            event_type = %event.event_type,
            outcome = %event.outcome,
            "Logged token verification event"
        );

        Ok(event)
    }

    /// Log a provider configuration change.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, user_id = %user_id))]
    pub async fn log_provider_change(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider_id: Uuid,
        provider_type: &str,
        operation: ProviderOperation,
        provider_name: &str,
    ) -> Result<IdentityAuditEvent, ApiAgentsError> {
        let (event_type, op_name) = match operation {
            ProviderOperation::Create => (IdentityAuditEventType::ProviderCreated, "create"),
            ProviderOperation::Update => (IdentityAuditEventType::ProviderUpdated, "update"),
            ProviderOperation::Delete => (IdentityAuditEventType::ProviderDeleted, "delete"),
        };

        let details = serde_json::json!({
            "provider_name": provider_name,
        });

        let request = CreateIdentityAuditEvent {
            event_type,
            agent_id: None,
            user_id: Some(user_id),
            provider_type: Some(provider_type.to_string()),
            operation: op_name.to_string(),
            resource_type: Some("identity_provider".to_string()),
            resource_id: Some(provider_id),
            details,
            outcome: IdentityAuditOutcome::Success,
        };

        let event = IdentityAuditEvent::create(&self.pool, tenant_id, &request).await?;

        info!(
            event_id = %event.id,
            provider_id = %provider_id,
            operation = op_name,
            "Logged provider change event"
        );

        Ok(event)
    }

    /// Log a role mapping change.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self), fields(tenant_id = %tenant_id, user_id = %user_id))]
    pub async fn log_mapping_change(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        mapping_id: Uuid,
        provider_type: &str,
        operation: MappingOperation,
        agent_type: Option<&str>,
        role_identifier: &str,
    ) -> Result<IdentityAuditEvent, ApiAgentsError> {
        let (event_type, op_name) = match operation {
            MappingOperation::Create => (IdentityAuditEventType::MappingCreated, "create"),
            MappingOperation::Update => (IdentityAuditEventType::MappingUpdated, "update"),
            MappingOperation::Delete => (IdentityAuditEventType::MappingDeleted, "delete"),
        };

        let details = serde_json::json!({
            "agent_type": agent_type,
            "role_identifier": role_identifier,
        });

        let request = CreateIdentityAuditEvent {
            event_type,
            agent_id: None,
            user_id: Some(user_id),
            provider_type: Some(provider_type.to_string()),
            operation: op_name.to_string(),
            resource_type: Some("role_mapping".to_string()),
            resource_id: Some(mapping_id),
            details,
            outcome: IdentityAuditOutcome::Success,
        };

        let event = IdentityAuditEvent::create(&self.pool, tenant_id, &request).await?;

        info!(
            event_id = %event.id,
            mapping_id = %mapping_id,
            operation = op_name,
            "Logged mapping change event"
        );

        Ok(event)
    }

    /// Log a health check event.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, provider_id = %provider_id))]
    pub async fn log_health_check(
        &self,
        tenant_id: Uuid,
        provider_id: Uuid,
        provider_type: &str,
        outcome: IdentityAuditOutcome,
        latency_ms: Option<i32>,
        error_message: Option<&str>,
    ) -> Result<IdentityAuditEvent, ApiAgentsError> {
        let mut details = serde_json::json!({});

        if let Some(latency) = latency_ms {
            details["latency_ms"] = serde_json::json!(latency);
        }
        if let Some(err) = error_message {
            details["error"] = serde_json::json!(err);
        }

        let request = CreateIdentityAuditEvent {
            event_type: IdentityAuditEventType::HealthCheck,
            agent_id: None,
            user_id: None,
            provider_type: Some(provider_type.to_string()),
            operation: "health_check".to_string(),
            resource_type: Some("identity_provider".to_string()),
            resource_id: Some(provider_id),
            details,
            outcome,
        };

        let event = IdentityAuditEvent::create(&self.pool, tenant_id, &request).await?;

        info!(
            event_id = %event.id,
            provider_id = %provider_id,
            outcome = %event.outcome,
            "Logged health check event"
        );

        Ok(event)
    }

    /// Log a cascade delete event (T044).
    #[instrument(skip(self), fields(tenant_id = %tenant_id, user_id = %user_id, provider_id = %provider_id))]
    pub async fn log_cascade_delete(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider_id: Uuid,
        provider_type: &str,
        deleted_mappings_count: u64,
    ) -> Result<IdentityAuditEvent, ApiAgentsError> {
        let details = serde_json::json!({
            "deleted_mappings_count": deleted_mappings_count,
            "cascade": true,
        });

        let request = CreateIdentityAuditEvent {
            event_type: IdentityAuditEventType::MappingDeleted,
            agent_id: None,
            user_id: Some(user_id),
            provider_type: Some(provider_type.to_string()),
            operation: "cascade_delete".to_string(),
            resource_type: Some("role_mappings".to_string()),
            resource_id: Some(provider_id),
            details,
            outcome: IdentityAuditOutcome::Success,
        };

        let event = IdentityAuditEvent::create(&self.pool, tenant_id, &request).await?;

        info!(
            event_id = %event.id,
            provider_id = %provider_id,
            deleted_mappings_count = deleted_mappings_count,
            "Logged cascade delete event"
        );

        Ok(event)
    }

    /// List audit events with optional filtering.
    pub async fn list_events(
        &self,
        tenant_id: Uuid,
        filter: &IdentityAuditEventFilter,
    ) -> Result<Vec<IdentityAuditEvent>, ApiAgentsError> {
        let events = IdentityAuditEvent::list(&self.pool, tenant_id, filter).await?;
        Ok(events)
    }

    /// Query audit events with pagination and return total count.
    pub async fn query_events(
        &self,
        tenant_id: Uuid,
        filter: &IdentityAuditEventFilter,
    ) -> Result<(Vec<IdentityAuditEvent>, i64), ApiAgentsError> {
        let events = IdentityAuditEvent::list(&self.pool, tenant_id, filter).await?;
        let total = IdentityAuditEvent::count(&self.pool, tenant_id, filter).await?;
        Ok((events, total))
    }

    /// Count audit events matching a filter.
    pub async fn count_events(
        &self,
        tenant_id: Uuid,
        filter: &IdentityAuditEventFilter,
    ) -> Result<i64, ApiAgentsError> {
        let count = IdentityAuditEvent::count(&self.pool, tenant_id, filter).await?;
        Ok(count)
    }

    /// Get a single audit event by ID.
    pub async fn get_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<IdentityAuditEvent>, ApiAgentsError> {
        let event = IdentityAuditEvent::get_by_id(&self.pool, tenant_id, event_id).await?;
        Ok(event)
    }

    /// Get events for a specific agent.
    pub async fn get_agent_events(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        limit: Option<i64>,
    ) -> Result<Vec<IdentityAuditEvent>, ApiAgentsError> {
        let filter = IdentityAuditEventFilter {
            agent_id: Some(agent_id),
            from,
            to,
            limit,
            ..Default::default()
        };

        self.list_events(tenant_id, &filter).await
    }

    /// Get events for a specific provider type.
    pub async fn get_provider_type_events(
        &self,
        tenant_id: Uuid,
        provider_type: &str,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        limit: Option<i64>,
    ) -> Result<Vec<IdentityAuditEvent>, ApiAgentsError> {
        let filter = IdentityAuditEventFilter {
            provider_type: Some(provider_type.to_string()),
            from,
            to,
            limit,
            ..Default::default()
        };

        self.list_events(tenant_id, &filter).await
    }

    /// Get failed events for monitoring.
    pub async fn get_failed_events(
        &self,
        tenant_id: Uuid,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        limit: Option<i64>,
    ) -> Result<Vec<IdentityAuditEvent>, ApiAgentsError> {
        let filter = IdentityAuditEventFilter {
            outcome: Some(IdentityAuditOutcome::Failure),
            from,
            to,
            limit,
            ..Default::default()
        };

        self.list_events(tenant_id, &filter).await
    }
}

/// Provider operation type for audit logging.
#[derive(Debug, Clone, Copy)]
pub enum ProviderOperation {
    /// Provider was created.
    Create,
    /// Provider was updated.
    Update,
    /// Provider was deleted.
    Delete,
}

/// Mapping operation type for audit logging.
#[derive(Debug, Clone, Copy)]
pub enum MappingOperation {
    /// Mapping was created.
    Create,
    /// Mapping was updated.
    Update,
    /// Mapping was deleted.
    Delete,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_operation() {
        let op = ProviderOperation::Create;
        assert!(matches!(op, ProviderOperation::Create));

        let op = ProviderOperation::Update;
        assert!(matches!(op, ProviderOperation::Update));

        let op = ProviderOperation::Delete;
        assert!(matches!(op, ProviderOperation::Delete));
    }

    #[test]
    fn test_mapping_operation() {
        let op = MappingOperation::Create;
        assert!(matches!(op, MappingOperation::Create));

        let op = MappingOperation::Update;
        assert!(matches!(op, MappingOperation::Update));

        let op = MappingOperation::Delete;
        assert!(matches!(op, MappingOperation::Delete));
    }
}
