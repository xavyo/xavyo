//! Audit service for logging and querying agent activities.
//!
//! Provides immutable audit trail for OWASP ASI compliance.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{AuditEventResponse, AuditFilter, AuditListResponse};
use xavyo_db::models::ai_agent::AiAgent;
use xavyo_db::models::ai_agent_audit_event::{
    AiAgentAuditEvent, AiAgentAuditEventFilter, LogAuditEvent,
};

/// Service for audit logging and queries.
#[derive(Clone)]
pub struct AuditService {
    pool: PgPool,
}

impl AuditService {
    /// Create a new `AuditService`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Log an authorization event.
    #[allow(clippy::too_many_arguments)]
    pub async fn log_authorization(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_id: Option<Uuid>,
        tool_name: &str,
        parameters: Option<serde_json::Value>,
        decision: &str,
        reason: &str,
        conversation_id: Option<&str>,
        session_id: Option<&str>,
        user_instruction: Option<&str>,
        source_ip: Option<&str>,
        duration_ms: i32,
    ) -> Result<Uuid, ApiAgentsError> {
        let input = LogAuditEvent {
            agent_id: Some(agent_id),
            event_type: "authorization".to_string(),
            conversation_id: conversation_id.map(String::from),
            session_id: session_id.map(String::from),
            user_instruction: user_instruction.map(String::from),
            agent_reasoning: None,
            tool_id,
            tool_name: Some(tool_name.to_string()),
            parameters,
            decision: Some(decision.to_string()),
            decision_reason: Some(reason.to_string()),
            policy_id: None,
            outcome: None,
            error_message: None,
            source_ip: source_ip.map(String::from),
            user_agent: None,
            duration_ms: Some(duration_ms),
        };

        let event = AiAgentAuditEvent::log(&self.pool, tenant_id, input).await?;

        Ok(event.id)
    }

    /// Log a tool invocation event (for MCP calls).
    pub async fn log_tool_invocation(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_id: Uuid,
        tool_name: &str,
        parameters: &serde_json::Value,
        context: Option<&serde_json::Value>,
    ) -> Result<Uuid, ApiAgentsError> {
        let (conversation_id, session_id, user_instruction) = if let Some(ctx) = context {
            (
                ctx.get("conversation_id")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                ctx.get("session_id")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                ctx.get("user_instruction")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            )
        } else {
            (None, None, None)
        };

        let input = LogAuditEvent {
            agent_id: Some(agent_id),
            event_type: "tool_invocation".to_string(),
            conversation_id,
            session_id,
            user_instruction,
            agent_reasoning: None,
            tool_id: Some(tool_id),
            tool_name: Some(tool_name.to_string()),
            parameters: Some(parameters.clone()),
            decision: Some("executed".to_string()),
            decision_reason: None,
            policy_id: None,
            outcome: Some("success".to_string()),
            error_message: None,
            source_ip: None,
            user_agent: None,
            duration_ms: None,
        };

        let event = AiAgentAuditEvent::log(&self.pool, tenant_id, input).await?;

        Ok(event.id)
    }

    /// Log a certificate lifecycle event (issuance, renewal, revocation).
    #[allow(clippy::too_many_arguments)]
    pub async fn log_certificate_event(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        event_type: &str,
        certificate_id: Option<Uuid>,
        serial_number: Option<&str>,
        outcome: &str,
        details: Option<serde_json::Value>,
        created_by: Option<Uuid>,
    ) -> Result<Uuid, ApiAgentsError> {
        let input = LogAuditEvent {
            agent_id: Some(agent_id),
            event_type: event_type.to_string(),
            conversation_id: None,
            session_id: None,
            user_instruction: None,
            agent_reasoning: None,
            tool_id: certificate_id, // Re-use tool_id field for certificate_id
            tool_name: serial_number.map(String::from), // Re-use tool_name for serial_number
            parameters: details,
            decision: Some(outcome.to_string()),
            decision_reason: created_by.map(|u| format!("Requested by user {u}")),
            policy_id: None,
            outcome: Some(outcome.to_string()),
            error_message: None,
            source_ip: None,
            user_agent: None,
            duration_ms: None,
        };

        let event = AiAgentAuditEvent::log(&self.pool, tenant_id, input).await?;

        Ok(event.id)
    }

    /// Query audit events for an agent.
    pub async fn query_by_agent(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        filter: AuditFilter,
    ) -> Result<AuditListResponse, ApiAgentsError> {
        // Verify agent exists
        AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        let db_filter = AiAgentAuditEventFilter {
            agent_id: Some(agent_id),
            event_type: filter.event_type,
            decision: filter.decision,
            outcome: None,
            conversation_id: None,
            tool_id: None,
            start_time: filter.start_time,
            end_time: filter.end_time,
        };

        let limit = i64::from(filter.limit.min(1000));
        let offset = i64::from(filter.offset.max(0));

        let events =
            AiAgentAuditEvent::list_by_tenant(&self.pool, tenant_id, &db_filter, limit, offset)
                .await?;
        let total = AiAgentAuditEvent::count_by_tenant(&self.pool, tenant_id, &db_filter).await?;

        Ok(AuditListResponse {
            events: events.into_iter().map(|e| self.to_response(e)).collect(),
            total,
            limit: filter.limit,
            offset: filter.offset,
        })
    }

    /// Convert audit event to response DTO.
    fn to_response(&self, event: AiAgentAuditEvent) -> AuditEventResponse {
        AuditEventResponse {
            id: event.id,
            agent_id: event.agent_id.unwrap_or_default(),
            event_type: event.event_type,
            conversation_id: event.conversation_id,
            session_id: event.session_id,
            tool_name: event.tool_name,
            decision: event.decision,
            decision_reason: event.decision_reason,
            outcome: event.outcome,
            timestamp: event.timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_audit_event_response_fields() {
        // Test that AuditEventResponse has the expected structure
        use crate::models::AuditEventResponse;
        use uuid::Uuid;

        let response = AuditEventResponse {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            event_type: "authorization".to_string(),
            conversation_id: Some("conv-123".to_string()),
            session_id: Some("sess-456".to_string()),
            tool_name: Some("send_email".to_string()),
            decision: Some("allow".to_string()),
            decision_reason: Some("Agent has permission".to_string()),
            outcome: None,
            timestamp: chrono::Utc::now(),
        };

        assert_eq!(response.event_type, "authorization");
        assert_eq!(response.decision, Some("allow".to_string()));
    }
}
