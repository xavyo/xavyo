//! AI Agent Audit Event model (F089 - AI Agent Security Platform).
//!
//! Provides an immutable audit trail for all agent activities, supporting
//! OWASP ASI01 (goal hijack prevention), ASI06 (memory poisoning), and
//! compliance requirements.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::net::IpAddr;
use uuid::Uuid;

/// Event types for AI agent audit logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAuditEventType {
    ToolInvocation,
    Authorization,
    ApprovalRequest,
    ApprovalDecision,
    AgentLifecycle,
}

impl std::fmt::Display for AiAuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiAuditEventType::ToolInvocation => write!(f, "tool_invocation"),
            AiAuditEventType::Authorization => write!(f, "authorization"),
            AiAuditEventType::ApprovalRequest => write!(f, "approval_request"),
            AiAuditEventType::ApprovalDecision => write!(f, "approval_decision"),
            AiAuditEventType::AgentLifecycle => write!(f, "agent_lifecycle"),
        }
    }
}

impl std::str::FromStr for AiAuditEventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tool_invocation" => Ok(AiAuditEventType::ToolInvocation),
            "authorization" => Ok(AiAuditEventType::Authorization),
            "approval_request" => Ok(AiAuditEventType::ApprovalRequest),
            "approval_decision" => Ok(AiAuditEventType::ApprovalDecision),
            "agent_lifecycle" => Ok(AiAuditEventType::AgentLifecycle),
            _ => Err(format!("Invalid audit event type: {s}")),
        }
    }
}

/// Decision outcomes for authorization events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAuditDecision {
    Allowed,
    Denied,
    Approved,
    Rejected,
    RequireApproval,
}

impl std::fmt::Display for AiAuditDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiAuditDecision::Allowed => write!(f, "allowed"),
            AiAuditDecision::Denied => write!(f, "denied"),
            AiAuditDecision::Approved => write!(f, "approved"),
            AiAuditDecision::Rejected => write!(f, "rejected"),
            AiAuditDecision::RequireApproval => write!(f, "require_approval"),
        }
    }
}

impl std::str::FromStr for AiAuditDecision {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "allowed" => Ok(AiAuditDecision::Allowed),
            "denied" => Ok(AiAuditDecision::Denied),
            "approved" => Ok(AiAuditDecision::Approved),
            "rejected" => Ok(AiAuditDecision::Rejected),
            "require_approval" => Ok(AiAuditDecision::RequireApproval),
            _ => Err(format!("Invalid audit decision: {s}")),
        }
    }
}

/// Outcome of a tool invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAuditOutcome {
    Success,
    Failure,
    Error,
    Timeout,
    Cancelled,
}

impl std::fmt::Display for AiAuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiAuditOutcome::Success => write!(f, "success"),
            AiAuditOutcome::Failure => write!(f, "failure"),
            AiAuditOutcome::Error => write!(f, "error"),
            AiAuditOutcome::Timeout => write!(f, "timeout"),
            AiAuditOutcome::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for AiAuditOutcome {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "success" => Ok(AiAuditOutcome::Success),
            "failure" => Ok(AiAuditOutcome::Failure),
            "error" => Ok(AiAuditOutcome::Error),
            "timeout" => Ok(AiAuditOutcome::Timeout),
            "cancelled" => Ok(AiAuditOutcome::Cancelled),
            _ => Err(format!("Invalid audit outcome: {s}")),
        }
    }
}

/// AI Agent Audit Event model representing an audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AiAgentAuditEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub event_type: String,
    pub conversation_id: Option<String>,
    pub session_id: Option<String>,
    pub user_instruction: Option<String>,
    pub agent_reasoning: Option<String>,
    pub tool_id: Option<Uuid>,
    pub tool_name: Option<String>,
    pub parameters: Option<serde_json::Value>,
    pub decision: Option<String>,
    pub decision_reason: Option<String>,
    pub policy_id: Option<Uuid>,
    pub outcome: Option<String>,
    pub error_message: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub duration_ms: Option<i32>,
    pub timestamp: DateTime<Utc>,
}

impl AiAgentAuditEvent {
    /// Returns the event type as an enum.
    pub fn event_type_enum(&self) -> Result<AiAuditEventType, String> {
        self.event_type.parse()
    }

    /// Returns the decision as an enum, if present.
    #[must_use]
    pub fn decision_enum(&self) -> Option<Result<AiAuditDecision, String>> {
        self.decision.as_ref().map(|d| d.parse())
    }

    /// Returns the outcome as an enum, if present.
    #[must_use]
    pub fn outcome_enum(&self) -> Option<Result<AiAuditOutcome, String>> {
        self.outcome.as_ref().map(|o| o.parse())
    }

    /// Get the source IP as parsed `IpAddr` (if present and valid).
    #[must_use]
    pub fn source_ip_addr(&self) -> Option<IpAddr> {
        self.source_ip.as_ref().and_then(|s| s.parse().ok())
    }
}

/// Request struct for logging an audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAuditEvent {
    pub agent_id: Option<Uuid>,
    pub event_type: String,
    pub conversation_id: Option<String>,
    pub session_id: Option<String>,
    pub user_instruction: Option<String>,
    pub agent_reasoning: Option<String>,
    pub tool_id: Option<Uuid>,
    pub tool_name: Option<String>,
    pub parameters: Option<serde_json::Value>,
    pub decision: Option<String>,
    pub decision_reason: Option<String>,
    pub policy_id: Option<Uuid>,
    pub outcome: Option<String>,
    pub error_message: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub duration_ms: Option<i32>,
}

/// Filter struct for querying audit events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAgentAuditEventFilter {
    pub agent_id: Option<Uuid>,
    pub event_type: Option<String>,
    pub decision: Option<String>,
    pub outcome: Option<String>,
    pub conversation_id: Option<String>,
    pub tool_id: Option<Uuid>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
}

impl AiAgentAuditEvent {
    /// Log a new audit event (INSERT only - events are immutable).
    pub async fn log(
        pool: &PgPool,
        tenant_id: Uuid,
        input: LogAuditEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO ai_agent_audit_events (
                tenant_id, agent_id, event_type, conversation_id, session_id,
                user_instruction, agent_reasoning, tool_id, tool_name, parameters,
                decision, decision_reason, policy_id, outcome, error_message,
                source_ip, user_agent, duration_ms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::inet, $17, $18)
            RETURNING id, tenant_id, agent_id, event_type, conversation_id, session_id,
                      user_instruction, agent_reasoning, tool_id, tool_name, parameters,
                      decision, decision_reason, policy_id, outcome, error_message,
                      source_ip::text, user_agent, duration_ms, timestamp
            ",
        )
        .bind(tenant_id)
        .bind(input.agent_id)
        .bind(&input.event_type)
        .bind(&input.conversation_id)
        .bind(&input.session_id)
        .bind(&input.user_instruction)
        .bind(&input.agent_reasoning)
        .bind(input.tool_id)
        .bind(&input.tool_name)
        .bind(&input.parameters)
        .bind(&input.decision)
        .bind(&input.decision_reason)
        .bind(input.policy_id)
        .bind(&input.outcome)
        .bind(&input.error_message)
        .bind(&input.source_ip)
        .bind(&input.user_agent)
        .bind(input.duration_ms)
        .fetch_one(pool)
        .await
    }

    /// Find an audit event by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, event_type, conversation_id, session_id,
                   user_instruction, agent_reasoning, tool_id, tool_name, parameters,
                   decision, decision_reason, policy_id, outcome, error_message,
                   source_ip::text, user_agent, duration_ms, timestamp
            FROM ai_agent_audit_events
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List audit events for a specific agent within a time range.
    pub async fn list_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let start = start.unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
        let end = end.unwrap_or_else(Utc::now);

        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, event_type, conversation_id, session_id,
                   user_instruction, agent_reasoning, tool_id, tool_name, parameters,
                   decision, decision_reason, policy_id, outcome, error_message,
                   source_ip::text, user_agent, duration_ms, timestamp
            FROM ai_agent_audit_events
            WHERE tenant_id = $1 AND agent_id = $2
              AND timestamp >= $3 AND timestamp <= $4
            ORDER BY timestamp DESC
            LIMIT $5
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(start)
        .bind(end)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// List audit events for a tenant with filtering.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &AiAgentAuditEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT id, tenant_id, agent_id, event_type, conversation_id, session_id,
                   user_instruction, agent_reasoning, tool_id, tool_name, parameters,
                   decision, decision_reason, policy_id, outcome, error_message,
                   source_ip::text, user_agent, duration_ms, timestamp
            FROM ai_agent_audit_events
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;
        let mut conditions = Vec::new();

        if filter.agent_id.is_some() {
            conditions.push(format!("agent_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.event_type.is_some() {
            conditions.push(format!("event_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.decision.is_some() {
            conditions.push(format!("decision = ${param_idx}"));
            param_idx += 1;
        }
        if filter.outcome.is_some() {
            conditions.push(format!("outcome = ${param_idx}"));
            param_idx += 1;
        }
        if filter.conversation_id.is_some() {
            conditions.push(format!("conversation_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.tool_id.is_some() {
            conditions.push(format!("tool_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.start_time.is_some() {
            conditions.push(format!("timestamp >= ${param_idx}"));
            param_idx += 1;
        }
        if filter.end_time.is_some() {
            conditions.push(format!("timestamp <= ${param_idx}"));
            param_idx += 1;
        }

        for condition in conditions {
            query.push_str(" AND ");
            query.push_str(&condition);
        }

        query.push_str(&format!(
            " ORDER BY timestamp DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut query_builder = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(agent_id) = filter.agent_id {
            query_builder = query_builder.bind(agent_id);
        }
        if let Some(ref event_type) = filter.event_type {
            query_builder = query_builder.bind(event_type);
        }
        if let Some(ref decision) = filter.decision {
            query_builder = query_builder.bind(decision);
        }
        if let Some(ref outcome) = filter.outcome {
            query_builder = query_builder.bind(outcome);
        }
        if let Some(ref conversation_id) = filter.conversation_id {
            query_builder = query_builder.bind(conversation_id);
        }
        if let Some(tool_id) = filter.tool_id {
            query_builder = query_builder.bind(tool_id);
        }
        if let Some(start_time) = filter.start_time {
            query_builder = query_builder.bind(start_time);
        }
        if let Some(end_time) = filter.end_time {
            query_builder = query_builder.bind(end_time);
        }

        query_builder = query_builder.bind(limit).bind(offset);

        query_builder.fetch_all(pool).await
    }

    /// Count audit events for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &AiAgentAuditEventFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) as count
            FROM ai_agent_audit_events
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;
        let mut conditions = Vec::new();

        if filter.agent_id.is_some() {
            conditions.push(format!("agent_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.event_type.is_some() {
            conditions.push(format!("event_type = ${param_idx}"));
            param_idx += 1;
        }
        if filter.decision.is_some() {
            conditions.push(format!("decision = ${param_idx}"));
            param_idx += 1;
        }
        if filter.outcome.is_some() {
            conditions.push(format!("outcome = ${param_idx}"));
            param_idx += 1;
        }
        if filter.conversation_id.is_some() {
            conditions.push(format!("conversation_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.tool_id.is_some() {
            conditions.push(format!("tool_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.start_time.is_some() {
            conditions.push(format!("timestamp >= ${param_idx}"));
            param_idx += 1;
        }
        if filter.end_time.is_some() {
            conditions.push(format!("timestamp <= ${param_idx}"));
        }

        for condition in conditions {
            query.push_str(" AND ");
            query.push_str(&condition);
        }

        let mut query_builder = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(agent_id) = filter.agent_id {
            query_builder = query_builder.bind(agent_id);
        }
        if let Some(ref event_type) = filter.event_type {
            query_builder = query_builder.bind(event_type);
        }
        if let Some(ref decision) = filter.decision {
            query_builder = query_builder.bind(decision);
        }
        if let Some(ref outcome) = filter.outcome {
            query_builder = query_builder.bind(outcome);
        }
        if let Some(ref conversation_id) = filter.conversation_id {
            query_builder = query_builder.bind(conversation_id);
        }
        if let Some(tool_id) = filter.tool_id {
            query_builder = query_builder.bind(tool_id);
        }
        if let Some(start_time) = filter.start_time {
            query_builder = query_builder.bind(start_time);
        }
        if let Some(end_time) = filter.end_time {
            query_builder = query_builder.bind(end_time);
        }

        query_builder.fetch_one(pool).await
    }

    /// Count audit events for a specific agent with optional time filter.
    pub async fn count_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<i64, sqlx::Error> {
        if let Some(since) = since {
            sqlx::query_scalar::<_, i64>(
                r"
                SELECT COUNT(*) as count
                FROM ai_agent_audit_events
                WHERE tenant_id = $1 AND agent_id = $2 AND timestamp >= $3
                ",
            )
            .bind(tenant_id)
            .bind(agent_id)
            .bind(since)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar::<_, i64>(
                r"
                SELECT COUNT(*) as count
                FROM ai_agent_audit_events
                WHERE tenant_id = $1 AND agent_id = $2
                ",
            )
            .bind(tenant_id)
            .bind(agent_id)
            .fetch_one(pool)
            .await
        }
    }

    /// Count distinct sessions for a specific agent with optional time filter.
    pub async fn count_distinct_sessions(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<i64, sqlx::Error> {
        if let Some(since) = since {
            sqlx::query_scalar::<_, i64>(
                r"
                SELECT COUNT(DISTINCT session_id) as count
                FROM ai_agent_audit_events
                WHERE tenant_id = $1 AND agent_id = $2 AND timestamp >= $3 AND session_id IS NOT NULL
                ",
            )
            .bind(tenant_id)
            .bind(agent_id)
            .bind(since)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar::<_, i64>(
                r"
                SELECT COUNT(DISTINCT session_id) as count
                FROM ai_agent_audit_events
                WHERE tenant_id = $1 AND agent_id = $2 AND session_id IS NOT NULL
                ",
            )
            .bind(tenant_id)
            .bind(agent_id)
            .fetch_one(pool)
            .await
        }
    }

    /// Get audit events for a specific conversation.
    pub async fn list_by_conversation(
        pool: &PgPool,
        tenant_id: Uuid,
        conversation_id: &str,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, event_type, conversation_id, session_id,
                   user_instruction, agent_reasoning, tool_id, tool_name, parameters,
                   decision, decision_reason, policy_id, outcome, error_message,
                   source_ip::text, user_agent, duration_ms, timestamp
            FROM ai_agent_audit_events
            WHERE tenant_id = $1 AND conversation_id = $2
            ORDER BY timestamp ASC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(conversation_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get recent denied/rejected events for security monitoring.
    pub async fn list_recent_denials(
        pool: &PgPool,
        tenant_id: Uuid,
        hours: i64,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let since = Utc::now() - chrono::Duration::hours(hours);

        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, event_type, conversation_id, session_id,
                   user_instruction, agent_reasoning, tool_id, tool_name, parameters,
                   decision, decision_reason, policy_id, outcome, error_message,
                   source_ip::text, user_agent, duration_ms, timestamp
            FROM ai_agent_audit_events
            WHERE tenant_id = $1
              AND timestamp >= $2
              AND decision IN ('denied', 'rejected')
            ORDER BY timestamp DESC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(since)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Get recent failed events for error monitoring.
    pub async fn list_recent_failures(
        pool: &PgPool,
        tenant_id: Uuid,
        hours: i64,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let since = Utc::now() - chrono::Duration::hours(hours);

        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, event_type, conversation_id, session_id,
                   user_instruction, agent_reasoning, tool_id, tool_name, parameters,
                   decision, decision_reason, policy_id, outcome, error_message,
                   source_ip::text, user_agent, duration_ms, timestamp
            FROM ai_agent_audit_events
            WHERE tenant_id = $1
              AND timestamp >= $2
              AND outcome IN ('failure', 'error', 'timeout')
            ORDER BY timestamp DESC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(since)
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_ai_audit_event_type_display() {
        assert_eq!(
            AiAuditEventType::ToolInvocation.to_string(),
            "tool_invocation"
        );
        assert_eq!(AiAuditEventType::Authorization.to_string(), "authorization");
        assert_eq!(
            AiAuditEventType::ApprovalRequest.to_string(),
            "approval_request"
        );
        assert_eq!(
            AiAuditEventType::ApprovalDecision.to_string(),
            "approval_decision"
        );
        assert_eq!(
            AiAuditEventType::AgentLifecycle.to_string(),
            "agent_lifecycle"
        );
    }

    #[test]
    fn test_ai_audit_event_type_from_str() {
        assert_eq!(
            "tool_invocation".parse::<AiAuditEventType>().unwrap(),
            AiAuditEventType::ToolInvocation
        );
        assert_eq!(
            "AUTHORIZATION".parse::<AiAuditEventType>().unwrap(),
            AiAuditEventType::Authorization
        );
        assert!("invalid".parse::<AiAuditEventType>().is_err());
    }

    #[test]
    fn test_ai_audit_decision_display() {
        assert_eq!(AiAuditDecision::Allowed.to_string(), "allowed");
        assert_eq!(AiAuditDecision::Denied.to_string(), "denied");
        assert_eq!(
            AiAuditDecision::RequireApproval.to_string(),
            "require_approval"
        );
    }

    #[test]
    fn test_ai_audit_decision_from_str() {
        assert_eq!(
            "allowed".parse::<AiAuditDecision>().unwrap(),
            AiAuditDecision::Allowed
        );
        assert_eq!(
            "DENIED".parse::<AiAuditDecision>().unwrap(),
            AiAuditDecision::Denied
        );
        assert!("invalid".parse::<AiAuditDecision>().is_err());
    }

    #[test]
    fn test_ai_audit_outcome_display() {
        assert_eq!(AiAuditOutcome::Success.to_string(), "success");
        assert_eq!(AiAuditOutcome::Failure.to_string(), "failure");
        assert_eq!(AiAuditOutcome::Timeout.to_string(), "timeout");
    }

    #[test]
    fn test_ai_audit_outcome_from_str() {
        assert_eq!(
            "success".parse::<AiAuditOutcome>().unwrap(),
            AiAuditOutcome::Success
        );
        assert_eq!(
            "ERROR".parse::<AiAuditOutcome>().unwrap(),
            AiAuditOutcome::Error
        );
        assert!("invalid".parse::<AiAuditOutcome>().is_err());
    }

    #[test]
    fn test_log_audit_event_serialization() {
        let input = LogAuditEvent {
            agent_id: Some(Uuid::new_v4()),
            event_type: "tool_invocation".to_string(),
            conversation_id: Some("conv-123".to_string()),
            session_id: Some("sess-456".to_string()),
            user_instruction: Some("Send follow-up email to customer".to_string()),
            agent_reasoning: Some("User requested email follow-up after sales call".to_string()),
            tool_id: Some(Uuid::new_v4()),
            tool_name: Some("send_email".to_string()),
            parameters: Some(json!({
                "to": "customer@example.com",
                "subject": "Follow-up",
                "body": "Thank you for your time..."
            })),
            decision: Some("allowed".to_string()),
            decision_reason: Some("Agent has permission for send_email tool".to_string()),
            policy_id: Some(Uuid::new_v4()),
            outcome: Some("success".to_string()),
            error_message: None,
            source_ip: Some("192.168.1.100".to_string()),
            user_agent: Some("AgentSDK/1.0".to_string()),
            duration_ms: Some(150),
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: LogAuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(input.event_type, deserialized.event_type);
        assert_eq!(input.conversation_id, deserialized.conversation_id);
        assert_eq!(input.decision, deserialized.decision);
        assert_eq!(input.outcome, deserialized.outcome);
    }

    #[test]
    fn test_log_audit_event_minimal() {
        let input = LogAuditEvent {
            agent_id: None,
            event_type: "agent_lifecycle".to_string(),
            conversation_id: None,
            session_id: None,
            user_instruction: None,
            agent_reasoning: None,
            tool_id: None,
            tool_name: None,
            parameters: None,
            decision: None,
            decision_reason: None,
            policy_id: None,
            outcome: None,
            error_message: None,
            source_ip: None,
            user_agent: None,
            duration_ms: None,
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"event_type\":\"agent_lifecycle\""));
    }

    #[test]
    fn test_ai_agent_audit_event_filter_serialization() {
        let filter = AiAgentAuditEventFilter {
            agent_id: Some(Uuid::new_v4()),
            event_type: Some("tool_invocation".to_string()),
            decision: Some("denied".to_string()),
            outcome: Some("failure".to_string()),
            conversation_id: Some("conv-789".to_string()),
            tool_id: Some(Uuid::new_v4()),
            start_time: Some(Utc::now() - chrono::Duration::days(7)),
            end_time: Some(Utc::now()),
        };

        let json = serde_json::to_string(&filter).unwrap();
        let deserialized: AiAgentAuditEventFilter = serde_json::from_str(&json).unwrap();

        assert_eq!(filter.event_type, deserialized.event_type);
        assert_eq!(filter.decision, deserialized.decision);
    }

    #[test]
    fn test_ai_agent_audit_event_filter_default() {
        let filter = AiAgentAuditEventFilter::default();

        assert!(filter.agent_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.decision.is_none());
        assert!(filter.start_time.is_none());
    }

    #[test]
    fn test_log_audit_event_ipv6() {
        let input = LogAuditEvent {
            agent_id: Some(Uuid::new_v4()),
            event_type: "authorization".to_string(),
            conversation_id: None,
            session_id: None,
            user_instruction: None,
            agent_reasoning: None,
            tool_id: None,
            tool_name: None,
            parameters: None,
            decision: Some("allowed".to_string()),
            decision_reason: None,
            policy_id: None,
            outcome: None,
            error_message: None,
            source_ip: Some("2001:db8::1".to_string()),
            user_agent: None,
            duration_ms: None,
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("2001:db8::1"));
    }

    #[test]
    fn test_log_audit_event_complex_parameters() {
        let complex_params = json!({
            "query": {
                "sql": "SELECT * FROM users WHERE status = $1",
                "params": ["active"]
            },
            "options": {
                "limit": 100,
                "offset": 0,
                "include_deleted": false
            },
            "metadata": {
                "request_id": "req-abc123",
                "correlation_id": "corr-xyz789"
            }
        });

        let input = LogAuditEvent {
            agent_id: Some(Uuid::new_v4()),
            event_type: "tool_invocation".to_string(),
            conversation_id: None,
            session_id: None,
            user_instruction: Some("List all active users".to_string()),
            agent_reasoning: Some("User requested user list for admin dashboard".to_string()),
            tool_id: Some(Uuid::new_v4()),
            tool_name: Some("query_database".to_string()),
            parameters: Some(complex_params.clone()),
            decision: Some("allowed".to_string()),
            decision_reason: None,
            policy_id: None,
            outcome: Some("success".to_string()),
            error_message: None,
            source_ip: None,
            user_agent: None,
            duration_ms: Some(45),
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: LogAuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(input.parameters, deserialized.parameters);
        assert_eq!(
            deserialized.parameters.as_ref().unwrap()["query"]["sql"],
            "SELECT * FROM users WHERE status = $1"
        );
    }

    #[test]
    fn test_log_audit_event_owasp_context() {
        // Test OWASP ASI01/ASI06 context fields
        let input = LogAuditEvent {
            agent_id: Some(Uuid::new_v4()),
            event_type: "tool_invocation".to_string(),
            conversation_id: Some("conv-secure-123".to_string()),
            session_id: Some("sess-secure-456".to_string()),
            user_instruction: Some("ORIGINAL: Transfer funds to account XYZ".to_string()),
            agent_reasoning: Some(
                "User authorized fund transfer after multi-factor authentication".to_string(),
            ),
            tool_id: Some(Uuid::new_v4()),
            tool_name: Some("transfer_funds".to_string()),
            parameters: Some(json!({
                "from_account": "ACC001",
                "to_account": "ACC002",
                "amount": 1000.00,
                "currency": "USD"
            })),
            decision: Some("require_approval".to_string()),
            decision_reason: Some("High-value transaction requires human approval".to_string()),
            policy_id: Some(Uuid::new_v4()),
            outcome: None,
            error_message: None,
            source_ip: Some("10.0.0.50".to_string()),
            user_agent: Some("FinanceAgent/2.0".to_string()),
            duration_ms: None,
        };

        // Verify all OWASP-related fields are present
        assert!(input.conversation_id.is_some());
        assert!(input.session_id.is_some());
        assert!(input.user_instruction.is_some());
        assert!(input.agent_reasoning.is_some());

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("ORIGINAL: Transfer funds"));
        assert!(json.contains("multi-factor authentication"));
    }
}
