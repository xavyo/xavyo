//! AI Agent Approval Request model (F092 - Human-in-the-Loop Approval System).
//!
//! Represents pending human decisions on AI agent tool invocations requiring oversight.
//! Implements approval workflow with status tracking, timeout handling, and audit trail.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Default approval timeout in seconds (5 minutes).
pub const DEFAULT_APPROVAL_TIMEOUT_SECS: i64 = 300;

/// Approval status enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting human decision.
    Pending,
    /// Action permitted by approver.
    Approved,
    /// Action rejected by approver.
    Denied,
    /// Timeout reached without decision.
    Expired,
}

impl std::str::FromStr for ApprovalStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            _ => Err(format!("Unknown approval status: {s}")),
        }
    }
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

impl ApprovalStatus {
    /// Convert to database string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    /// Check if this is a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Approved | Self::Denied | Self::Expired)
    }
}

/// AI Agent Approval Request model.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AiAgentApprovalRequest {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub tool_id: Uuid,
    pub parameters: serde_json::Value,
    pub context: serde_json::Value,
    pub risk_score: i32,
    pub user_instruction: Option<String>,
    pub session_id: Option<String>,
    pub conversation_id: Option<String>,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub decided_by: Option<Uuid>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decision_reason: Option<String>,
    pub conditions: Option<serde_json::Value>,
    pub notification_sent: bool,
    pub notification_url: Option<String>,
}

impl AiAgentApprovalRequest {
    /// Get status as enum.
    pub fn status_enum(&self) -> Result<ApprovalStatus, String> {
        self.status.parse()
    }

    /// Check if the approval request is still pending.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }

    /// Check if the approval has expired (past `expires_at` time).
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Check if the approval can still be decided (pending and not expired).
    #[must_use]
    pub fn can_be_decided(&self) -> bool {
        self.is_pending() && !self.is_expired()
    }
}

/// Filter for listing approval requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalRequestFilter {
    pub status: Option<String>,
    pub agent_id: Option<Uuid>,
    pub tool_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

/// Request struct for creating an approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApprovalRequest {
    pub agent_id: Uuid,
    pub tool_id: Uuid,
    pub parameters: serde_json::Value,
    pub context: serde_json::Value,
    pub risk_score: i32,
    pub user_instruction: Option<String>,
    pub session_id: Option<String>,
    pub conversation_id: Option<String>,
    pub timeout_secs: Option<i64>,
    pub notification_url: Option<String>,
}

impl AiAgentApprovalRequest {
    /// Find an approval request by ID within a tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, tool_id, parameters, context, risk_score,
                   user_instruction, session_id, conversation_id, status, requested_at,
                   expires_at, decided_by, decided_at, decision_reason, conditions,
                   notification_sent, notification_url
            FROM ai_agent_approval_requests
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List approval requests with optional filtering.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &ApprovalRequestFilter,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT id, tenant_id, agent_id, tool_id, parameters, context, risk_score,
                   user_instruction, session_id, conversation_id, status, requested_at,
                   expires_at, decided_by, decided_at, decision_reason, conditions,
                   notification_sent, notification_url
            FROM ai_agent_approval_requests
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;
        let mut conditions = Vec::new();

        if filter.status.is_some() {
            conditions.push(format!("status = ${param_idx}"));
            param_idx += 1;
        }
        if filter.agent_id.is_some() {
            conditions.push(format!("agent_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.tool_id.is_some() {
            conditions.push(format!("tool_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.from_date.is_some() {
            conditions.push(format!("requested_at >= ${param_idx}"));
            param_idx += 1;
        }
        if filter.to_date.is_some() {
            conditions.push(format!("requested_at <= ${param_idx}"));
            param_idx += 1;
        }

        if !conditions.is_empty() {
            query.push_str(" AND ");
            query.push_str(&conditions.join(" AND "));
        }

        query.push_str(&format!(
            " ORDER BY requested_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut sqlx_query = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(ref status) = filter.status {
            sqlx_query = sqlx_query.bind(status);
        }
        if let Some(agent_id) = filter.agent_id {
            sqlx_query = sqlx_query.bind(agent_id);
        }
        if let Some(tool_id) = filter.tool_id {
            sqlx_query = sqlx_query.bind(tool_id);
        }
        if let Some(from_date) = filter.from_date {
            sqlx_query = sqlx_query.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            sqlx_query = sqlx_query.bind(to_date);
        }

        sqlx_query = sqlx_query.bind(limit).bind(offset);

        sqlx_query.fetch_all(pool).await
    }

    /// Count approval requests matching the filter.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &ApprovalRequestFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) as count
            FROM ai_agent_approval_requests
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;
        let mut conditions = Vec::new();

        if filter.status.is_some() {
            conditions.push(format!("status = ${param_idx}"));
            param_idx += 1;
        }
        if filter.agent_id.is_some() {
            conditions.push(format!("agent_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.tool_id.is_some() {
            conditions.push(format!("tool_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.from_date.is_some() {
            conditions.push(format!("requested_at >= ${param_idx}"));
            param_idx += 1;
        }
        if filter.to_date.is_some() {
            conditions.push(format!("requested_at <= ${param_idx}"));
            // param_idx not needed after last use
        }

        if !conditions.is_empty() {
            query.push_str(" AND ");
            query.push_str(&conditions.join(" AND "));
        }

        let mut sqlx_query = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ref status) = filter.status {
            sqlx_query = sqlx_query.bind(status);
        }
        if let Some(agent_id) = filter.agent_id {
            sqlx_query = sqlx_query.bind(agent_id);
        }
        if let Some(tool_id) = filter.tool_id {
            sqlx_query = sqlx_query.bind(tool_id);
        }
        if let Some(from_date) = filter.from_date {
            sqlx_query = sqlx_query.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            sqlx_query = sqlx_query.bind(to_date);
        }

        sqlx_query.fetch_one(pool).await
    }

    /// List pending approvals for a specific agent.
    pub async fn list_pending_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, agent_id, tool_id, parameters, context, risk_score,
                   user_instruction, session_id, conversation_id, status, requested_at,
                   expires_at, decided_by, decided_at, decision_reason, conditions,
                   notification_sent, notification_url
            FROM ai_agent_approval_requests
            WHERE tenant_id = $1 AND agent_id = $2 AND status = 'pending'
            ORDER BY requested_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_all(pool)
        .await
    }

    /// Create a new approval request.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        input: CreateApprovalRequest,
    ) -> Result<Self, sqlx::Error> {
        let timeout_secs = input.timeout_secs.unwrap_or(DEFAULT_APPROVAL_TIMEOUT_SECS);
        let expires_at = Utc::now() + Duration::seconds(timeout_secs);

        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO ai_agent_approval_requests (
                tenant_id, agent_id, tool_id, parameters, context, risk_score,
                user_instruction, session_id, conversation_id, expires_at, notification_url
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id, tenant_id, agent_id, tool_id, parameters, context, risk_score,
                      user_instruction, session_id, conversation_id, status, requested_at,
                      expires_at, decided_by, decided_at, decision_reason, conditions,
                      notification_sent, notification_url
            ",
        )
        .bind(tenant_id)
        .bind(input.agent_id)
        .bind(input.tool_id)
        .bind(&input.parameters)
        .bind(&input.context)
        .bind(input.risk_score)
        .bind(&input.user_instruction)
        .bind(&input.session_id)
        .bind(&input.conversation_id)
        .bind(expires_at)
        .bind(&input.notification_url)
        .fetch_one(pool)
        .await
    }

    /// Approve an approval request.
    /// Returns None if the request was not in pending state or doesn't exist.
    pub async fn approve(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        decided_by: Uuid,
        reason: Option<String>,
        conditions: Option<serde_json::Value>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            UPDATE ai_agent_approval_requests
            SET status = 'approved',
                decided_by = $3,
                decided_at = NOW(),
                decision_reason = $4,
                conditions = $5
            WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
            RETURNING id, tenant_id, agent_id, tool_id, parameters, context, risk_score,
                      user_instruction, session_id, conversation_id, status, requested_at,
                      expires_at, decided_by, decided_at, decision_reason, conditions,
                      notification_sent, notification_url
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(decided_by)
        .bind(reason)
        .bind(conditions)
        .fetch_optional(pool)
        .await
    }

    /// Deny an approval request.
    /// Returns None if the request was not in pending state or doesn't exist.
    pub async fn deny(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        decided_by: Uuid,
        reason: String,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r"
            UPDATE ai_agent_approval_requests
            SET status = 'denied',
                decided_by = $3,
                decided_at = NOW(),
                decision_reason = $4
            WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
            RETURNING id, tenant_id, agent_id, tool_id, parameters, context, risk_score,
                      user_instruction, session_id, conversation_id, status, requested_at,
                      expires_at, decided_by, decided_at, decision_reason, conditions,
                      notification_sent, notification_url
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(decided_by)
        .bind(reason)
        .fetch_optional(pool)
        .await
    }

    /// Mark notification as sent for an approval request.
    pub async fn mark_notification_sent(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE ai_agent_approval_requests
            SET notification_sent = true
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Expire all pending requests that have passed their expiration time.
    /// This is used by the background expiration task.
    /// Returns the number of expired requests.
    pub async fn expire_pending(pool: &PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE ai_agent_approval_requests
            SET status = 'expired'
            WHERE status = 'pending' AND expires_at < NOW()
            ",
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Expire pending requests for a specific tenant.
    pub async fn expire_pending_for_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE ai_agent_approval_requests
            SET status = 'expired'
            WHERE tenant_id = $1 AND status = 'pending' AND expires_at < NOW()
            ",
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count pending approvals for a tenant.
    pub async fn count_pending(pool: &PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar::<_, i64>(
            r"
            SELECT COUNT(*) as count
            FROM ai_agent_approval_requests
            WHERE tenant_id = $1 AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Count pending approvals for a specific agent.
    pub async fn count_pending_by_agent(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar::<_, i64>(
            r"
            SELECT COUNT(*) as count
            FROM ai_agent_approval_requests
            WHERE tenant_id = $1 AND agent_id = $2 AND status = 'pending'
            ",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_one(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::str::FromStr;

    #[test]
    fn test_approval_status_from_str() {
        assert_eq!(
            ApprovalStatus::from_str("pending").unwrap(),
            ApprovalStatus::Pending
        );
        assert_eq!(
            ApprovalStatus::from_str("approved").unwrap(),
            ApprovalStatus::Approved
        );
        assert_eq!(
            ApprovalStatus::from_str("denied").unwrap(),
            ApprovalStatus::Denied
        );
        assert_eq!(
            ApprovalStatus::from_str("expired").unwrap(),
            ApprovalStatus::Expired
        );
        assert!(ApprovalStatus::from_str("invalid").is_err());
    }

    #[test]
    fn test_approval_status_display() {
        assert_eq!(format!("{}", ApprovalStatus::Pending), "pending");
        assert_eq!(format!("{}", ApprovalStatus::Approved), "approved");
        assert_eq!(format!("{}", ApprovalStatus::Denied), "denied");
        assert_eq!(format!("{}", ApprovalStatus::Expired), "expired");
    }

    #[test]
    fn test_approval_status_as_str() {
        assert_eq!(ApprovalStatus::Pending.as_str(), "pending");
        assert_eq!(ApprovalStatus::Approved.as_str(), "approved");
        assert_eq!(ApprovalStatus::Denied.as_str(), "denied");
        assert_eq!(ApprovalStatus::Expired.as_str(), "expired");
    }

    #[test]
    fn test_approval_status_is_terminal() {
        assert!(!ApprovalStatus::Pending.is_terminal());
        assert!(ApprovalStatus::Approved.is_terminal());
        assert!(ApprovalStatus::Denied.is_terminal());
        assert!(ApprovalStatus::Expired.is_terminal());
    }

    #[test]
    fn test_approval_request_serialization() {
        let request = AiAgentApprovalRequest {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            parameters: json!({"to": "customer@example.com", "subject": "Hello"}),
            context: json!({"conversation_id": "conv-123"}),
            risk_score: 45,
            user_instruction: Some("Send a follow-up email".to_string()),
            session_id: Some("sess-456".to_string()),
            conversation_id: Some("conv-123".to_string()),
            status: "pending".to_string(),
            requested_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            decided_by: None,
            decided_at: None,
            decision_reason: None,
            conditions: None,
            notification_sent: false,
            notification_url: Some("https://webhook.example.com/approvals".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: AiAgentApprovalRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.id, deserialized.id);
        assert_eq!(request.agent_id, deserialized.agent_id);
        assert_eq!(request.tool_id, deserialized.tool_id);
        assert_eq!(request.risk_score, deserialized.risk_score);
        assert_eq!(request.status, deserialized.status);
    }

    #[test]
    fn test_approval_request_is_pending() {
        let mut request = AiAgentApprovalRequest {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            parameters: json!({}),
            context: json!({}),
            risk_score: 0,
            user_instruction: None,
            session_id: None,
            conversation_id: None,
            status: "pending".to_string(),
            requested_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            decided_by: None,
            decided_at: None,
            decision_reason: None,
            conditions: None,
            notification_sent: false,
            notification_url: None,
        };

        assert!(request.is_pending());
        assert!(!request.is_expired());
        assert!(request.can_be_decided());

        request.status = "approved".to_string();
        assert!(!request.is_pending());
        assert!(!request.can_be_decided());
    }

    #[test]
    fn test_approval_request_is_expired() {
        let request = AiAgentApprovalRequest {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            parameters: json!({}),
            context: json!({}),
            risk_score: 0,
            user_instruction: None,
            session_id: None,
            conversation_id: None,
            status: "pending".to_string(),
            requested_at: Utc::now() - Duration::minutes(10),
            expires_at: Utc::now() - Duration::minutes(5),
            decided_by: None,
            decided_at: None,
            decision_reason: None,
            conditions: None,
            notification_sent: false,
            notification_url: None,
        };

        assert!(request.is_pending());
        assert!(request.is_expired());
        assert!(!request.can_be_decided());
    }

    #[test]
    fn test_create_approval_request_serialization() {
        let input = CreateApprovalRequest {
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            parameters: json!({"action": "send_email", "to": "test@example.com"}),
            context: json!({"session_id": "sess-123", "conversation_id": "conv-456"}),
            risk_score: 65,
            user_instruction: Some("Send email to customer".to_string()),
            session_id: Some("sess-123".to_string()),
            conversation_id: Some("conv-456".to_string()),
            timeout_secs: Some(600),
            notification_url: Some("https://webhook.example.com".to_string()),
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: CreateApprovalRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(input.agent_id, deserialized.agent_id);
        assert_eq!(input.tool_id, deserialized.tool_id);
        assert_eq!(input.risk_score, deserialized.risk_score);
        assert_eq!(input.timeout_secs, deserialized.timeout_secs);
    }

    #[test]
    fn test_approval_request_filter_default() {
        let filter = ApprovalRequestFilter::default();

        assert!(filter.status.is_none());
        assert!(filter.agent_id.is_none());
        assert!(filter.tool_id.is_none());
        assert!(filter.from_date.is_none());
        assert!(filter.to_date.is_none());
    }

    #[test]
    fn test_default_timeout() {
        assert_eq!(DEFAULT_APPROVAL_TIMEOUT_SECS, 300);
    }

    #[test]
    fn test_approval_status_serialization() {
        let pending = ApprovalStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let approved = ApprovalStatus::Approved;
        let json = serde_json::to_string(&approved).unwrap();
        assert_eq!(json, "\"approved\"");

        let denied = ApprovalStatus::Denied;
        let json = serde_json::to_string(&denied).unwrap();
        assert_eq!(json, "\"denied\"");

        let expired = ApprovalStatus::Expired;
        let json = serde_json::to_string(&expired).unwrap();
        assert_eq!(json, "\"expired\"");
    }

    #[test]
    fn test_approval_status_deserialization() {
        let pending: ApprovalStatus = serde_json::from_str("\"pending\"").unwrap();
        assert_eq!(pending, ApprovalStatus::Pending);

        let approved: ApprovalStatus = serde_json::from_str("\"approved\"").unwrap();
        assert_eq!(approved, ApprovalStatus::Approved);

        let denied: ApprovalStatus = serde_json::from_str("\"denied\"").unwrap();
        assert_eq!(denied, ApprovalStatus::Denied);

        let expired: ApprovalStatus = serde_json::from_str("\"expired\"").unwrap();
        assert_eq!(expired, ApprovalStatus::Expired);
    }
}
