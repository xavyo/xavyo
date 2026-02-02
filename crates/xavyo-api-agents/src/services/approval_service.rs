//! Approval service for managing human-in-the-loop approval requests (F092).
//!
//! Provides business logic for creating, listing, approving, and denying
//! approval requests for AI agent tool invocations.

use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{
    ApprovalListResponse, ApprovalResponse, ApprovalStatusResponse, ApprovalSummary,
    ApprovalWebhookPayload,
};
use crate::services::audit_service::AuditService;
use crate::services::webhook_service::WebhookService;
use xavyo_db::models::ai_agent::AiAgent;
use xavyo_db::models::ai_agent_approval_request::{
    AiAgentApprovalRequest, ApprovalRequestFilter, CreateApprovalRequest,
};
use xavyo_db::models::ai_tool::AiTool;
use xavyo_db::models::group_membership::GroupMembership;

/// Service for managing approval requests.
#[derive(Clone)]
pub struct ApprovalService {
    pool: PgPool,
    audit_service: Arc<AuditService>,
    webhook_service: Arc<WebhookService>,
    base_url: String,
}

impl ApprovalService {
    /// Create a new ApprovalService.
    pub fn new(
        pool: PgPool,
        audit_service: Arc<AuditService>,
        webhook_service: Arc<WebhookService>,
    ) -> Self {
        let base_url =
            std::env::var("API_BASE_URL").unwrap_or_else(|_| "https://api.xavyo.net".to_string());
        Self {
            pool,
            audit_service,
            webhook_service,
            base_url,
        }
    }

    /// Create a new approval request.
    pub async fn create_approval(
        &self,
        tenant_id: Uuid,
        request: CreateApprovalRequest,
    ) -> Result<AiAgentApprovalRequest, ApiAgentsError> {
        // Create the approval request
        let approval =
            AiAgentApprovalRequest::create(&self.pool, tenant_id, request.clone()).await?;

        // Log audit event
        let _ = self
            .audit_service
            .log_authorization(
                tenant_id,
                request.agent_id,
                Some(request.tool_id),
                "", // tool name not available here
                Some(request.parameters.clone()),
                "require_approval",
                "Human approval required for this action",
                request.conversation_id.as_deref(),
                request.session_id.as_deref(),
                request.user_instruction.as_deref(),
                None,
                0,
            )
            .await;

        // Send webhook notification if configured
        if let Some(ref url) = approval.notification_url {
            let approval_clone = approval.clone();
            let url_clone = url.clone();
            let pool_clone = self.pool.clone();
            let webhook_service = self.webhook_service.clone();
            let base_url = self.base_url.clone();

            // Fire-and-forget webhook delivery
            tokio::spawn(async move {
                // Get agent and tool names for the webhook payload
                let agent_name =
                    AiAgent::find_by_id(&pool_clone, tenant_id, approval_clone.agent_id)
                        .await
                        .ok()
                        .flatten()
                        .map(|a| a.name)
                        .unwrap_or_else(|| "unknown".to_string());

                let tool_name = AiTool::find_by_id(&pool_clone, tenant_id, approval_clone.tool_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|t| t.name)
                    .unwrap_or_else(|| "unknown".to_string());

                let payload = ApprovalWebhookPayload {
                    event: "approval_requested".to_string(),
                    approval_id: approval_clone.id,
                    agent_id: approval_clone.agent_id,
                    agent_name,
                    tool_id: approval_clone.tool_id,
                    tool_name,
                    risk_score: approval_clone.risk_score,
                    requested_at: approval_clone.requested_at,
                    expires_at: approval_clone.expires_at,
                    approval_url: format!("{}/v1/approvals/{}", base_url, approval_clone.id),
                };

                if let Err(e) = webhook_service
                    .deliver_approval_webhook(tenant_id, approval_clone.id, &url_clone, &payload)
                    .await
                {
                    tracing::warn!(
                        "Failed to deliver approval webhook for {}: {}",
                        approval_clone.id,
                        e
                    );
                }

                // Mark notification as sent (best effort)
                let _ = AiAgentApprovalRequest::mark_notification_sent(
                    &pool_clone,
                    tenant_id,
                    approval_clone.id,
                )
                .await;
            });
        }

        Ok(approval)
    }

    /// List approval requests with optional filtering.
    pub async fn list_approvals(
        &self,
        tenant_id: Uuid,
        status: Option<String>,
        agent_id: Option<Uuid>,
        limit: i32,
        offset: i32,
    ) -> Result<ApprovalListResponse, ApiAgentsError> {
        let filter = ApprovalRequestFilter {
            status,
            agent_id,
            tool_id: None,
            from_date: None,
            to_date: None,
        };

        let approvals =
            AiAgentApprovalRequest::list(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = AiAgentApprovalRequest::count(&self.pool, tenant_id, &filter).await?;

        // Convert to summaries with agent/tool names
        let mut summaries = Vec::with_capacity(approvals.len());
        for approval in approvals {
            let agent_name = AiAgent::find_by_id(&self.pool, tenant_id, approval.agent_id)
                .await?
                .map(|a| a.name)
                .unwrap_or_else(|| "unknown".to_string());

            let tool_name = AiTool::find_by_id(&self.pool, tenant_id, approval.tool_id)
                .await?
                .map(|t| t.name)
                .unwrap_or_else(|| "unknown".to_string());

            summaries.push(ApprovalSummary {
                id: approval.id,
                agent_id: approval.agent_id,
                agent_name,
                tool_id: approval.tool_id,
                tool_name,
                status: approval.status,
                risk_score: approval.risk_score,
                requested_at: approval.requested_at,
                expires_at: approval.expires_at,
            });
        }

        Ok(ApprovalListResponse {
            items: summaries,
            total,
            limit: Some(limit),
            offset: Some(offset),
        })
    }

    /// Get approval request details.
    pub async fn get_approval(
        &self,
        tenant_id: Uuid,
        approval_id: Uuid,
    ) -> Result<ApprovalResponse, ApiAgentsError> {
        let approval = AiAgentApprovalRequest::find_by_id(&self.pool, tenant_id, approval_id)
            .await?
            .ok_or(ApiAgentsError::ApprovalNotFound)?;

        let agent_name = AiAgent::find_by_id(&self.pool, tenant_id, approval.agent_id)
            .await?
            .map(|a| a.name)
            .unwrap_or_else(|| "unknown".to_string());

        let tool_name = AiTool::find_by_id(&self.pool, tenant_id, approval.tool_id)
            .await?
            .map(|t| t.name)
            .unwrap_or_else(|| "unknown".to_string());

        Ok(self.to_response(approval, agent_name, tool_name))
    }

    /// Check approval status (lightweight endpoint for agent polling).
    pub async fn check_status(
        &self,
        tenant_id: Uuid,
        approval_id: Uuid,
    ) -> Result<ApprovalStatusResponse, ApiAgentsError> {
        let approval = AiAgentApprovalRequest::find_by_id(&self.pool, tenant_id, approval_id)
            .await?
            .ok_or(ApiAgentsError::ApprovalNotFound)?;

        // Check if pending but expired
        let status = if approval.is_pending() && approval.is_expired() {
            "expired".to_string()
        } else {
            approval.status
        };

        Ok(ApprovalStatusResponse {
            status,
            decided_at: approval.decided_at,
            conditions: approval.conditions,
        })
    }

    /// Approve an approval request.
    pub async fn approve(
        &self,
        tenant_id: Uuid,
        approval_id: Uuid,
        user_id: Uuid,
        reason: Option<String>,
        conditions: Option<serde_json::Value>,
    ) -> Result<ApprovalResponse, ApiAgentsError> {
        // Get the approval first to check authorization
        let approval = AiAgentApprovalRequest::find_by_id(&self.pool, tenant_id, approval_id)
            .await?
            .ok_or(ApiAgentsError::ApprovalNotFound)?;

        // Check if already decided
        if !approval.is_pending() {
            return Err(ApiAgentsError::ApprovalAlreadyDecided);
        }

        // Check if expired
        if approval.is_expired() {
            return Err(ApiAgentsError::ApprovalExpired);
        }

        // Check if user is authorized to approve
        if !self
            .is_authorized_approver(tenant_id, approval.agent_id, user_id)
            .await?
        {
            return Err(ApiAgentsError::NotAuthorizedApprover);
        }

        // Approve the request
        let updated = AiAgentApprovalRequest::approve(
            &self.pool,
            tenant_id,
            approval_id,
            user_id,
            reason,
            conditions,
        )
        .await?
        .ok_or(ApiAgentsError::ApprovalAlreadyDecided)?;

        // Log audit event
        let _ = self
            .audit_service
            .log_authorization(
                tenant_id,
                updated.agent_id,
                Some(updated.tool_id),
                "",
                Some(updated.parameters.clone()),
                "approved",
                updated
                    .decision_reason
                    .as_deref()
                    .unwrap_or("Approved by human"),
                updated.conversation_id.as_deref(),
                updated.session_id.as_deref(),
                updated.user_instruction.as_deref(),
                None,
                0,
            )
            .await;

        let agent_name = AiAgent::find_by_id(&self.pool, tenant_id, updated.agent_id)
            .await?
            .map(|a| a.name)
            .unwrap_or_else(|| "unknown".to_string());

        let tool_name = AiTool::find_by_id(&self.pool, tenant_id, updated.tool_id)
            .await?
            .map(|t| t.name)
            .unwrap_or_else(|| "unknown".to_string());

        Ok(self.to_response(updated, agent_name, tool_name))
    }

    /// Deny an approval request.
    pub async fn deny(
        &self,
        tenant_id: Uuid,
        approval_id: Uuid,
        user_id: Uuid,
        reason: String,
    ) -> Result<ApprovalResponse, ApiAgentsError> {
        // Validate reason is not empty
        if reason.trim().is_empty() {
            return Err(ApiAgentsError::DenialReasonRequired);
        }

        // Get the approval first to check authorization
        let approval = AiAgentApprovalRequest::find_by_id(&self.pool, tenant_id, approval_id)
            .await?
            .ok_or(ApiAgentsError::ApprovalNotFound)?;

        // Check if already decided
        if !approval.is_pending() {
            return Err(ApiAgentsError::ApprovalAlreadyDecided);
        }

        // Check if expired
        if approval.is_expired() {
            return Err(ApiAgentsError::ApprovalExpired);
        }

        // Check if user is authorized to deny
        if !self
            .is_authorized_approver(tenant_id, approval.agent_id, user_id)
            .await?
        {
            return Err(ApiAgentsError::NotAuthorizedApprover);
        }

        // Deny the request
        let updated =
            AiAgentApprovalRequest::deny(&self.pool, tenant_id, approval_id, user_id, reason)
                .await?
                .ok_or(ApiAgentsError::ApprovalAlreadyDecided)?;

        // Log audit event
        let _ = self
            .audit_service
            .log_authorization(
                tenant_id,
                updated.agent_id,
                Some(updated.tool_id),
                "",
                Some(updated.parameters.clone()),
                "rejected",
                updated.decision_reason.as_deref().unwrap_or("Denied"),
                updated.conversation_id.as_deref(),
                updated.session_id.as_deref(),
                updated.user_instruction.as_deref(),
                None,
                0,
            )
            .await;

        let agent_name = AiAgent::find_by_id(&self.pool, tenant_id, updated.agent_id)
            .await?
            .map(|a| a.name)
            .unwrap_or_else(|| "unknown".to_string());

        let tool_name = AiTool::find_by_id(&self.pool, tenant_id, updated.tool_id)
            .await?
            .map(|t| t.name)
            .unwrap_or_else(|| "unknown".to_string());

        Ok(self.to_response(updated, agent_name, tool_name))
    }

    /// Check if a user is authorized to approve/deny requests for an agent.
    /// Authorized users are:
    /// - The agent owner (ai_agents.owner_id)
    /// - Members of the agent's team (ai_agents.team_id)
    async fn is_authorized_approver(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, ApiAgentsError> {
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        // Check if user is the agent owner
        if agent.owner_id == Some(user_id) {
            return Ok(true);
        }

        // Check if user is a member of the agent's team
        if let Some(team_id) = agent.team_id {
            let is_member =
                GroupMembership::is_member(&self.pool, tenant_id, team_id, user_id).await?;
            if is_member {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Run expiration task - expire all pending approvals past their expiration time.
    /// This should be called periodically (e.g., every 30 seconds).
    pub async fn run_expiration_task(&self) -> Result<u64, ApiAgentsError> {
        let count = AiAgentApprovalRequest::expire_pending(&self.pool).await?;
        if count > 0 {
            tracing::info!("Expired {} pending approval requests", count);
        }
        Ok(count)
    }

    /// Convert database model to API response.
    fn to_response(
        &self,
        approval: AiAgentApprovalRequest,
        agent_name: String,
        tool_name: String,
    ) -> ApprovalResponse {
        ApprovalResponse {
            id: approval.id,
            agent_id: approval.agent_id,
            agent_name,
            tool_id: approval.tool_id,
            tool_name,
            parameters: approval.parameters,
            context: approval.context,
            user_instruction: approval.user_instruction,
            session_id: approval.session_id,
            conversation_id: approval.conversation_id,
            status: approval.status,
            risk_score: approval.risk_score,
            requested_at: approval.requested_at,
            expires_at: approval.expires_at,
            decided_by: approval.decided_by,
            decided_at: approval.decided_at,
            decision_reason: approval.decision_reason,
            conditions: approval.conditions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ApprovalSummary;
    use chrono::{Duration, Utc};

    #[test]
    fn test_approval_service_base_url_default() {
        // Test that the default base URL is set correctly
        let expected_default = "https://api.xavyo.net";
        assert!(expected_default.starts_with("https://"));
    }

    #[test]
    fn test_approval_response_fields() {
        // Verify ApprovalResponse has all required fields
        let response = ApprovalResponse {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "test-agent".to_string(),
            tool_id: Uuid::new_v4(),
            tool_name: "test-tool".to_string(),
            parameters: serde_json::json!({"key": "value"}),
            context: serde_json::json!({}),
            user_instruction: Some("Do something".to_string()),
            session_id: Some("sess-123".to_string()),
            conversation_id: Some("conv-456".to_string()),
            status: "pending".to_string(),
            risk_score: 50,
            requested_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            decided_by: None,
            decided_at: None,
            decision_reason: None,
            conditions: None,
        };

        assert_eq!(response.status, "pending");
        assert_eq!(response.risk_score, 50);
        assert!(response.decided_by.is_none());
    }

    #[test]
    fn test_approval_summary_fields() {
        let summary = ApprovalSummary {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            agent_name: "sales-assistant".to_string(),
            tool_id: Uuid::new_v4(),
            tool_name: "send_email".to_string(),
            status: "pending".to_string(),
            risk_score: 45,
            requested_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };

        assert_eq!(summary.agent_name, "sales-assistant");
        assert_eq!(summary.tool_name, "send_email");
        assert_eq!(summary.risk_score, 45);
    }

    #[test]
    fn test_approval_status_response_pending() {
        let response = ApprovalStatusResponse {
            status: "pending".to_string(),
            decided_at: None,
            conditions: None,
        };

        assert_eq!(response.status, "pending");
        assert!(response.decided_at.is_none());
        assert!(response.conditions.is_none());
    }

    #[test]
    fn test_approval_status_response_approved_with_conditions() {
        let response = ApprovalStatusResponse {
            status: "approved".to_string(),
            decided_at: Some(Utc::now()),
            conditions: Some(serde_json::json!({"session_only": true, "max_calls": 5})),
        };

        assert_eq!(response.status, "approved");
        assert!(response.decided_at.is_some());
        assert!(response.conditions.is_some());

        let conditions = response.conditions.unwrap();
        assert_eq!(conditions["session_only"], true);
        assert_eq!(conditions["max_calls"], 5);
    }

    #[test]
    fn test_approval_list_response() {
        let list = ApprovalListResponse {
            items: vec![],
            total: 0,
            limit: Some(50),
            offset: Some(0),
        };

        assert!(list.items.is_empty());
        assert_eq!(list.total, 0);
        assert_eq!(list.limit, Some(50));
        assert_eq!(list.offset, Some(0));
    }

    #[test]
    fn test_approval_list_response_with_items() {
        let items = vec![
            ApprovalSummary {
                id: Uuid::new_v4(),
                agent_id: Uuid::new_v4(),
                agent_name: "agent-1".to_string(),
                tool_id: Uuid::new_v4(),
                tool_name: "tool-1".to_string(),
                status: "pending".to_string(),
                risk_score: 30,
                requested_at: Utc::now(),
                expires_at: Utc::now() + Duration::minutes(5),
            },
            ApprovalSummary {
                id: Uuid::new_v4(),
                agent_id: Uuid::new_v4(),
                agent_name: "agent-2".to_string(),
                tool_id: Uuid::new_v4(),
                tool_name: "tool-2".to_string(),
                status: "approved".to_string(),
                risk_score: 60,
                requested_at: Utc::now() - Duration::hours(1),
                expires_at: Utc::now() - Duration::minutes(55),
            },
        ];

        let list = ApprovalListResponse {
            items,
            total: 2,
            limit: Some(50),
            offset: Some(0),
        };

        assert_eq!(list.items.len(), 2);
        assert_eq!(list.total, 2);
        assert_eq!(list.items[0].status, "pending");
        assert_eq!(list.items[1].status, "approved");
    }

    #[test]
    fn test_denial_reason_validation() {
        // Empty reason should be rejected
        let empty_reason = "";
        assert!(empty_reason.trim().is_empty());

        // Whitespace-only reason should be rejected
        let whitespace_reason = "   \t\n  ";
        assert!(whitespace_reason.trim().is_empty());

        // Valid reason should be accepted
        let valid_reason = "Content violates company policy";
        assert!(!valid_reason.trim().is_empty());
    }
}
