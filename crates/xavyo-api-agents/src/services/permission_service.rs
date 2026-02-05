//! Permission service for managing agent-tool permissions.
//!
//! Provides business logic for granting, revoking, and checking permissions.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{GrantPermissionRequest, PermissionListResponse, PermissionResponse};
use xavyo_db::models::ai_agent::AiAgent;
use xavyo_db::models::ai_agent_tool_permission::{
    AiAgentToolPermission, AiAgentToolPermissionDetails, GrantToolPermission,
};
use xavyo_db::models::ai_tool::AiTool;

/// Service for managing agent-tool permissions.
#[derive(Clone)]
pub struct PermissionService {
    pool: PgPool,
}

impl PermissionService {
    /// Create a new `PermissionService`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Grant a permission to an agent for a specific tool.
    pub async fn grant(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request: GrantPermissionRequest,
        granted_by: Option<Uuid>,
    ) -> Result<PermissionResponse, ApiAgentsError> {
        // Verify agent exists
        AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        // Verify tool exists
        let tool = AiTool::find_by_id(&self.pool, tenant_id, request.tool_id)
            .await?
            .ok_or(ApiAgentsError::ToolNotFound)?;

        let input = GrantToolPermission {
            agent_id,
            tool_id: request.tool_id,
            allowed_parameters: request.allowed_parameters,
            max_calls_per_hour: request.max_calls_per_hour,
            requires_approval: request.requires_approval,
            expires_at: request.expires_at,
        };

        let permission =
            AiAgentToolPermission::grant(&self.pool, tenant_id, input, granted_by).await?;

        Ok(self.to_response(permission, &tool.name))
    }

    /// Revoke a permission.
    pub async fn revoke(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_id: Uuid,
    ) -> Result<(), ApiAgentsError> {
        // Verify agent exists
        AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        let revoked =
            AiAgentToolPermission::revoke(&self.pool, tenant_id, agent_id, tool_id).await?;

        if !revoked {
            return Err(ApiAgentsError::PermissionNotFound);
        }

        Ok(())
    }

    /// List permissions for an agent.
    pub async fn list_by_agent(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        limit: i32,
        offset: i32,
    ) -> Result<PermissionListResponse, ApiAgentsError> {
        // Verify agent exists
        AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        let permissions =
            AiAgentToolPermission::list_by_agent_with_details(&self.pool, tenant_id, agent_id)
                .await?;

        let total = permissions.len() as i64;

        // Apply pagination in memory (for simplicity)
        let paginated: Vec<_> = permissions
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|p| self.details_to_response(p))
            .collect();

        Ok(PermissionListResponse {
            permissions: paginated,
            total,
            limit,
            offset,
        })
    }

    /// Check if an agent has permission for a tool.
    pub async fn check_permission(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_id: Uuid,
    ) -> Result<Option<AiAgentToolPermission>, ApiAgentsError> {
        Ok(
            AiAgentToolPermission::check_permission(&self.pool, tenant_id, agent_id, tool_id)
                .await?,
        )
    }

    /// Check if an agent has permission for a tool by name.
    pub async fn check_permission_by_tool_name(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        tool_name: &str,
    ) -> Result<Option<(AiAgentToolPermission, AiTool)>, ApiAgentsError> {
        // Find the tool by name
        let tool = match AiTool::find_by_name(&self.pool, tenant_id, tool_name).await? {
            Some(t) => t,
            None => return Ok(None),
        };

        // Check permission
        let permission =
            AiAgentToolPermission::check_permission(&self.pool, tenant_id, agent_id, tool.id)
                .await?;

        Ok(permission.map(|p| (p, tool)))
    }

    /// Convert permission to response DTO.
    fn to_response(
        &self,
        permission: AiAgentToolPermission,
        tool_name: &str,
    ) -> PermissionResponse {
        PermissionResponse {
            id: permission.id,
            agent_id: permission.agent_id,
            tool_id: permission.tool_id,
            tool_name: tool_name.to_string(),
            allowed_parameters: permission.allowed_parameters,
            max_calls_per_hour: permission.max_calls_per_hour,
            requires_approval: permission.requires_approval,
            granted_at: permission.granted_at,
            granted_by: permission.granted_by,
            expires_at: permission.expires_at,
        }
    }

    /// Convert permission details to response DTO.
    fn details_to_response(&self, details: AiAgentToolPermissionDetails) -> PermissionResponse {
        PermissionResponse {
            id: details.id,
            agent_id: details.agent_id,
            tool_id: details.tool_id,
            tool_name: details.tool_name,
            allowed_parameters: details.allowed_parameters,
            max_calls_per_hour: details.max_calls_per_hour,
            requires_approval: details.requires_approval,
            granted_at: details.granted_at,
            granted_by: details.granted_by,
            expires_at: details.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_permission_response_fields() {
        // Test that PermissionResponse has the expected structure
        use crate::models::PermissionResponse;
        use uuid::Uuid;

        let response = PermissionResponse {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            tool_id: Uuid::new_v4(),
            tool_name: "test_tool".to_string(),
            allowed_parameters: None,
            max_calls_per_hour: Some(100),
            requires_approval: Some(false),
            granted_at: chrono::Utc::now(),
            granted_by: None,
            expires_at: None,
        };

        assert_eq!(response.tool_name, "test_tool");
        assert_eq!(response.max_calls_per_hour, Some(100));
    }
}
