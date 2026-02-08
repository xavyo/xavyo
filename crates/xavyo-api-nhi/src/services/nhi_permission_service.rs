//! Tool permission management service.
//!
//! Manages agent-to-tool permission grants:
//! - Grant permissions with optional parameter restrictions and expiry
//! - Revoke permissions
//! - List permissions by agent or tool
//! - Cascade revoke all permissions for an NHI (on archive)

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::{
    nhi_identity::NhiIdentity,
    nhi_tool_permission::{CreateNhiToolPermission, NhiToolPermission},
};
use xavyo_nhi::NhiType;

use crate::error::NhiApiError;

/// Service for managing agent-to-tool permissions.
pub struct NhiPermissionService;

impl NhiPermissionService {
    /// Grant an agent permission to use a tool.
    ///
    /// Validates:
    /// - Agent exists and is of type `Agent`
    /// - Tool exists and is of type `Tool`
    /// - Both are in `Active` lifecycle state (rejects deprecated/archived)
    /// - `expires_at`, if provided, is in the future
    pub async fn grant(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_nhi_id: Uuid,
        tool_nhi_id: Uuid,
        granted_by: Uuid,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<NhiToolPermission, NhiApiError> {
        // 1. Verify agent exists and is the correct type
        let agent = NhiIdentity::find_by_id(pool, tenant_id, agent_nhi_id)
            .await?
            .ok_or(NhiApiError::NotFound)?;

        if agent.nhi_type != NhiType::Agent {
            return Err(NhiApiError::BadRequest(format!(
                "NHI {} is a {}, not an agent",
                agent_nhi_id, agent.nhi_type
            )));
        }

        if !agent.lifecycle_state.is_usable() {
            return Err(NhiApiError::BadRequest(format!(
                "Agent is in {} state; must be active to grant permissions",
                agent.lifecycle_state
            )));
        }

        // 2. Verify tool exists and is the correct type
        let tool = NhiIdentity::find_by_id(pool, tenant_id, tool_nhi_id)
            .await?
            .ok_or(NhiApiError::NotFound)?;

        if tool.nhi_type != NhiType::Tool {
            return Err(NhiApiError::BadRequest(format!(
                "NHI {} is a {}, not a tool",
                tool_nhi_id, tool.nhi_type
            )));
        }

        if !tool.lifecycle_state.is_usable() {
            return Err(NhiApiError::BadRequest(format!(
                "Tool is in {} state; must be active to grant permissions",
                tool.lifecycle_state
            )));
        }

        // 3. Validate expires_at is in the future if provided
        if let Some(exp) = expires_at {
            if exp <= Utc::now() {
                return Err(NhiApiError::BadRequest(
                    "expires_at must be in the future".into(),
                ));
            }
        }

        // 4. Create (or upsert) the permission
        let input = CreateNhiToolPermission {
            agent_nhi_id,
            tool_nhi_id,
            allowed_parameters: None,
            max_calls_per_hour: None,
            requires_approval: None,
            granted_by: Some(granted_by),
            expires_at,
        };

        let perm = NhiToolPermission::grant(pool, tenant_id, input).await?;
        Ok(perm)
    }

    /// Revoke an agent's permission to use a tool.
    ///
    /// Returns `true` if a permission was found and deleted, `false` if none existed.
    pub async fn revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_nhi_id: Uuid,
        tool_nhi_id: Uuid,
    ) -> Result<bool, NhiApiError> {
        let perm = NhiToolPermission::find_by_pair(pool, tenant_id, agent_nhi_id, tool_nhi_id)
            .await?
            .ok_or(NhiApiError::NotFound)?;

        NhiToolPermission::revoke(pool, tenant_id, perm.id)
            .await
            .map_err(NhiApiError::Database)
    }

    /// List tools an agent has permission to use (excluding expired).
    pub async fn list_agent_tools(
        pool: &PgPool,
        tenant_id: Uuid,
        agent_nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NhiToolPermission>, NhiApiError> {
        let perms =
            NhiToolPermission::list_by_agent(pool, tenant_id, agent_nhi_id, limit, offset).await?;
        Ok(perms)
    }

    /// List agents that have permission to use a tool (excluding expired).
    pub async fn list_tool_agents(
        pool: &PgPool,
        tenant_id: Uuid,
        tool_nhi_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NhiToolPermission>, NhiApiError> {
        let perms =
            NhiToolPermission::list_by_tool(pool, tenant_id, tool_nhi_id, limit, offset).await?;
        Ok(perms)
    }

    /// Cascade revoke all permissions for an NHI (called on archive).
    ///
    /// Removes all permissions where the given NHI is either the agent or the tool.
    pub async fn cascade_revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<u64, NhiApiError> {
        NhiToolPermission::revoke_all_for_nhi(pool, tenant_id, nhi_id)
            .await
            .map_err(NhiApiError::Database)
    }
}
