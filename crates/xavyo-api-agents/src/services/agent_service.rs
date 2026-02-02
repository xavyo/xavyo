//! Agent service for managing AI agents.
//!
//! Provides business logic for agent CRUD operations, status management,
//! and validation following OWASP ASI guidelines.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::models::{
    responses::CanOperateResponse, AgentListResponse, AgentResponse, CreateAgentRequest,
    ListAgentsQuery, OrphanedAgentListResponse, OrphanedAgentResponse, PromotionResponse,
    UpdateAgentRequest,
};
use xavyo_db::models::ai_agent::{AiAgent, AiAgentFilter, CreateAiAgent, UpdateAiAgent};
use xavyo_db::models::user::User;

/// Service for managing AI agents.
#[derive(Clone)]
pub struct AgentService {
    pool: PgPool,
}

impl AgentService {
    /// Create a new AgentService.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new AI agent.
    ///
    /// If `owner_id` is not provided in the request, defaults to the authenticated user.
    /// This ensures HITL approval workflows have an authorized approver.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        created_by: Uuid,
        request: CreateAgentRequest,
    ) -> Result<AgentResponse, ApiAgentsError> {
        // Validate agent type
        self.validate_agent_type(&request.agent_type)?;

        // Validate risk level
        self.validate_risk_level(&request.risk_level)?;

        // Check for duplicate name
        if let Some(_existing) = AiAgent::find_by_name(&self.pool, tenant_id, &request.name).await?
        {
            return Err(ApiAgentsError::AgentNameExists);
        }

        // Default owner_id to the authenticated user if not provided.
        // This ensures there's always someone authorized to approve HITL requests.
        let owner_id = request.owner_id.or(Some(created_by));

        // Create agent
        let input = CreateAiAgent {
            name: request.name,
            description: request.description,
            agent_type: request.agent_type,
            owner_id,
            team_id: request.team_id,
            backup_owner_id: request.backup_owner_id,
            model_provider: request.model_provider,
            model_name: request.model_name,
            model_version: request.model_version,
            agent_card_url: None,
            risk_level: request.risk_level,
            max_token_lifetime_secs: request.max_token_lifetime_secs,
            requires_human_approval: request.requires_human_approval,
            expires_at: request.expires_at,
            inactivity_threshold_days: request.inactivity_threshold_days,
            rotation_interval_days: request.rotation_interval_days,
        };

        let agent = AiAgent::create(&self.pool, tenant_id, input).await?;

        Ok(self.to_response(agent))
    }

    /// Get an agent by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<AgentResponse, ApiAgentsError> {
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        Ok(self.to_response(agent))
    }

    /// List agents for a tenant with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: ListAgentsQuery,
    ) -> Result<AgentListResponse, ApiAgentsError> {
        let filter = AiAgentFilter {
            status: query.status,
            agent_type: query.agent_type,
            owner_id: query.owner_id,
            risk_level: query.risk_level,
            name_prefix: query.name,
        };

        let limit = query.limit.min(1000) as i64;
        let offset = query.offset.max(0) as i64;

        let agents = AiAgent::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = AiAgent::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(AgentListResponse {
            agents: agents.into_iter().map(|a| self.to_response(a)).collect(),
            total,
            limit: query.limit,
            offset: query.offset,
        })
    }

    /// Update an agent.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request: UpdateAgentRequest,
    ) -> Result<AgentResponse, ApiAgentsError> {
        // Validate risk level if provided
        if let Some(ref risk_level) = request.risk_level {
            self.validate_risk_level(risk_level)?;
        }

        // Check agent exists
        AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        let input = UpdateAiAgent {
            name: None, // Name is not updatable
            description: request.description,
            owner_id: None,
            team_id: None,
            backup_owner_id: request.backup_owner_id.map(Some),
            model_provider: request.model_provider,
            model_name: request.model_name,
            model_version: request.model_version,
            agent_card_url: None,
            agent_card_signature: None,
            risk_level: request.risk_level,
            max_token_lifetime_secs: request.max_token_lifetime_secs,
            requires_human_approval: request.requires_human_approval,
            expires_at: request.expires_at.map(Some),
            inactivity_threshold_days: request.inactivity_threshold_days.map(Some),
            grace_period_ends_at: None,
            suspension_reason: None,
            rotation_interval_days: request.rotation_interval_days.map(Some),
            last_rotation_at: None,
        };

        let agent = AiAgent::update(&self.pool, tenant_id, agent_id, input)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        Ok(self.to_response(agent))
    }

    /// Delete an agent.
    pub async fn delete(&self, tenant_id: Uuid, agent_id: Uuid) -> Result<(), ApiAgentsError> {
        let deleted = AiAgent::delete(&self.pool, tenant_id, agent_id).await?;

        if !deleted {
            return Err(ApiAgentsError::AgentNotFound);
        }

        Ok(())
    }

    /// Suspend an agent.
    pub async fn suspend(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<AgentResponse, ApiAgentsError> {
        // Check current status
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        if agent.status == "suspended" {
            return Err(ApiAgentsError::AgentAlreadySuspended);
        }

        if agent.status == "expired" {
            return Err(ApiAgentsError::AgentExpired);
        }

        let suspended_agent = AiAgent::suspend(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        Ok(self.to_response(suspended_agent))
    }

    /// Reactivate a suspended agent.
    pub async fn reactivate(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<AgentResponse, ApiAgentsError> {
        // Check current status
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        if agent.status != "suspended" {
            return Err(ApiAgentsError::AgentCannotReactivate);
        }

        // Check if agent is expired
        if agent.is_expired() {
            return Err(ApiAgentsError::AgentExpired);
        }

        let reactivated_agent = AiAgent::reactivate(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        Ok(self.to_response(reactivated_agent))
    }

    /// Update the last activity timestamp for an agent.
    pub async fn update_last_activity(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<bool, ApiAgentsError> {
        Ok(AiAgent::update_last_activity(&self.pool, tenant_id, agent_id).await?)
    }

    /// Detect agents whose owner no longer exists (F108 governance).
    ///
    /// Returns agents where:
    /// - owner_id is set but the user no longer exists in the tenant
    /// - OR owner_id is NULL (unassigned)
    ///
    /// These agents need governance attention - either assign a new owner
    /// or promote the backup_owner.
    pub async fn detect_orphaned_agents(
        &self,
        tenant_id: Uuid,
    ) -> Result<OrphanedAgentListResponse, ApiAgentsError> {
        // Get all active agents for the tenant
        let filter = AiAgentFilter {
            status: Some("active".to_string()),
            agent_type: None,
            owner_id: None,
            risk_level: None,
            name_prefix: None,
        };

        let agents = AiAgent::list_by_tenant(&self.pool, tenant_id, &filter, 10000, 0).await?;

        let mut orphaned = Vec::new();

        for agent in agents {
            let is_orphaned = match agent.owner_id {
                None => true, // No owner assigned
                Some(owner_id) => {
                    // Check if owner still exists
                    !User::exists_in_tenant(&self.pool, tenant_id, owner_id).await?
                }
            };

            if is_orphaned {
                // Check if backup_owner exists and is valid
                let can_auto_promote = match agent.backup_owner_id {
                    Some(backup_id) => {
                        User::exists_in_tenant(&self.pool, tenant_id, backup_id).await?
                    }
                    None => false,
                };

                orphaned.push(OrphanedAgentResponse {
                    id: agent.id,
                    name: agent.name.clone(),
                    agent_type: agent.agent_type.clone(),
                    owner_id: agent.owner_id,
                    backup_owner_id: agent.backup_owner_id,
                    status: agent.status.clone(),
                    risk_level: agent.risk_level.clone(),
                    last_activity_at: agent.last_activity_at,
                    can_auto_promote,
                });
            }
        }

        let total = orphaned.len() as i64;
        Ok(OrphanedAgentListResponse {
            agents: orphaned,
            total,
        })
    }

    /// Promote backup owner to primary owner (F108 governance).
    ///
    /// This is used when the primary owner is no longer available
    /// (e.g., left the organization). The backup_owner becomes the new owner,
    /// and backup_owner is cleared.
    pub async fn promote_backup_owner(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<PromotionResponse, ApiAgentsError> {
        // Get the agent
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        // Verify there's a backup owner to promote
        let backup_owner_id = agent.backup_owner_id.ok_or(ApiAgentsError::NoBackupOwner)?;

        // Verify the backup owner exists
        if !User::exists_in_tenant(&self.pool, tenant_id, backup_owner_id).await? {
            return Err(ApiAgentsError::BackupOwnerNotFound);
        }

        let previous_owner_id = agent.owner_id;

        // Update: promote backup to owner, clear backup
        let input = UpdateAiAgent {
            name: None,
            description: None,
            owner_id: Some(Some(backup_owner_id)),
            team_id: None,
            backup_owner_id: Some(None), // Clear backup owner
            model_provider: None,
            model_name: None,
            model_version: None,
            agent_card_url: None,
            agent_card_signature: None,
            risk_level: None,
            max_token_lifetime_secs: None,
            requires_human_approval: None,
            expires_at: None,
            inactivity_threshold_days: None,
            grace_period_ends_at: None,
            suspension_reason: None,
            rotation_interval_days: None,
            last_rotation_at: None,
        };

        let updated_agent = AiAgent::update(&self.pool, tenant_id, agent_id, input)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        Ok(PromotionResponse {
            agent: self.to_response(updated_agent),
            previous_owner_id,
            new_owner_id: backup_owner_id,
        })
    }

    // =========================================================================
    // F108: US5 - Agent Inactivity Detection and Suspension
    // =========================================================================

    /// Check for inactive agents and return those that need attention (F108 US5).
    ///
    /// Returns agents where:
    /// - last_activity_at is older than their inactivity_threshold_days
    /// - OR last_activity_at is NULL and created_at is older than threshold
    ///
    /// These agents are candidates for grace period or suspension.
    pub async fn check_inactive_agents(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<AgentResponse>, ApiAgentsError> {
        // Get all active agents with inactivity thresholds configured
        let filter = AiAgentFilter {
            status: Some("active".to_string()),
            agent_type: None,
            owner_id: None,
            risk_level: None,
            name_prefix: None,
        };

        let agents = AiAgent::list_by_tenant(&self.pool, tenant_id, &filter, 10000, 0).await?;
        let now = chrono::Utc::now();

        let inactive: Vec<_> = agents
            .into_iter()
            .filter(|agent| {
                if let Some(threshold_days) = agent.inactivity_threshold_days {
                    let threshold = chrono::Duration::days(threshold_days as i64);
                    let last_activity = agent.last_activity_at.unwrap_or(agent.created_at);
                    now - last_activity > threshold
                } else {
                    false // No threshold configured = skip
                }
            })
            .map(|a| self.to_response(a))
            .collect();

        Ok(inactive)
    }

    /// Set grace period for an agent before suspension (F108 US5).
    ///
    /// Grace period gives the owner time to reactivate the agent
    /// before automatic suspension takes effect.
    pub async fn set_grace_period(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        grace_days: i32,
    ) -> Result<AgentResponse, ApiAgentsError> {
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        if agent.status != "active" {
            return Err(ApiAgentsError::AgentNotActive);
        }

        let grace_period_ends_at = chrono::Utc::now() + chrono::Duration::days(grace_days as i64);

        let input = UpdateAiAgent {
            grace_period_ends_at: Some(Some(grace_period_ends_at)),
            ..Default::default()
        };

        let updated = AiAgent::update(&self.pool, tenant_id, agent_id, input)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        Ok(self.to_response(updated))
    }

    /// Suspend an agent for inactivity (F108 US5).
    ///
    /// Sets status to suspended with suspension_reason = "Inactive".
    /// Clears the grace period since suspension is now in effect.
    pub async fn suspend_for_inactivity(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<AgentResponse, ApiAgentsError> {
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        if agent.status != "active" {
            return Err(ApiAgentsError::AgentNotActive);
        }

        // Use the existing suspend method first
        let _ = AiAgent::suspend(&self.pool, tenant_id, agent_id).await?;

        // Then update with the inactivity-specific fields
        let input = UpdateAiAgent {
            suspension_reason: Some(Some("Inactive".to_string())),
            grace_period_ends_at: Some(None), // Clear grace period
            ..Default::default()
        };

        let updated = AiAgent::update(&self.pool, tenant_id, agent_id, input)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        Ok(self.to_response(updated))
    }

    /// Reactivate an agent and reset inactivity counters (F108 US5).
    ///
    /// This extends the standard reactivate by also clearing
    /// grace_period_ends_at and suspension_reason.
    pub async fn reactivate_with_reset(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<AgentResponse, ApiAgentsError> {
        // Use standard reactivate first
        let _ = self.reactivate(tenant_id, agent_id).await?;

        // Then reset inactivity-related fields
        let input = UpdateAiAgent {
            grace_period_ends_at: Some(None),
            suspension_reason: Some(None),
            ..Default::default()
        };

        let updated = AiAgent::update(&self.pool, tenant_id, agent_id, input)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        Ok(self.to_response(updated))
    }

    // =========================================================================
    // F108: US6 - Agent Credential Rotation Tracking
    // =========================================================================

    /// Record a credential rotation for an agent (F108 US6).
    ///
    /// Updates last_rotation_at timestamp to NOW.
    pub async fn record_rotation(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
    ) -> Result<AgentResponse, ApiAgentsError> {
        let _ = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        let input = UpdateAiAgent {
            last_rotation_at: Some(chrono::Utc::now()),
            ..Default::default()
        };

        let updated = AiAgent::update(&self.pool, tenant_id, agent_id, input)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        Ok(self.to_response(updated))
    }

    /// Check for agents that need credential rotation (F108 US6).
    ///
    /// Returns agents where:
    /// - rotation_interval_days is set
    /// - last_rotation_at is older than rotation_interval_days (or never rotated)
    pub async fn check_rotation_needed(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<AgentResponse>, ApiAgentsError> {
        let filter = AiAgentFilter {
            status: Some("active".to_string()),
            agent_type: None,
            owner_id: None,
            risk_level: None,
            name_prefix: None,
        };

        let agents = AiAgent::list_by_tenant(&self.pool, tenant_id, &filter, 10000, 0).await?;
        let now = chrono::Utc::now();

        let needs_rotation: Vec<_> = agents
            .into_iter()
            .filter(|agent| {
                if let Some(interval_days) = agent.rotation_interval_days {
                    let interval = chrono::Duration::days(interval_days as i64);
                    match agent.last_rotation_at {
                        Some(last_rotation) => now - last_rotation > interval,
                        None => true, // Never rotated = needs rotation
                    }
                } else {
                    false // No interval configured = skip
                }
            })
            .map(|a| self.to_response(a))
            .collect();

        Ok(needs_rotation)
    }

    // =========================================================================
    // F123: Three-Layer Authorization - User-Agent Check
    // =========================================================================

    /// Check if a user can operate an agent (F123 three-layer authorization).
    ///
    /// Part of the three-layer authorization model:
    /// 1. User can operate agent (this method) - checks owner/backup_owner
    /// 2. Agent is active and valid - checked separately
    /// 3. Agent has permission for specific tool - checked separately
    ///
    /// A user can operate an agent if they are:
    /// - The agent's owner (owner_id)
    /// - The agent's backup owner (backup_owner_id)
    /// - (Future: member of the agent's team)
    pub async fn can_operate(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        user_id: Uuid,
    ) -> Result<CanOperateResponse, ApiAgentsError> {
        // Get the agent
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await?
            .ok_or(ApiAgentsError::AgentNotFound)?;

        // Check if user is the owner
        if let Some(owner_id) = agent.owner_id {
            if owner_id == user_id {
                return Ok(CanOperateResponse {
                    can_operate: true,
                    reason: "User is agent owner".to_string(),
                    permissions: vec!["full_access".to_string()],
                });
            }
        }

        // Check if user is the backup owner
        if let Some(backup_owner_id) = agent.backup_owner_id {
            if backup_owner_id == user_id {
                return Ok(CanOperateResponse {
                    can_operate: true,
                    reason: "User is backup owner".to_string(),
                    permissions: vec!["operate".to_string()],
                });
            }
        }

        // Future: Check team membership
        // if let Some(team_id) = agent.team_id {
        //     if is_user_in_team(tenant_id, team_id, user_id).await? {
        //         return Ok(CanOperateResponse { ... });
        //     }
        // }

        // User is not authorized to operate this agent
        Ok(CanOperateResponse {
            can_operate: false,
            reason: "User is not owner or backup owner of this agent".to_string(),
            permissions: vec![],
        })
    }

    /// Validate agent type.
    fn validate_agent_type(&self, agent_type: &str) -> Result<(), ApiAgentsError> {
        match agent_type.to_lowercase().as_str() {
            "autonomous" | "copilot" | "workflow" | "orchestrator" => Ok(()),
            _ => Err(ApiAgentsError::InvalidAgentType(agent_type.to_string())),
        }
    }

    /// Validate risk level.
    fn validate_risk_level(&self, risk_level: &str) -> Result<(), ApiAgentsError> {
        match risk_level.to_lowercase().as_str() {
            "low" | "medium" | "high" | "critical" => Ok(()),
            _ => Err(ApiAgentsError::InvalidRiskLevel(risk_level.to_string())),
        }
    }

    /// Convert database model to API response.
    fn to_response(&self, agent: AiAgent) -> AgentResponse {
        AgentResponse {
            id: agent.id,
            name: agent.name,
            description: agent.description,
            agent_type: agent.agent_type,
            owner_id: agent.owner_id,
            team_id: agent.team_id,
            backup_owner_id: agent.backup_owner_id,
            model_provider: agent.model_provider,
            model_name: agent.model_name,
            status: agent.status,
            risk_level: agent.risk_level,
            max_token_lifetime_secs: agent.max_token_lifetime_secs,
            requires_human_approval: agent.requires_human_approval,
            created_at: agent.created_at,
            updated_at: agent.updated_at,
            last_activity_at: agent.last_activity_at,
            expires_at: agent.expires_at,
            // F108 governance fields
            inactivity_threshold_days: agent.inactivity_threshold_days,
            grace_period_ends_at: agent.grace_period_ends_at,
            suspension_reason: agent.suspension_reason,
            rotation_interval_days: agent.rotation_interval_days,
            last_rotation_at: agent.last_rotation_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test validation functions without requiring a database connection
    fn validate_agent_type(agent_type: &str) -> Result<(), ApiAgentsError> {
        match agent_type.to_lowercase().as_str() {
            "autonomous" | "copilot" | "workflow" | "orchestrator" => Ok(()),
            _ => Err(ApiAgentsError::InvalidAgentType(agent_type.to_string())),
        }
    }

    fn validate_risk_level(risk_level: &str) -> Result<(), ApiAgentsError> {
        match risk_level.to_lowercase().as_str() {
            "low" | "medium" | "high" | "critical" => Ok(()),
            _ => Err(ApiAgentsError::InvalidRiskLevel(risk_level.to_string())),
        }
    }

    #[test]
    fn test_validate_agent_type() {
        assert!(validate_agent_type("autonomous").is_ok());
        assert!(validate_agent_type("copilot").is_ok());
        assert!(validate_agent_type("workflow").is_ok());
        assert!(validate_agent_type("orchestrator").is_ok());
        assert!(validate_agent_type("COPILOT").is_ok());
        assert!(validate_agent_type("invalid").is_err());
    }

    #[test]
    fn test_validate_risk_level() {
        assert!(validate_risk_level("low").is_ok());
        assert!(validate_risk_level("medium").is_ok());
        assert!(validate_risk_level("high").is_ok());
        assert!(validate_risk_level("critical").is_ok());
        assert!(validate_risk_level("HIGH").is_ok());
        assert!(validate_risk_level("invalid").is_err());
    }
}
