//! AI Agent model for agent identity registry.
//!
//! Represents AI agent identities with A2A `AgentCard` support,
//! ownership tracking, and security settings per OWASP ASI guidelines.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Agent type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiAgentType {
    /// Fully autonomous agent that can act independently.
    Autonomous,
    /// Co-pilot agent that assists users with suggestions.
    Copilot,
    /// Workflow agent that executes predefined sequences.
    Workflow,
    /// Orchestrator agent that coordinates other agents.
    Orchestrator,
}

impl std::fmt::Display for AiAgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiAgentType::Autonomous => write!(f, "autonomous"),
            AiAgentType::Copilot => write!(f, "copilot"),
            AiAgentType::Workflow => write!(f, "workflow"),
            AiAgentType::Orchestrator => write!(f, "orchestrator"),
        }
    }
}

impl std::str::FromStr for AiAgentType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "autonomous" => Ok(AiAgentType::Autonomous),
            "copilot" => Ok(AiAgentType::Copilot),
            "workflow" => Ok(AiAgentType::Workflow),
            "orchestrator" => Ok(AiAgentType::Orchestrator),
            _ => Err(format!("Invalid agent type: {s}")),
        }
    }
}

/// Agent status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiAgentStatus {
    /// Agent is active and can make requests.
    Active,
    /// Agent is temporarily suspended.
    Suspended,
    /// Agent has expired and cannot be used.
    Expired,
}

impl std::fmt::Display for AiAgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiAgentStatus::Active => write!(f, "active"),
            AiAgentStatus::Suspended => write!(f, "suspended"),
            AiAgentStatus::Expired => write!(f, "expired"),
        }
    }
}

impl std::str::FromStr for AiAgentStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(AiAgentStatus::Active),
            "suspended" => Ok(AiAgentStatus::Suspended),
            "expired" => Ok(AiAgentStatus::Expired),
            _ => Err(format!("Invalid agent status: {s}")),
        }
    }
}

/// An AI agent registered in the system.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AiAgent {
    /// Unique identifier for the agent.
    pub id: Uuid,

    /// The tenant this agent belongs to.
    pub tenant_id: Uuid,

    /// Agent display name (unique per tenant).
    pub name: String,

    /// Agent description.
    pub description: Option<String>,

    /// Agent type classification.
    pub agent_type: String,

    /// User responsible for this agent (OWASP ASI03).
    pub owner_id: Option<Uuid>,

    /// Team/group associated with this agent.
    pub team_id: Option<Uuid>,

    /// Backup owner for governance continuity (F108).
    pub backup_owner_id: Option<Uuid>,

    /// Model provider (anthropic, openai, google, etc.).
    pub model_provider: Option<String>,

    /// Model name (claude-sonnet-4, gpt-4, etc.).
    pub model_name: Option<String>,

    /// Specific model version.
    pub model_version: Option<String>,

    /// A2A Protocol: URL to /.well-known/agent.json.
    pub agent_card_url: Option<String>,

    /// A2A Protocol: JWS signature for `AgentCard` verification.
    pub agent_card_signature: Option<String>,

    /// Agent status (active, suspended, expired).
    pub status: String,

    /// Risk level (low, medium, high, critical).
    pub risk_level: String,

    /// Maximum OAuth token lifetime in seconds.
    pub max_token_lifetime_secs: i32,

    /// OWASP ASI09: Require human-in-the-loop for sensitive operations.
    pub requires_human_approval: bool,

    /// When the agent was created.
    pub created_at: DateTime<Utc>,

    /// When the agent was last updated.
    pub updated_at: DateTime<Utc>,

    /// Last authorization request timestamp.
    pub last_activity_at: Option<DateTime<Utc>>,

    /// Optional expiration date.
    pub expires_at: Option<DateTime<Utc>>,

    // F108: Inactivity detection fields
    /// Days of inactivity before agent enters grace period.
    pub inactivity_threshold_days: Option<i32>,

    /// When grace period expires and agent will be suspended.
    pub grace_period_ends_at: Option<DateTime<Utc>>,

    /// Reason for suspension (Inactive, `CertificationRevoked`, Emergency, Manual).
    pub suspension_reason: Option<String>,

    // F108: Credential rotation tracking
    /// Number of days between required credential rotations.
    pub rotation_interval_days: Option<i32>,

    /// Timestamp of last credential rotation.
    pub last_rotation_at: Option<DateTime<Utc>>,

    // F108: Risk and certification tracking
    /// Unified risk score 0-100 for governance dashboard.
    pub risk_score: Option<i32>,

    /// When next certification review is due.
    pub next_certification_at: Option<DateTime<Utc>>,

    /// Timestamp of last certification.
    pub last_certified_at: Option<DateTime<Utc>>,

    /// User who performed last certification.
    pub last_certified_by: Option<Uuid>,
}

impl AiAgent {
    /// Returns the agent type as an enum.
    pub fn agent_type_enum(&self) -> Result<AiAgentType, String> {
        self.agent_type.parse()
    }

    /// Returns the agent status as an enum.
    pub fn status_enum(&self) -> Result<AiAgentStatus, String> {
        self.status.parse()
    }

    /// Returns the risk level as an enum.
    pub fn risk_level_enum(&self) -> Result<super::ai_tool::AiRiskLevel, String> {
        self.risk_level.parse()
    }

    /// Check if the agent is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// Check if the agent has expired.
    #[must_use] 
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            self.status == "expired"
        }
    }
}

/// Request to create a new AI agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateAiAgent {
    /// Agent display name (unique per tenant).
    pub name: String,

    /// Agent description.
    pub description: Option<String>,

    /// Agent type (autonomous, copilot, workflow, orchestrator).
    pub agent_type: String,

    /// User responsible for this agent.
    pub owner_id: Option<Uuid>,

    /// Team/group associated with this agent.
    pub team_id: Option<Uuid>,

    /// Backup owner for governance continuity (F108).
    pub backup_owner_id: Option<Uuid>,

    /// Model provider.
    pub model_provider: Option<String>,

    /// Model name.
    pub model_name: Option<String>,

    /// Model version.
    pub model_version: Option<String>,

    /// A2A `AgentCard` URL.
    pub agent_card_url: Option<String>,

    /// Risk level (default: medium).
    #[serde(default = "default_risk_level")]
    pub risk_level: String,

    /// Max token lifetime in seconds (default: 900).
    #[serde(default = "default_token_lifetime")]
    pub max_token_lifetime_secs: i32,

    /// Require human approval (default: false).
    #[serde(default)]
    pub requires_human_approval: bool,

    /// Optional expiration date.
    pub expires_at: Option<DateTime<Utc>>,

    // F108: Inactivity detection
    /// Days of inactivity before grace period (default: 90).
    #[serde(default = "default_inactivity_threshold")]
    pub inactivity_threshold_days: Option<i32>,

    // F108: Credential rotation tracking
    /// Days between required credential rotations.
    pub rotation_interval_days: Option<i32>,
}

fn default_inactivity_threshold() -> Option<i32> {
    Some(90)
}

fn default_risk_level() -> String {
    "medium".to_string()
}

fn default_token_lifetime() -> i32 {
    900
}

/// Request to update an AI agent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateAiAgent {
    /// Updated agent name.
    pub name: Option<String>,

    /// Updated description.
    pub description: Option<String>,

    /// Updated owner.
    pub owner_id: Option<Option<Uuid>>,

    /// Updated team.
    pub team_id: Option<Option<Uuid>>,

    /// Updated backup owner (F108).
    pub backup_owner_id: Option<Option<Uuid>>,

    /// Updated model provider.
    pub model_provider: Option<String>,

    /// Updated model name.
    pub model_name: Option<String>,

    /// Updated model version.
    pub model_version: Option<String>,

    /// Updated `AgentCard` URL.
    pub agent_card_url: Option<String>,

    /// Updated `AgentCard` signature.
    pub agent_card_signature: Option<String>,

    /// Updated risk level.
    pub risk_level: Option<String>,

    /// Updated max token lifetime.
    pub max_token_lifetime_secs: Option<i32>,

    /// Updated human approval requirement.
    pub requires_human_approval: Option<bool>,

    /// Updated expiration date.
    pub expires_at: Option<Option<DateTime<Utc>>>,

    // F108: Inactivity detection
    /// Updated inactivity threshold in days.
    pub inactivity_threshold_days: Option<Option<i32>>,

    /// Updated grace period end date.
    pub grace_period_ends_at: Option<Option<DateTime<Utc>>>,

    /// Updated suspension reason.
    pub suspension_reason: Option<Option<String>>,

    // F108: Credential rotation tracking
    /// Updated rotation interval in days.
    pub rotation_interval_days: Option<Option<i32>>,

    /// Updated last rotation timestamp.
    pub last_rotation_at: Option<DateTime<Utc>>,
}

/// Filter options for listing AI agents.
#[derive(Debug, Clone, Default)]
pub struct AiAgentFilter {
    /// Filter by status.
    pub status: Option<String>,

    /// Filter by agent type.
    pub agent_type: Option<String>,

    /// Filter by owner.
    pub owner_id: Option<Uuid>,

    /// Filter by risk level.
    pub risk_level: Option<String>,

    /// Search by name prefix.
    pub name_prefix: Option<String>,
}

impl AiAgent {
    /// Find an agent by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM ai_agents
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update the `last_rotation_at` timestamp for an agent.
    pub async fn update_last_rotation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE ai_agents
            SET last_rotation_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an agent by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM ai_agents
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List agents for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AiAgentFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM ai_agents
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        if filter.agent_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND agent_type = ${param_count}"));
        }

        if filter.owner_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND owner_id = ${param_count}"));
        }

        if filter.risk_level.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND risk_level = ${param_count}"));
        }

        if filter.name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${param_count} || '%'"));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, AiAgent>(&query).bind(tenant_id);

        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }
        if let Some(ref agent_type) = filter.agent_type {
            q = q.bind(agent_type);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }
        if let Some(ref risk_level) = filter.risk_level {
            q = q.bind(risk_level);
        }
        if let Some(ref prefix) = filter.name_prefix {
            q = q.bind(prefix);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count agents in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &AiAgentFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM ai_agents
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        if filter.agent_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND agent_type = ${param_count}"));
        }

        if filter.owner_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND owner_id = ${param_count}"));
        }

        if filter.risk_level.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND risk_level = ${param_count}"));
        }

        if filter.name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${param_count} || '%'"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }
        if let Some(ref agent_type) = filter.agent_type {
            q = q.bind(agent_type);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }
        if let Some(ref risk_level) = filter.risk_level {
            q = q.bind(risk_level);
        }
        if let Some(ref prefix) = filter.name_prefix {
            q = q.bind(prefix);
        }

        q.fetch_one(pool).await
    }

    /// Create a new AI agent.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateAiAgent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO ai_agents (
                tenant_id, name, description, agent_type, owner_id, team_id,
                backup_owner_id, model_provider, model_name, model_version, agent_card_url,
                risk_level, max_token_lifetime_secs, requires_human_approval, expires_at,
                inactivity_threshold_days, rotation_interval_days
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.agent_type)
        .bind(input.owner_id)
        .bind(input.team_id)
        .bind(input.backup_owner_id)
        .bind(&input.model_provider)
        .bind(&input.model_name)
        .bind(&input.model_version)
        .bind(&input.agent_card_url)
        .bind(&input.risk_level)
        .bind(input.max_token_lifetime_secs)
        .bind(input.requires_human_approval)
        .bind(input.expires_at)
        .bind(input.inactivity_threshold_days)
        .bind(input.rotation_interval_days)
        .fetch_one(pool)
        .await
    }

    /// Update an existing AI agent.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateAiAgent,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Build dynamic update query
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.owner_id.is_some() {
            updates.push(format!("owner_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.team_id.is_some() {
            updates.push(format!("team_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.backup_owner_id.is_some() {
            updates.push(format!("backup_owner_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.model_provider.is_some() {
            updates.push(format!("model_provider = ${param_idx}"));
            param_idx += 1;
        }
        if input.model_name.is_some() {
            updates.push(format!("model_name = ${param_idx}"));
            param_idx += 1;
        }
        if input.model_version.is_some() {
            updates.push(format!("model_version = ${param_idx}"));
            param_idx += 1;
        }
        if input.agent_card_url.is_some() {
            updates.push(format!("agent_card_url = ${param_idx}"));
            param_idx += 1;
        }
        if input.agent_card_signature.is_some() {
            updates.push(format!("agent_card_signature = ${param_idx}"));
            param_idx += 1;
        }
        if input.risk_level.is_some() {
            updates.push(format!("risk_level = ${param_idx}"));
            param_idx += 1;
        }
        if input.max_token_lifetime_secs.is_some() {
            updates.push(format!("max_token_lifetime_secs = ${param_idx}"));
            param_idx += 1;
        }
        if input.requires_human_approval.is_some() {
            updates.push(format!("requires_human_approval = ${param_idx}"));
            param_idx += 1;
        }
        if input.expires_at.is_some() {
            updates.push(format!("expires_at = ${param_idx}"));
            param_idx += 1;
        }
        if input.inactivity_threshold_days.is_some() {
            updates.push(format!("inactivity_threshold_days = ${param_idx}"));
            param_idx += 1;
        }
        if input.grace_period_ends_at.is_some() {
            updates.push(format!("grace_period_ends_at = ${param_idx}"));
            param_idx += 1;
        }
        if input.suspension_reason.is_some() {
            updates.push(format!("suspension_reason = ${param_idx}"));
            param_idx += 1;
        }
        if input.rotation_interval_days.is_some() {
            updates.push(format!("rotation_interval_days = ${param_idx}"));
            param_idx += 1;
        }
        if input.last_rotation_at.is_some() {
            updates.push(format!("last_rotation_at = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE ai_agents SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, AiAgent>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(ref owner_opt) = input.owner_id {
            q = q.bind(*owner_opt);
        }
        if let Some(ref team_opt) = input.team_id {
            q = q.bind(*team_opt);
        }
        if let Some(ref backup_owner_opt) = input.backup_owner_id {
            q = q.bind(*backup_owner_opt);
        }
        if let Some(ref model_provider) = input.model_provider {
            q = q.bind(model_provider);
        }
        if let Some(ref model_name) = input.model_name {
            q = q.bind(model_name);
        }
        if let Some(ref model_version) = input.model_version {
            q = q.bind(model_version);
        }
        if let Some(ref agent_card_url) = input.agent_card_url {
            q = q.bind(agent_card_url);
        }
        if let Some(ref agent_card_signature) = input.agent_card_signature {
            q = q.bind(agent_card_signature);
        }
        if let Some(ref risk_level) = input.risk_level {
            q = q.bind(risk_level);
        }
        if let Some(max_token_lifetime_secs) = input.max_token_lifetime_secs {
            q = q.bind(max_token_lifetime_secs);
        }
        if let Some(requires_human_approval) = input.requires_human_approval {
            q = q.bind(requires_human_approval);
        }
        if let Some(ref expires_opt) = input.expires_at {
            q = q.bind(*expires_opt);
        }
        if let Some(ref inactivity_opt) = input.inactivity_threshold_days {
            q = q.bind(*inactivity_opt);
        }
        if let Some(ref grace_opt) = input.grace_period_ends_at {
            q = q.bind(*grace_opt);
        }
        if let Some(ref reason_opt) = input.suspension_reason {
            q = q.bind(reason_opt.clone());
        }
        if let Some(ref rotation_opt) = input.rotation_interval_days {
            q = q.bind(*rotation_opt);
        }
        if let Some(last_rotation) = input.last_rotation_at {
            q = q.bind(last_rotation);
        }

        q.fetch_optional(pool).await
    }

    /// Delete an AI agent.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM ai_agents
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Suspend an AI agent.
    pub async fn suspend(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE ai_agents
            SET status = 'suspended', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Reactivate a suspended AI agent.
    pub async fn reactivate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE ai_agents
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'suspended'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update the last activity timestamp.
    pub async fn update_last_activity(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE ai_agents
            SET last_activity_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_agent_serialization() {
        let agent = AiAgent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test-agent".to_string(),
            description: Some("Test agent".to_string()),
            agent_type: "copilot".to_string(),
            owner_id: Some(Uuid::new_v4()),
            team_id: None,
            backup_owner_id: None,
            model_provider: Some("anthropic".to_string()),
            model_name: Some("claude-sonnet-4".to_string()),
            model_version: Some("20260101".to_string()),
            agent_card_url: Some("https://example.com/.well-known/agent.json".to_string()),
            agent_card_signature: None,
            status: "active".to_string(),
            risk_level: "medium".to_string(),
            max_token_lifetime_secs: 900,
            requires_human_approval: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_activity_at: None,
            expires_at: None,
            // F108 governance fields
            inactivity_threshold_days: Some(90),
            grace_period_ends_at: None,
            suspension_reason: None,
            rotation_interval_days: None,
            last_rotation_at: None,
            risk_score: None,
            next_certification_at: None,
            last_certified_at: None,
            last_certified_by: None,
        };

        let json = serde_json::to_string(&agent).unwrap();
        assert!(json.contains("test-agent"));
        assert!(json.contains("copilot"));
        assert!(json.contains("anthropic"));

        let deserialized: AiAgent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test-agent");
        assert_eq!(deserialized.agent_type, "copilot");
    }

    #[test]
    fn test_create_ai_agent_defaults() {
        let input = CreateAiAgent {
            name: "new-agent".to_string(),
            description: None,
            agent_type: "autonomous".to_string(),
            owner_id: None,
            team_id: None,
            backup_owner_id: None,
            model_provider: None,
            model_name: None,
            model_version: None,
            agent_card_url: None,
            risk_level: default_risk_level(),
            max_token_lifetime_secs: default_token_lifetime(),
            requires_human_approval: false,
            expires_at: None,
            inactivity_threshold_days: default_inactivity_threshold(),
            rotation_interval_days: None,
        };

        assert_eq!(input.risk_level, "medium");
        assert_eq!(input.max_token_lifetime_secs, 900);
        assert!(!input.requires_human_approval);
    }

    #[test]
    fn test_update_ai_agent_struct() {
        let update = UpdateAiAgent {
            name: Some("renamed-agent".to_string()),
            risk_level: Some("high".to_string()),
            ..Default::default()
        };

        assert!(update.name.is_some());
        assert!(update.risk_level.is_some());
        assert!(update.description.is_none());
    }

    #[test]
    fn test_ai_agent_filter() {
        let filter = AiAgentFilter {
            status: Some("active".to_string()),
            agent_type: Some("copilot".to_string()),
            owner_id: None,
            risk_level: None,
            name_prefix: Some("test".to_string()),
        };

        assert_eq!(filter.status, Some("active".to_string()));
        assert_eq!(filter.agent_type, Some("copilot".to_string()));
        assert!(filter.owner_id.is_none());
    }

    #[test]
    fn test_ai_agent_type_display() {
        assert_eq!(AiAgentType::Autonomous.to_string(), "autonomous");
        assert_eq!(AiAgentType::Copilot.to_string(), "copilot");
        assert_eq!(AiAgentType::Workflow.to_string(), "workflow");
        assert_eq!(AiAgentType::Orchestrator.to_string(), "orchestrator");
    }

    #[test]
    fn test_ai_agent_type_from_str() {
        assert_eq!(
            "autonomous".parse::<AiAgentType>().unwrap(),
            AiAgentType::Autonomous
        );
        assert_eq!(
            "COPILOT".parse::<AiAgentType>().unwrap(),
            AiAgentType::Copilot
        );
        assert_eq!(
            "Workflow".parse::<AiAgentType>().unwrap(),
            AiAgentType::Workflow
        );
        assert!("invalid".parse::<AiAgentType>().is_err());
    }

    #[test]
    fn test_ai_agent_status_display() {
        assert_eq!(AiAgentStatus::Active.to_string(), "active");
        assert_eq!(AiAgentStatus::Suspended.to_string(), "suspended");
        assert_eq!(AiAgentStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn test_ai_agent_status_from_str() {
        assert_eq!(
            "active".parse::<AiAgentStatus>().unwrap(),
            AiAgentStatus::Active
        );
        assert_eq!(
            "SUSPENDED".parse::<AiAgentStatus>().unwrap(),
            AiAgentStatus::Suspended
        );
        assert!("invalid".parse::<AiAgentStatus>().is_err());
    }

    #[test]
    fn test_ai_agent_helper_methods() {
        let agent = AiAgent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test-agent".to_string(),
            description: None,
            agent_type: "copilot".to_string(),
            owner_id: None,
            team_id: None,
            backup_owner_id: None,
            model_provider: None,
            model_name: None,
            model_version: None,
            agent_card_url: None,
            agent_card_signature: None,
            status: "active".to_string(),
            risk_level: "medium".to_string(),
            max_token_lifetime_secs: 900,
            requires_human_approval: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_activity_at: None,
            expires_at: None,
            // F108 governance fields
            inactivity_threshold_days: Some(90),
            grace_period_ends_at: None,
            suspension_reason: None,
            rotation_interval_days: None,
            last_rotation_at: None,
            risk_score: None,
            next_certification_at: None,
            last_certified_at: None,
            last_certified_by: None,
        };

        assert!(agent.is_active());
        assert!(!agent.is_expired());
        assert_eq!(agent.agent_type_enum().unwrap(), AiAgentType::Copilot);
        assert_eq!(agent.status_enum().unwrap(), AiAgentStatus::Active);
    }

    #[test]
    fn test_ai_agent_is_expired() {
        use chrono::Duration;

        // Agent with past expiration date
        let expired_agent = AiAgent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "expired-agent".to_string(),
            description: None,
            agent_type: "autonomous".to_string(),
            owner_id: None,
            team_id: None,
            backup_owner_id: None,
            model_provider: None,
            model_name: None,
            model_version: None,
            agent_card_url: None,
            agent_card_signature: None,
            status: "active".to_string(),
            risk_level: "low".to_string(),
            max_token_lifetime_secs: 900,
            requires_human_approval: false,
            created_at: Utc::now() - Duration::days(30),
            updated_at: Utc::now() - Duration::days(30),
            last_activity_at: None,
            expires_at: Some(Utc::now() - Duration::days(1)),
            // F108 governance fields
            inactivity_threshold_days: Some(90),
            grace_period_ends_at: None,
            suspension_reason: None,
            rotation_interval_days: None,
            last_rotation_at: None,
            risk_score: None,
            next_certification_at: None,
            last_certified_at: None,
            last_certified_by: None,
        };

        assert!(expired_agent.is_expired());

        // Agent with future expiration
        let active_agent = AiAgent {
            expires_at: Some(Utc::now() + Duration::days(30)),
            ..expired_agent.clone()
        };

        assert!(!active_agent.is_expired());
    }
}
