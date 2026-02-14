-- Migration: 891_ai_agents
-- Feature: F089 - AI Agent Security Platform
-- Description: Create ai_agents table for AI agent identity registry with A2A AgentCard support

-- Create ai_agents table
CREATE TABLE IF NOT EXISTS ai_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,
    agent_type VARCHAR(50) NOT NULL,

    -- Ownership & Accountability (OWASP ASI03)
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    team_id UUID REFERENCES groups(id) ON DELETE SET NULL,

    -- Model Info
    model_provider VARCHAR(100),
    model_name VARCHAR(100),
    model_version VARCHAR(50),

    -- A2A Protocol
    agent_card_url VARCHAR(500),
    agent_card_signature TEXT,

    -- Security
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    risk_level VARCHAR(20) NOT NULL DEFAULT 'medium',
    max_token_lifetime_secs INTEGER NOT NULL DEFAULT 900,
    requires_human_approval BOOLEAN NOT NULL DEFAULT false,

    -- Lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT ai_agents_tenant_name_unique UNIQUE (tenant_id, name),
    CONSTRAINT ai_agents_type_check CHECK (agent_type IN ('autonomous', 'copilot', 'workflow', 'orchestrator')),
    CONSTRAINT ai_agents_status_check CHECK (status IN ('active', 'suspended', 'expired')),
    CONSTRAINT ai_agents_risk_level_check CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT ai_agents_token_lifetime_check CHECK (max_token_lifetime_secs > 0 AND max_token_lifetime_secs <= 86400)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_ai_agents_tenant ON ai_agents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_agents_tenant_name ON ai_agents(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_ai_agents_tenant_status ON ai_agents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_ai_agents_tenant_owner ON ai_agents(tenant_id, owner_id);
CREATE INDEX IF NOT EXISTS idx_ai_agents_tenant_type ON ai_agents(tenant_id, agent_type);

-- Enable RLS
ALTER TABLE ai_agents ENABLE ROW LEVEL SECURITY;

-- RLS policies for tenant isolation
CREATE POLICY ai_agents_tenant_isolation_select ON ai_agents
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_agents_tenant_isolation_insert ON ai_agents
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_agents_tenant_isolation_update ON ai_agents
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_agents_tenant_isolation_delete ON ai_agents
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Comments for documentation
COMMENT ON TABLE ai_agents IS 'AI agent identity registry with A2A AgentCard support (F089)';
COMMENT ON COLUMN ai_agents.agent_type IS 'Agent classification: autonomous, copilot, workflow, orchestrator';
COMMENT ON COLUMN ai_agents.owner_id IS 'User responsible for this agent (OWASP ASI03)';
COMMENT ON COLUMN ai_agents.agent_card_url IS 'A2A Protocol: URL to /.well-known/agent.json';
COMMENT ON COLUMN ai_agents.agent_card_signature IS 'A2A Protocol: JWS signature for AgentCard verification';
COMMENT ON COLUMN ai_agents.max_token_lifetime_secs IS 'Maximum OAuth token lifetime in seconds (default 900 = 15 min per arXiv security recommendation)';
COMMENT ON COLUMN ai_agents.requires_human_approval IS 'OWASP ASI09: Require human-in-the-loop for sensitive operations';
