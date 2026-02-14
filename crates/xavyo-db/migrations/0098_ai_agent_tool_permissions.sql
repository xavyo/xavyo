-- Migration: 893_ai_agent_tool_permissions
-- Feature: F089 - AI Agent Security Platform
-- Description: Create ai_agent_tool_permissions table for agent-tool permission mapping

-- Create ai_agent_tool_permissions table
CREATE TABLE IF NOT EXISTS ai_agent_tool_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    tool_id UUID NOT NULL REFERENCES ai_tools(id) ON DELETE CASCADE,

    -- Scope restrictions
    allowed_parameters JSONB,
    max_calls_per_hour INTEGER,
    requires_approval BOOLEAN,

    -- Validity
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT ai_perms_tenant_agent_tool_unique UNIQUE (tenant_id, agent_id, tool_id)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_ai_perms_tenant ON ai_agent_tool_permissions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_perms_tenant_agent ON ai_agent_tool_permissions(tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_ai_perms_tenant_tool ON ai_agent_tool_permissions(tenant_id, tool_id);
CREATE INDEX IF NOT EXISTS idx_ai_perms_granted_by ON ai_agent_tool_permissions(granted_by);
CREATE INDEX IF NOT EXISTS idx_ai_perms_expires ON ai_agent_tool_permissions(tenant_id, expires_at) WHERE expires_at IS NOT NULL;

-- Enable RLS
ALTER TABLE ai_agent_tool_permissions ENABLE ROW LEVEL SECURITY;

-- RLS policies for tenant isolation
CREATE POLICY ai_perms_tenant_isolation_select ON ai_agent_tool_permissions
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_perms_tenant_isolation_insert ON ai_agent_tool_permissions
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_perms_tenant_isolation_update ON ai_agent_tool_permissions
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_perms_tenant_isolation_delete ON ai_agent_tool_permissions
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Comments for documentation
COMMENT ON TABLE ai_agent_tool_permissions IS 'Agent-tool permission mapping for least-privilege access control (F089)';
COMMENT ON COLUMN ai_agent_tool_permissions.allowed_parameters IS 'JSON object restricting which parameter values the agent can use';
COMMENT ON COLUMN ai_agent_tool_permissions.max_calls_per_hour IS 'Override default tool rate limit for this agent';
COMMENT ON COLUMN ai_agent_tool_permissions.requires_approval IS 'Override default tool approval requirement for this agent';
COMMENT ON COLUMN ai_agent_tool_permissions.granted_by IS 'User who granted this permission (audit trail)';
COMMENT ON COLUMN ai_agent_tool_permissions.expires_at IS 'Optional permission expiration for time-limited access';
