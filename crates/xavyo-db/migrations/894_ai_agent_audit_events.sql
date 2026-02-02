-- Migration: 894_ai_agent_audit_events
-- Feature: F089 - AI Agent Security Platform
-- Description: Create ai_agent_audit_events table for agent activity audit trail

-- Create ai_agent_audit_events table
CREATE TABLE IF NOT EXISTS ai_agent_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES ai_agents(id) ON DELETE SET NULL,

    -- Event type
    event_type VARCHAR(100) NOT NULL,

    -- Context (OWASP ASI01, ASI06 - prevent goal hijack, memory poisoning)
    conversation_id VARCHAR(255),
    session_id VARCHAR(255),
    user_instruction TEXT,
    agent_reasoning TEXT,

    -- Tool details
    tool_id UUID REFERENCES ai_tools(id) ON DELETE SET NULL,
    tool_name VARCHAR(255),
    parameters JSONB,

    -- Decision
    decision VARCHAR(50),
    decision_reason TEXT,
    policy_id UUID,

    -- Outcome
    outcome VARCHAR(50),
    error_message TEXT,

    -- Metadata
    source_ip INET,
    user_agent TEXT,
    duration_ms INTEGER,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT ai_audit_event_type_check CHECK (event_type IN ('tool_invocation', 'authorization', 'approval_request', 'approval_decision', 'agent_lifecycle')),
    CONSTRAINT ai_audit_decision_check CHECK (decision IS NULL OR decision IN ('allowed', 'denied', 'approved', 'rejected', 'require_approval')),
    CONSTRAINT ai_audit_outcome_check CHECK (outcome IS NULL OR outcome IN ('success', 'failure', 'error', 'timeout', 'cancelled'))
);

-- Indexes for common query patterns (optimized for time-series queries)
CREATE INDEX IF NOT EXISTS idx_ai_audit_tenant ON ai_agent_audit_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_audit_tenant_agent ON ai_agent_audit_events(tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_ai_audit_tenant_agent_time ON ai_agent_audit_events(tenant_id, agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ai_audit_tenant_time ON ai_agent_audit_events(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ai_audit_event_type ON ai_agent_audit_events(tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_ai_audit_decision ON ai_agent_audit_events(tenant_id, decision) WHERE decision IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_audit_conversation ON ai_agent_audit_events(tenant_id, conversation_id) WHERE conversation_id IS NOT NULL;

-- Enable RLS
ALTER TABLE ai_agent_audit_events ENABLE ROW LEVEL SECURITY;

-- RLS policies for tenant isolation
CREATE POLICY ai_audit_tenant_isolation_select ON ai_agent_audit_events
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_audit_tenant_isolation_insert ON ai_agent_audit_events
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Note: No UPDATE or DELETE policies - audit events are immutable
-- If needed for compliance, add policies with restricted conditions

-- Comments for documentation
COMMENT ON TABLE ai_agent_audit_events IS 'Immutable audit trail for agent activities (F089)';
COMMENT ON COLUMN ai_agent_audit_events.event_type IS 'Type of event: tool_invocation, authorization, approval_request, approval_decision, agent_lifecycle';
COMMENT ON COLUMN ai_agent_audit_events.conversation_id IS 'OWASP ASI01/ASI06: Conversation context for goal hijack prevention';
COMMENT ON COLUMN ai_agent_audit_events.user_instruction IS 'What the user asked the agent to do (audit trail)';
COMMENT ON COLUMN ai_agent_audit_events.agent_reasoning IS 'Why the agent decided to take this action (explainability)';
COMMENT ON COLUMN ai_agent_audit_events.tool_name IS 'Denormalized tool name for history preservation if tool is deleted';
COMMENT ON COLUMN ai_agent_audit_events.decision IS 'Authorization decision: allowed, denied, approved, rejected, require_approval';
COMMENT ON COLUMN ai_agent_audit_events.policy_id IS 'Reference to the authorization policy that matched (if any)';
COMMENT ON COLUMN ai_agent_audit_events.duration_ms IS 'Operation duration in milliseconds for performance monitoring';
