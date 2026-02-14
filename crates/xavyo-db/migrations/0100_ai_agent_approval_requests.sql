-- Migration: 895_ai_agent_approval_requests
-- Feature: F092 - Human-in-the-Loop Approval System
-- Description: Create table for AI agent approval requests requiring human oversight

-- Create approval requests table
CREATE TABLE IF NOT EXISTS ai_agent_approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    tool_id UUID NOT NULL REFERENCES ai_tools(id) ON DELETE CASCADE,

    -- Request context
    parameters JSONB NOT NULL DEFAULT '{}',
    context JSONB NOT NULL DEFAULT '{}',
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    user_instruction TEXT,
    session_id VARCHAR(255),
    conversation_id VARCHAR(255),

    -- Status and lifecycle
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    -- Decision details
    decided_by UUID REFERENCES users(id),
    decided_at TIMESTAMPTZ,
    decision_reason TEXT,
    conditions JSONB,

    -- Notification tracking
    notification_sent BOOLEAN NOT NULL DEFAULT false,
    notification_url VARCHAR(500),

    -- Constraints
    CONSTRAINT valid_expiration CHECK (expires_at > requested_at),
    CONSTRAINT decision_requires_decider CHECK (
        (status IN ('pending', 'expired')) OR
        (status IN ('approved', 'denied') AND decided_by IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CONSTRAINT denial_requires_reason CHECK (
        status != 'denied' OR decision_reason IS NOT NULL
    )
);

-- Create indexes for efficient queries
CREATE INDEX idx_approval_requests_tenant_status
    ON ai_agent_approval_requests(tenant_id, status);

CREATE INDEX idx_approval_requests_agent
    ON ai_agent_approval_requests(tenant_id, agent_id);

CREATE INDEX idx_approval_requests_expires
    ON ai_agent_approval_requests(expires_at)
    WHERE status = 'pending';

CREATE INDEX idx_approval_requests_requested
    ON ai_agent_approval_requests(tenant_id, requested_at DESC);

-- Enable Row-Level Security
ALTER TABLE ai_agent_approval_requests ENABLE ROW LEVEL SECURITY;

-- Tenant isolation policies
CREATE POLICY approval_requests_select ON ai_agent_approval_requests
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY approval_requests_insert ON ai_agent_approval_requests
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY approval_requests_update ON ai_agent_approval_requests
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- No DELETE policy - approval requests are immutable for audit purposes
-- Expired/decided requests remain in the database for compliance

-- Add comments for documentation
COMMENT ON TABLE ai_agent_approval_requests IS 'Human-in-the-loop approval requests for AI agent tool invocations (F092)';
COMMENT ON COLUMN ai_agent_approval_requests.parameters IS 'Tool invocation parameters captured at request time';
COMMENT ON COLUMN ai_agent_approval_requests.context IS 'Conversation and session context for approver review';
COMMENT ON COLUMN ai_agent_approval_requests.risk_score IS 'Calculated risk score (0-100) from authorization service';
COMMENT ON COLUMN ai_agent_approval_requests.status IS 'Approval status: pending, approved, denied, expired';
COMMENT ON COLUMN ai_agent_approval_requests.conditions IS 'Optional conditions attached to approval (e.g., session_only: true)';
