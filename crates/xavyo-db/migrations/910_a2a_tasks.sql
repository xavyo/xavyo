-- Migration: 910_a2a_tasks.sql
-- Feature: F091 - MCP & A2A Protocol Integration
-- Description: Create A2A tasks table for Agent-to-Agent asynchronous task management

CREATE TABLE a2a_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    source_agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    target_agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    task_type VARCHAR(100) NOT NULL,
    input JSONB NOT NULL,
    state VARCHAR(20) NOT NULL DEFAULT 'pending',
    result JSONB,
    error_code VARCHAR(50),
    error_message TEXT,
    callback_url VARCHAR(500),
    callback_status VARCHAR(20),
    callback_attempts INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT valid_state CHECK (state IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    CONSTRAINT valid_callback_status CHECK (callback_status IS NULL OR callback_status IN ('pending', 'delivered', 'failed'))
);

-- Indexes for efficient queries
CREATE INDEX idx_a2a_tasks_tenant_source ON a2a_tasks(tenant_id, source_agent_id, created_at DESC);
CREATE INDEX idx_a2a_tasks_tenant_target_state ON a2a_tasks(tenant_id, target_agent_id, state);
CREATE INDEX idx_a2a_tasks_tenant_state ON a2a_tasks(tenant_id, state);

-- Row-Level Security
ALTER TABLE a2a_tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY a2a_tasks_tenant_isolation ON a2a_tasks
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Trigger for updated_at
CREATE TRIGGER a2a_tasks_updated_at
    BEFORE UPDATE ON a2a_tasks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
