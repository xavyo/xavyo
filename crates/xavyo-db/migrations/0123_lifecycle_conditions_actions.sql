-- Migration: 999_lifecycle_conditions_actions.sql
-- Feature: F-193 Lifecycle State Machine Extensions
-- Purpose: Add conditions to transitions, entry/exit actions to states, and action execution logging

-- Add conditions column to transitions (for transition condition evaluation)
ALTER TABLE gov_lifecycle_transitions
ADD COLUMN IF NOT EXISTS conditions JSONB DEFAULT '[]'::JSONB;

COMMENT ON COLUMN gov_lifecycle_transitions.conditions IS
'Array of condition objects that must be satisfied for transition. Format: [{"type": "termination_date_set", "config": {}}]';

-- Add entry/exit actions columns to states
ALTER TABLE gov_lifecycle_states
ADD COLUMN IF NOT EXISTS entry_actions JSONB DEFAULT '[]'::JSONB,
ADD COLUMN IF NOT EXISTS exit_actions JSONB DEFAULT '[]'::JSONB;

COMMENT ON COLUMN gov_lifecycle_states.entry_actions IS
'Array of action objects to execute when entering this state. Format: [{"type": "disable_access", "config": {}}]';

COMMENT ON COLUMN gov_lifecycle_states.exit_actions IS
'Array of action objects to execute when leaving this state';

-- Create action execution log table for tracking entry/exit action results
CREATE TABLE IF NOT EXISTS gov_lifecycle_action_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    transition_audit_id UUID NOT NULL,
    state_id UUID NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    action_config JSONB NOT NULL DEFAULT '{}'::JSONB,
    trigger_type VARCHAR(20) NOT NULL DEFAULT 'entry', -- 'entry' or 'exit'
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'success', 'failed', 'skipped'
    executed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for action execution log
CREATE INDEX IF NOT EXISTS idx_lifecycle_action_executions_tenant
ON gov_lifecycle_action_executions(tenant_id);

CREATE INDEX IF NOT EXISTS idx_lifecycle_action_executions_audit
ON gov_lifecycle_action_executions(transition_audit_id);

CREATE INDEX IF NOT EXISTS idx_lifecycle_action_executions_status
ON gov_lifecycle_action_executions(status) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_lifecycle_action_executions_state
ON gov_lifecycle_action_executions(state_id);

-- RLS Policy for action execution log
ALTER TABLE gov_lifecycle_action_executions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS lifecycle_action_executions_tenant_isolation ON gov_lifecycle_action_executions;
CREATE POLICY lifecycle_action_executions_tenant_isolation
ON gov_lifecycle_action_executions
FOR ALL
USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Add index on conditions column for JSON queries if frequently used
CREATE INDEX IF NOT EXISTS idx_lifecycle_transitions_conditions
ON gov_lifecycle_transitions USING GIN (conditions);

-- Add index on entry/exit actions for JSON queries
CREATE INDEX IF NOT EXISTS idx_lifecycle_states_entry_actions
ON gov_lifecycle_states USING GIN (entry_actions);

CREATE INDEX IF NOT EXISTS idx_lifecycle_states_exit_actions
ON gov_lifecycle_states USING GIN (exit_actions);
