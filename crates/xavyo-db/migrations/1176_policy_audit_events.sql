-- Policy audit events for compliance logging
-- F-003: xavyo-authorization Policy Admin Integration

CREATE TABLE IF NOT EXISTS policy_audit_events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    policy_id UUID,  -- NULL for list operations
    action VARCHAR(50) NOT NULL,  -- created, updated, deleted, enabled, disabled, rolled_back
    actor_id UUID NOT NULL,
    actor_ip INET,
    before_state JSONB,  -- State before the action
    after_state JSONB,   -- State after the action
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB,

    CONSTRAINT policy_audit_events_valid_action CHECK (
        action IN ('created', 'updated', 'deleted', 'enabled', 'disabled', 'rolled_back')
    )
);

-- Indexes for audit log queries
CREATE INDEX IF NOT EXISTS idx_policy_audit_events_tenant_time ON policy_audit_events(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_policy_audit_events_policy ON policy_audit_events(tenant_id, policy_id, timestamp DESC) WHERE policy_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policy_audit_events_actor ON policy_audit_events(tenant_id, actor_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_policy_audit_events_action ON policy_audit_events(tenant_id, action);

-- Enable RLS
ALTER TABLE policy_audit_events ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
CREATE POLICY policy_audit_events_tenant_isolation ON policy_audit_events
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE policy_audit_events IS 'Audit trail for all policy administration actions';
COMMENT ON COLUMN policy_audit_events.before_state IS 'Policy state before update/delete (NULL for create)';
COMMENT ON COLUMN policy_audit_events.after_state IS 'Policy state after create/update (NULL for delete)';
