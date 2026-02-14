-- Policy obligations for on_permit/on_deny actions
-- F-003: xavyo-authorization Policy Admin Integration

-- Obligation trigger enum
DO $$ BEGIN
    CREATE TYPE obligation_trigger AS ENUM ('on_permit', 'on_deny');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS policy_obligations (
    id UUID PRIMARY KEY,
    policy_id UUID NOT NULL REFERENCES authorization_policies(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    trigger obligation_trigger NOT NULL,
    obligation_type VARCHAR(100) NOT NULL,
    parameters JSONB,
    execution_order INT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT policy_obligations_positive_order CHECK (execution_order >= 0)
);

-- Indexes for obligation lookup during evaluation
CREATE INDEX IF NOT EXISTS idx_policy_obligations_lookup ON policy_obligations(tenant_id, policy_id, trigger) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_policy_obligations_type ON policy_obligations(obligation_type);

-- Enable RLS
ALTER TABLE policy_obligations ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
CREATE POLICY policy_obligations_tenant_isolation ON policy_obligations
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE policy_obligations IS 'Actions to execute on permit or deny authorization decisions';
COMMENT ON COLUMN policy_obligations.trigger IS 'When to execute: on_permit or on_deny';
COMMENT ON COLUMN policy_obligations.obligation_type IS 'Handler identifier (e.g., log_access, notify_owner)';
COMMENT ON COLUMN policy_obligations.execution_order IS 'Order for multiple obligations (lower = first)';
