-- Policy versioning for history tracking and rollback
-- F-003: xavyo-authorization Policy Admin Integration

CREATE TABLE IF NOT EXISTS policy_versions (
    id UUID PRIMARY KEY,
    policy_id UUID NOT NULL REFERENCES authorization_policies(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    version INT NOT NULL,
    policy_snapshot JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,
    change_summary TEXT,

    CONSTRAINT policy_versions_unique_version UNIQUE (tenant_id, policy_id, version)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_policy_versions_tenant_policy ON policy_versions(tenant_id, policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_versions_created_at ON policy_versions(tenant_id, policy_id, created_at);

-- Enable RLS
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
CREATE POLICY policy_versions_tenant_isolation ON policy_versions
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE policy_versions IS 'Stores historical snapshots of authorization policies for versioning and rollback';
COMMENT ON COLUMN policy_versions.version IS 'Sequential version number per policy (1, 2, 3...)';
COMMENT ON COLUMN policy_versions.policy_snapshot IS 'Complete JSON representation of the policy at this version';
