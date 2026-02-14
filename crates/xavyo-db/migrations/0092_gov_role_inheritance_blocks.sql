-- Migration: 088_003_gov_role_inheritance_blocks
-- Feature: F088 - Business Role Hierarchy Model
-- Description: Create inheritance blocks table for selective entitlement exclusion

-- Create gov_role_inheritance_blocks table
CREATE TABLE IF NOT EXISTS gov_role_inheritance_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES gov_roles(id) ON DELETE CASCADE,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One block per entitlement per role
    CONSTRAINT gov_role_inh_block_unique UNIQUE (role_id, entitlement_id)
);

-- Index for lookup when computing effective entitlements
CREATE INDEX IF NOT EXISTS idx_gov_role_inh_block_role ON gov_role_inheritance_blocks(role_id);
CREATE INDEX IF NOT EXISTS idx_gov_role_inh_block_tenant ON gov_role_inheritance_blocks(tenant_id, role_id);

-- Enable RLS
ALTER TABLE gov_role_inheritance_blocks ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS gov_role_inh_block_tenant_isolation ON gov_role_inheritance_blocks;
CREATE POLICY gov_role_inh_block_tenant_isolation ON gov_role_inheritance_blocks
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Comments for documentation
COMMENT ON TABLE gov_role_inheritance_blocks IS 'Explicit blocks preventing specific entitlements from being inherited by a role (F088)';
COMMENT ON COLUMN gov_role_inheritance_blocks.entitlement_id IS 'The entitlement that should NOT be inherited from ancestors';
COMMENT ON COLUMN gov_role_inheritance_blocks.created_by IS 'User who created this inheritance block';
