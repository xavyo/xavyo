-- Migration: 088_002_gov_role_effective_entitlements
-- Feature: F088 - Business Role Hierarchy Model
-- Description: Create effective entitlement cache table for O(1) lookups

-- Create gov_role_effective_entitlements table
CREATE TABLE IF NOT EXISTS gov_role_effective_entitlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES gov_roles(id) ON DELETE CASCADE,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    source_role_id UUID NOT NULL REFERENCES gov_roles(id) ON DELETE CASCADE,
    is_inherited BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One entry per entitlement per role (deduplicated)
    CONSTRAINT gov_role_eff_ent_unique UNIQUE (role_id, entitlement_id)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_gov_role_eff_ent_role ON gov_role_effective_entitlements(role_id);
CREATE INDEX IF NOT EXISTS idx_gov_role_eff_ent_tenant ON gov_role_effective_entitlements(tenant_id, role_id);
CREATE INDEX IF NOT EXISTS idx_gov_role_eff_ent_source ON gov_role_effective_entitlements(source_role_id);
CREATE INDEX IF NOT EXISTS idx_gov_role_eff_ent_entitlement ON gov_role_effective_entitlements(entitlement_id);

-- Enable RLS
ALTER TABLE gov_role_effective_entitlements ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS gov_role_eff_ent_tenant_isolation ON gov_role_effective_entitlements;
CREATE POLICY gov_role_eff_ent_tenant_isolation ON gov_role_effective_entitlements
    USING (
        tenant_id = COALESCE(
            NULLIF(current_setting('app.current_tenant', true), '')::uuid,
            tenant_id
        )
    );

-- Comments for documentation
COMMENT ON TABLE gov_role_effective_entitlements IS 'Cached/denormalized effective entitlements for each role (direct + inherited) (F088)';
COMMENT ON COLUMN gov_role_effective_entitlements.source_role_id IS 'The role that originally grants this entitlement (for tracing inheritance)';
COMMENT ON COLUMN gov_role_effective_entitlements.is_inherited IS 'True if inherited from an ancestor role, false if directly assigned to this role';
