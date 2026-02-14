-- Migration: 027_tenant_policies.sql
-- Feature: F026 - Device Management (fix for device policy storage)
-- Description: Create tenant_policies table for JSONB-based policy storage

-- ============================================================================
-- Part 1: Create tenant_policies table
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    policies JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Part 2: Enable RLS
-- ============================================================================

ALTER TABLE tenant_policies ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS tenant_isolation_tenant_policies ON tenant_policies;
CREATE POLICY tenant_isolation_tenant_policies ON tenant_policies
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- Part 3: Trigger for updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION update_tenant_policies_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_tenant_policies_updated_at ON tenant_policies;
CREATE TRIGGER trigger_tenant_policies_updated_at
    BEFORE UPDATE ON tenant_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_tenant_policies_updated_at();

-- ============================================================================
-- Part 4: Index for policy lookups
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_tenant_policies_device ON tenant_policies
    USING gin ((policies -> 'device_policy'));

-- ============================================================================
-- Part 5: Comments
-- ============================================================================

COMMENT ON TABLE tenant_policies IS 'JSONB-based storage for tenant-specific policies (device, etc.)';
COMMENT ON COLUMN tenant_policies.policies IS 'JSONB object containing policy configurations by key';
