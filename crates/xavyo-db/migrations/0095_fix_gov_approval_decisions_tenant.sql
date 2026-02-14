-- Fix gov_approval_decisions table: Add tenant_id column and RLS policies
-- This addresses a critical multi-tenancy vulnerability where approval decisions
-- could be accessed across tenants.

-- ============================================================================
-- Add tenant_id column
-- ============================================================================

ALTER TABLE gov_approval_decisions
ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Populate tenant_id from the related request
UPDATE gov_approval_decisions d
SET tenant_id = r.tenant_id
FROM gov_access_requests r
WHERE d.request_id = r.id
  AND d.tenant_id IS NULL;

-- Make tenant_id NOT NULL after populating
ALTER TABLE gov_approval_decisions
ALTER COLUMN tenant_id SET NOT NULL;

-- Add foreign key constraint
ALTER TABLE gov_approval_decisions
ADD CONSTRAINT gov_approval_decisions_tenant_fk
FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- Add indexes for tenant-scoped queries
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_gov_approval_decisions_tenant
ON gov_approval_decisions(tenant_id);

CREATE INDEX IF NOT EXISTS idx_gov_approval_decisions_tenant_request
ON gov_approval_decisions(tenant_id, request_id);

CREATE INDEX IF NOT EXISTS idx_gov_approval_decisions_tenant_approver
ON gov_approval_decisions(tenant_id, approver_id, decided_at);

-- ============================================================================
-- Enable RLS and create policies
-- ============================================================================

ALTER TABLE gov_approval_decisions ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_approval_decisions_tenant_isolation_select ON gov_approval_decisions
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_approval_decisions_tenant_isolation_insert ON gov_approval_decisions
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_approval_decisions_tenant_isolation_update ON gov_approval_decisions
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_approval_decisions_tenant_isolation_delete ON gov_approval_decisions
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
