-- F-PLAN-MGMT: Plan management for tenants
-- Migration to track plan changes and scheduled downgrades

-- Plan change history table
CREATE TABLE IF NOT EXISTS tenant_plan_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    change_type VARCHAR(20) NOT NULL CHECK (change_type IN ('upgrade', 'downgrade')),
    old_plan VARCHAR(50) NOT NULL,
    new_plan VARCHAR(50) NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'cancelled')),
    admin_user_id UUID NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for finding pending changes that need to be applied
CREATE INDEX IF NOT EXISTS idx_tenant_plan_changes_pending
    ON tenant_plan_changes (effective_at, status)
    WHERE status = 'pending';

-- Index for tenant history lookups
CREATE INDEX IF NOT EXISTS idx_tenant_plan_changes_tenant
    ON tenant_plan_changes (tenant_id, created_at DESC);

-- Enable RLS
ALTER TABLE tenant_plan_changes ENABLE ROW LEVEL SECURITY;

-- RLS policy: Only allow access to rows for the current tenant or system tenant
-- Note: System tenant admins can see all plan changes for management purposes
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'tenant_plan_changes'
        AND policyname = 'tenant_plan_changes_isolation'
    ) THEN
        CREATE POLICY tenant_plan_changes_isolation ON tenant_plan_changes
            FOR ALL
            USING (
                tenant_id = COALESCE(
                    NULLIF(current_setting('app.current_tenant', true), '')::uuid,
                    '00000000-0000-0000-0000-000000000001'::uuid
                )
                OR current_setting('app.current_tenant', true) = '00000000-0000-0000-0000-000000000001'
            );
    END IF;
END $$;
