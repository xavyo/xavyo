-- A6: Admin audit events for user CRUD operations.
--
-- Provides a durable, immutable audit trail for admin actions on user accounts.
-- Complements the webhook event publisher (outbound) with an internal record.

CREATE TABLE IF NOT EXISTS admin_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id UUID NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for audit log queries
CREATE INDEX IF NOT EXISTS idx_admin_audit_tenant_time
    ON admin_audit_events (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_actor
    ON admin_audit_events (tenant_id, actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_resource
    ON admin_audit_events (tenant_id, resource_type, resource_id, created_at DESC);

-- Enable RLS with NULLIF pattern for tenant isolation
ALTER TABLE admin_audit_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY admin_audit_events_tenant_isolation ON admin_audit_events
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

CREATE POLICY admin_audit_events_insert ON admin_audit_events
    FOR INSERT
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
