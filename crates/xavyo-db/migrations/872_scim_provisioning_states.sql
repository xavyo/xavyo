-- Migration: Create scim_provisioning_states table with Row-Level Security
-- Feature: F087 - SCIM 2.0 Outbound Provisioning Client
-- Description: Tracks provisioning status of each internal resource per SCIM target

CREATE TABLE IF NOT EXISTS scim_provisioning_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
    resource_type VARCHAR(10) NOT NULL,
    internal_resource_id UUID NOT NULL,
    external_resource_id VARCHAR(255),
    external_id VARCHAR(255),
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    last_synced_at TIMESTAMPTZ,
    last_error TEXT,
    retry_count INT NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Resource type must be User or Group (SCIM RFC uses capitalized resource types)
    CONSTRAINT scim_prov_state_resource_type_check CHECK (
        resource_type IN ('User', 'Group')
    ),

    -- Status must be a known value
    CONSTRAINT scim_prov_state_status_check CHECK (
        status IN ('pending', 'synced', 'error', 'conflict', 'pending_update', 'pending_deprovision', 'deprovisioned')
    ),

    -- Unique state per target, resource type, and internal resource
    CONSTRAINT scim_prov_state_unique UNIQUE (target_id, resource_type, internal_resource_id)
);

-- Index for target_id lookups
CREATE INDEX IF NOT EXISTS idx_scim_prov_state_target
    ON scim_provisioning_states(target_id);

-- Index for finding provisioning state by internal resource
CREATE INDEX IF NOT EXISTS idx_scim_prov_state_resource
    ON scim_provisioning_states(tenant_id, resource_type, internal_resource_id);

-- Index for filtering by status per target
CREATE INDEX IF NOT EXISTS idx_scim_prov_state_status
    ON scim_provisioning_states(tenant_id, target_id, status);

-- Partial index for pending/error states (fast lookup for retry processing)
CREATE INDEX IF NOT EXISTS idx_scim_prov_state_pending
    ON scim_provisioning_states(tenant_id, target_id)
    WHERE status IN ('pending', 'pending_update', 'pending_deprovision', 'error');

-- Enable Row-Level Security on the table
ALTER TABLE scim_provisioning_states ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE scim_provisioning_states FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
DROP POLICY IF EXISTS tenant_isolation_policy ON scim_provisioning_states;
CREATE POLICY tenant_isolation_policy ON scim_provisioning_states
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE scim_provisioning_states IS 'Tracks provisioning status of each user/group per SCIM target';
COMMENT ON COLUMN scim_provisioning_states.external_resource_id IS 'SCIM target-assigned resource ID (from response)';
COMMENT ON COLUMN scim_provisioning_states.external_id IS 'externalId sent to target (typically internal UUID)';
COMMENT ON COLUMN scim_provisioning_states.status IS 'Current state: pending, synced, error, conflict, pending_update, pending_deprovision, deprovisioned';
