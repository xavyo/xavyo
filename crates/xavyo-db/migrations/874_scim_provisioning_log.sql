-- Migration: Create scim_provisioning_log table with Row-Level Security
-- Feature: F087 - SCIM 2.0 Outbound Provisioning Client
-- Description: Immutable audit log of individual SCIM provisioning operations

CREATE TABLE IF NOT EXISTS scim_provisioning_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
    sync_run_id UUID REFERENCES scim_sync_runs(id) ON DELETE SET NULL,
    operation_type VARCHAR(20) NOT NULL,
    resource_type VARCHAR(10) NOT NULL,
    internal_resource_id UUID NOT NULL,
    external_resource_id VARCHAR(255),
    http_method VARCHAR(10) NOT NULL,
    http_status INT,
    request_summary TEXT,
    response_summary TEXT,
    retry_count INT NOT NULL DEFAULT 0,
    duration_ms INT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Operation type must be a known value
    CONSTRAINT scim_prov_log_op_type_check CHECK (
        operation_type IN ('create', 'update', 'deprovision', 'delete', 'lookup', 'create_conflict_resolved', 'add_members', 'remove_members')
    ),

    -- Resource type must be User or Group (SCIM RFC uses capitalized resource types)
    CONSTRAINT scim_prov_log_resource_type_check CHECK (
        resource_type IN ('User', 'Group')
    )
);

-- Index for target + created_at queries (list logs for a target, most recent first)
CREATE INDEX IF NOT EXISTS idx_scim_prov_log_target
    ON scim_provisioning_log(target_id, created_at DESC);

-- Index for resource-level log queries
CREATE INDEX IF NOT EXISTS idx_scim_prov_log_resource
    ON scim_provisioning_log(tenant_id, internal_resource_id, created_at DESC);

-- Index for sync run log queries (partial: only when sync_run_id is set)
CREATE INDEX IF NOT EXISTS idx_scim_prov_log_sync_run
    ON scim_provisioning_log(sync_run_id)
    WHERE sync_run_id IS NOT NULL;

-- Index for retention cleanup (delete old logs by tenant)
CREATE INDEX IF NOT EXISTS idx_scim_prov_log_retention
    ON scim_provisioning_log(tenant_id, created_at);

-- Enable Row-Level Security on the table
ALTER TABLE scim_provisioning_log ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE scim_provisioning_log FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
DROP POLICY IF EXISTS tenant_isolation_policy ON scim_provisioning_log;
CREATE POLICY tenant_isolation_policy ON scim_provisioning_log
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE scim_provisioning_log IS 'Immutable audit log of SCIM provisioning operations (90-day retention)';
COMMENT ON COLUMN scim_provisioning_log.request_summary IS 'Abbreviated request body (max 4KB)';
COMMENT ON COLUMN scim_provisioning_log.response_summary IS 'Abbreviated response body (max 4KB)';
COMMENT ON COLUMN scim_provisioning_log.sync_run_id IS 'Parent sync run (NULL for incremental/event-driven operations)';
