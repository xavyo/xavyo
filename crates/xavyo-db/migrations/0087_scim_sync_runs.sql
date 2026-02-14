-- Migration: Create scim_sync_runs table with Row-Level Security
-- Feature: F087 - SCIM 2.0 Outbound Provisioning Client
-- Description: Tracks full sync and reconciliation run executions

CREATE TABLE IF NOT EXISTS scim_sync_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
    run_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'running',
    triggered_by UUID,
    total_resources INT NOT NULL DEFAULT 0,
    processed_count INT NOT NULL DEFAULT 0,
    created_count INT NOT NULL DEFAULT 0,
    updated_count INT NOT NULL DEFAULT 0,
    skipped_count INT NOT NULL DEFAULT 0,
    failed_count INT NOT NULL DEFAULT 0,
    orphan_count INT NOT NULL DEFAULT 0,
    missing_count INT NOT NULL DEFAULT 0,
    drift_count INT NOT NULL DEFAULT 0,
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Run type must be a known value
    CONSTRAINT scim_sync_runs_type_check CHECK (
        run_type IN ('full_sync', 'reconciliation')
    ),

    -- Status must be a known value
    CONSTRAINT scim_sync_runs_status_check CHECK (
        status IN ('running', 'completed', 'failed', 'cancelled')
    )
);

-- Index for target + started_at queries (list runs, most recent first)
CREATE INDEX IF NOT EXISTS idx_scim_sync_runs_target
    ON scim_sync_runs(target_id, started_at DESC);

-- Partial unique index: prevent concurrent runs per target
CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_sync_runs_active
    ON scim_sync_runs(target_id)
    WHERE status = 'running';

-- Enable Row-Level Security on the table
ALTER TABLE scim_sync_runs ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE scim_sync_runs FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
DROP POLICY IF EXISTS tenant_isolation_policy ON scim_sync_runs;
CREATE POLICY tenant_isolation_policy ON scim_sync_runs
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE scim_sync_runs IS 'Tracks full sync and reconciliation executions per SCIM target';
COMMENT ON COLUMN scim_sync_runs.run_type IS 'Type: full_sync (push all resources) or reconciliation (compare and report)';
COMMENT ON COLUMN scim_sync_runs.triggered_by IS 'Admin user who triggered the run (NULL for system-triggered)';
COMMENT ON COLUMN scim_sync_runs.orphan_count IS 'Resources found in target but not in local (reconciliation only)';
COMMENT ON COLUMN scim_sync_runs.missing_count IS 'Resources in local but not found in target (reconciliation only)';
COMMENT ON COLUMN scim_sync_runs.drift_count IS 'Resources with attribute mismatches between local and target (reconciliation only)';
