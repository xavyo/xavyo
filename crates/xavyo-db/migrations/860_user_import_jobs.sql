-- Migration: Create user_import_jobs table with Row-Level Security
-- Feature: F086 - Bulk User Import & Invitation Flows
-- Description: Stores import job records for CSV bulk user imports

CREATE TABLE IF NOT EXISTS user_import_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    file_name VARCHAR(255) NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    total_rows INTEGER NOT NULL DEFAULT 0,
    processed_rows INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    skip_count INTEGER NOT NULL DEFAULT 0,
    send_invitations BOOLEAN NOT NULL DEFAULT false,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Status must be a known value
    CONSTRAINT user_import_jobs_status_check CHECK (
        status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')
    )
);

-- Index for tenant_id lookups (critical for RLS performance)
CREATE INDEX IF NOT EXISTS idx_user_import_jobs_tenant_id
    ON user_import_jobs(tenant_id);

-- Index for tenant + status queries (find active/pending imports)
CREATE INDEX IF NOT EXISTS idx_user_import_jobs_tenant_status
    ON user_import_jobs(tenant_id, status);

-- Index for tenant + created_at DESC (list jobs ordered by most recent)
CREATE INDEX IF NOT EXISTS idx_user_import_jobs_created_at
    ON user_import_jobs(tenant_id, created_at DESC);

-- Enforce at most one active (pending/processing) import per tenant.
-- This prevents concurrent import race conditions at the database level.
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_import_jobs_active_per_tenant
    ON user_import_jobs(tenant_id)
    WHERE status IN ('pending', 'processing');

-- Enable Row-Level Security on the table
ALTER TABLE user_import_jobs ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE user_import_jobs FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
CREATE POLICY tenant_isolation_policy ON user_import_jobs
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE user_import_jobs IS 'Stores CSV bulk user import job records with processing lifecycle tracking';
COMMENT ON COLUMN user_import_jobs.id IS 'Unique job identifier';
COMMENT ON COLUMN user_import_jobs.tenant_id IS 'Reference to the tenant this import belongs to';
COMMENT ON COLUMN user_import_jobs.status IS 'Job lifecycle state: pending, processing, completed, failed, cancelled';
COMMENT ON COLUMN user_import_jobs.file_hash IS 'SHA-256 hex hash of the uploaded CSV file';
COMMENT ON COLUMN user_import_jobs.send_invitations IS 'Whether to send email invitations to imported users';
COMMENT ON COLUMN user_import_jobs.created_by IS 'Admin user who initiated the import';
