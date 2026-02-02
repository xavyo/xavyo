-- Migration: Create user_import_errors table with Row-Level Security
-- Feature: F086 - Bulk User Import & Invitation Flows
-- Description: Records per-row errors from CSV import jobs

CREATE TABLE IF NOT EXISTS user_import_errors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES user_import_jobs(id) ON DELETE CASCADE,
    line_number INTEGER NOT NULL,
    email VARCHAR(255),
    column_name VARCHAR(100),
    error_type VARCHAR(50) NOT NULL,
    error_message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Error type must be a known value
    CONSTRAINT user_import_errors_type_check CHECK (
        error_type IN ('validation', 'duplicate_in_file', 'duplicate_in_tenant', 'role_not_found', 'group_error', 'attribute_error', 'system')
    )
);

-- Index for job_id lookups (list errors for a specific job)
CREATE INDEX IF NOT EXISTS idx_user_import_errors_job_id
    ON user_import_errors(job_id);

-- Index for tenant + job queries
CREATE INDEX IF NOT EXISTS idx_user_import_errors_tenant_job
    ON user_import_errors(tenant_id, job_id);

-- Enable Row-Level Security on the table
ALTER TABLE user_import_errors ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE user_import_errors FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
CREATE POLICY tenant_isolation_policy ON user_import_errors
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE user_import_errors IS 'Per-row error records from CSV bulk user import jobs';
COMMENT ON COLUMN user_import_errors.line_number IS 'CSV line number (1-based, header = line 1)';
COMMENT ON COLUMN user_import_errors.error_type IS 'Error category: validation, duplicate_in_file, duplicate_in_tenant, role_not_found, group_error, attribute_error, system';
