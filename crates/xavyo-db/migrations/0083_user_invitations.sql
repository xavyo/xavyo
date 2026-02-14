-- Migration: Create user_invitations table with Row-Level Security
-- Feature: F086 - Bulk User Import & Invitation Flows
-- Description: Tracks invitation tokens sent to imported users for password setup

CREATE TABLE IF NOT EXISTS user_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    job_id UUID REFERENCES user_import_jobs(id) ON DELETE SET NULL,
    token_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    sent_at TIMESTAMPTZ,
    accepted_at TIMESTAMPTZ,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Status must be a known value
    CONSTRAINT user_invitations_status_check CHECK (
        status IN ('pending', 'sent', 'accepted', 'expired')
    )
);

-- Unique index for token_hash lookups (token validation on acceptance).
-- Uniqueness prevents (astronomically unlikely) hash collisions from
-- causing cross-tenant data access.
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_invitations_token_hash
    ON user_invitations(token_hash);

-- Index for tenant + user queries (find invitations for a user)
CREATE INDEX IF NOT EXISTS idx_user_invitations_tenant_user
    ON user_invitations(tenant_id, user_id);

-- Index for job_id lookups (list invitations for an import job)
CREATE INDEX IF NOT EXISTS idx_user_invitations_job_id
    ON user_invitations(job_id);

-- Partial index for active invitations (pending/sent) by tenant
CREATE INDEX IF NOT EXISTS idx_user_invitations_tenant_status_active
    ON user_invitations(tenant_id, status)
    WHERE status IN ('pending', 'sent');

-- Enable Row-Level Security on the table
ALTER TABLE user_invitations ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE user_invitations FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
CREATE POLICY tenant_isolation_policy ON user_invitations
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE user_invitations IS 'Invitation tokens for imported users to set their password and activate their account';
COMMENT ON COLUMN user_invitations.token_hash IS 'SHA-256 hex hash of the invitation token (raw token sent via email)';
COMMENT ON COLUMN user_invitations.status IS 'Invitation lifecycle state: pending, sent, accepted, expired';
COMMENT ON COLUMN user_invitations.expires_at IS 'Token expiry timestamp (default: 7 days from creation)';
COMMENT ON COLUMN user_invitations.ip_address IS 'IP address of the acceptance request (audit trail)';
