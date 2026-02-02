-- Migration: 023_self_service_profile.sql
-- Feature: F027 - Self-Service Profile
-- Description: Add avatar_url to users and create email_change_requests table

-- ============================================================================
-- Part 1: Add avatar_url column to users table
-- ============================================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(2048);

COMMENT ON COLUMN users.avatar_url IS 'URL to user avatar image (max 2048 chars)';

-- ============================================================================
-- Part 2: Create email_change_requests table
-- ============================================================================

CREATE TABLE email_change_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    new_email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ NULL,
    cancelled_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure token_hash is unique across all tenants
    CONSTRAINT uq_email_change_requests_token_hash UNIQUE (token_hash)
);

-- ============================================================================
-- Part 3: Create indexes for email_change_requests
-- ============================================================================

-- Index for finding pending requests for a user
CREATE INDEX idx_email_change_requests_user_id
    ON email_change_requests(tenant_id, user_id);

-- Index for token lookup during verification
CREATE INDEX idx_email_change_requests_token_hash
    ON email_change_requests(token_hash);

-- Index for checking email availability within tenant
CREATE INDEX idx_email_change_requests_new_email
    ON email_change_requests(tenant_id, new_email);

-- Partial index for pending (active) requests only
CREATE INDEX idx_email_change_requests_pending
    ON email_change_requests(tenant_id, user_id)
    WHERE verified_at IS NULL AND cancelled_at IS NULL;

-- ============================================================================
-- Part 4: Enable Row Level Security
-- ============================================================================

ALTER TABLE email_change_requests ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Users can only see/modify their own email change requests within their tenant
CREATE POLICY tenant_isolation ON email_change_requests
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- Part 5: Comments for documentation
-- ============================================================================

COMMENT ON TABLE email_change_requests IS 'Pending email change requests with verification tokens (24h expiration)';
COMMENT ON COLUMN email_change_requests.new_email IS 'The new email address being requested';
COMMENT ON COLUMN email_change_requests.token_hash IS 'SHA-256 hash of verification token (hex encoded)';
COMMENT ON COLUMN email_change_requests.expires_at IS 'Token expiration timestamp (24 hours from creation)';
COMMENT ON COLUMN email_change_requests.verified_at IS 'When verification completed (NULL if pending)';
COMMENT ON COLUMN email_change_requests.cancelled_at IS 'When request was cancelled (NULL if active)';
