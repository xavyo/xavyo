-- Migration: 005_create_password_reset_tokens
-- Feature: F007 - Password Reset & Email Verification
-- Description: Create password_reset_tokens table for secure password reset flow

-- Create password_reset_tokens table
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,

    -- Ensure token_hash is unique across all tenants (tokens are globally unique)
    CONSTRAINT uq_password_reset_tokens_token_hash UNIQUE (token_hash)
);

-- Index for token lookup (primary query path)
CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);

-- Index for user's pending resets
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);

-- Index for tenant queries
CREATE INDEX idx_password_reset_tokens_tenant_id ON password_reset_tokens(tenant_id);

-- Partial index for cleanup job (only unused, expired tokens)
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at)
    WHERE used_at IS NULL;

-- Enable Row Level Security
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
-- Users can only see/modify tokens belonging to their tenant
CREATE POLICY tenant_isolation ON password_reset_tokens
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Comment on table
COMMENT ON TABLE password_reset_tokens IS 'Stores password reset tokens with single-use enforcement and 1-hour expiration';
COMMENT ON COLUMN password_reset_tokens.token_hash IS 'SHA-256 hash of the token (hex encoded) - never store raw token';
COMMENT ON COLUMN password_reset_tokens.used_at IS 'Timestamp when token was consumed - NULL means still valid';
COMMENT ON COLUMN password_reset_tokens.ip_address IS 'IP address of the requester for audit trail';
