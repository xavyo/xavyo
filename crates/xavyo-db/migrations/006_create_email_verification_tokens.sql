-- Migration: 006_create_email_verification_tokens
-- Feature: F007 - Password Reset & Email Verification
-- Description: Create email_verification_tokens table for email verification flow

-- Create email_verification_tokens table
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address VARCHAR(45) NULL,

    -- Ensure token_hash is unique across all tenants (tokens are globally unique)
    CONSTRAINT uq_email_verification_tokens_token_hash UNIQUE (token_hash)
);

-- Index for token lookup (primary query path)
CREATE INDEX idx_email_verification_tokens_token_hash ON email_verification_tokens(token_hash);

-- Index for user's pending verifications
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);

-- Index for tenant queries
CREATE INDEX idx_email_verification_tokens_tenant_id ON email_verification_tokens(tenant_id);

-- Partial index for cleanup job (only unverified, expired tokens)
CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at)
    WHERE verified_at IS NULL;

-- Enable Row Level Security
ALTER TABLE email_verification_tokens ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
-- Users can only see/modify tokens belonging to their tenant
CREATE POLICY tenant_isolation ON email_verification_tokens
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Comment on table
COMMENT ON TABLE email_verification_tokens IS 'Stores email verification tokens with single-use enforcement and 24-hour expiration';
COMMENT ON COLUMN email_verification_tokens.token_hash IS 'SHA-256 hash of the token (hex encoded) - never store raw token';
COMMENT ON COLUMN email_verification_tokens.verified_at IS 'Timestamp when email was verified - NULL means still pending';
COMMENT ON COLUMN email_verification_tokens.ip_address IS 'IP address of the requester for audit trail';
