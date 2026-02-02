-- Migration: Create refresh_tokens table with Row-Level Security
-- Description: Stores opaque refresh tokens for JWT session management

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent TEXT,
    ip_address INET
);

-- Index for token lookup by hash (primary lookup method)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- Index for listing tokens by user
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- Index for cleaning up expired tokens
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Index for tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_id ON refresh_tokens(tenant_id);

-- Enable Row-Level Security
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
CREATE POLICY tenant_isolation_policy ON refresh_tokens
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE refresh_tokens IS 'Opaque refresh tokens for JWT session management';
COMMENT ON COLUMN refresh_tokens.id IS 'Unique identifier for the refresh token record';
COMMENT ON COLUMN refresh_tokens.user_id IS 'Reference to the user who owns this token';
COMMENT ON COLUMN refresh_tokens.tenant_id IS 'Reference to the tenant for RLS enforcement';
COMMENT ON COLUMN refresh_tokens.token_hash IS 'SHA-256 hash of the opaque refresh token';
COMMENT ON COLUMN refresh_tokens.expires_at IS 'Token expiration timestamp (7 days from creation)';
COMMENT ON COLUMN refresh_tokens.revoked_at IS 'Revocation timestamp (NULL if token is still valid)';
COMMENT ON COLUMN refresh_tokens.created_at IS 'Token creation timestamp';
COMMENT ON COLUMN refresh_tokens.user_agent IS 'Client user agent string (optional, for auditing)';
COMMENT ON COLUMN refresh_tokens.ip_address IS 'Client IP address (optional, for auditing)';
