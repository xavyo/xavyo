-- Migration: Create OAuth2 refresh tokens table
-- Description: Long-lived tokens for obtaining new access tokens with rotation support

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    family_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for token_hash lookups (primary access pattern)
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_token_hash ON oauth_refresh_tokens(token_hash);

-- Index for family_id (for rotation and family revocation)
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family_id ON oauth_refresh_tokens(family_id);

-- Index for user_id (for user token listing/management)
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_user_id ON oauth_refresh_tokens(user_id);

-- Index for tenant_id lookups (critical for RLS performance)
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_tenant_id ON oauth_refresh_tokens(tenant_id);

-- Index for expires_at (for cleanup job)
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expires_at ON oauth_refresh_tokens(expires_at);

-- Partial index for non-revoked tokens (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_active ON oauth_refresh_tokens(token_hash) WHERE revoked = FALSE;

-- Enable Row-Level Security
ALTER TABLE oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner
ALTER TABLE oauth_refresh_tokens FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
CREATE POLICY tenant_isolation_policy ON oauth_refresh_tokens
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE oauth_refresh_tokens IS 'OAuth2 refresh tokens with rotation support (7 day expiry)';
COMMENT ON COLUMN oauth_refresh_tokens.id IS 'Internal unique identifier';
COMMENT ON COLUMN oauth_refresh_tokens.token_hash IS 'SHA-256 hash of the refresh token';
COMMENT ON COLUMN oauth_refresh_tokens.client_id IS 'Reference to the OAuth2 client';
COMMENT ON COLUMN oauth_refresh_tokens.user_id IS 'Reference to the token owner';
COMMENT ON COLUMN oauth_refresh_tokens.tenant_id IS 'Reference to the tenant';
COMMENT ON COLUMN oauth_refresh_tokens.scope IS 'Granted OAuth2 scopes (space-separated)';
COMMENT ON COLUMN oauth_refresh_tokens.family_id IS 'Token family ID for rotation tracking (replay detection)';
COMMENT ON COLUMN oauth_refresh_tokens.expires_at IS 'Expiration timestamp (7 days after creation)';
COMMENT ON COLUMN oauth_refresh_tokens.revoked IS 'Whether the token has been revoked';
COMMENT ON COLUMN oauth_refresh_tokens.revoked_at IS 'Timestamp when the token was revoked';
