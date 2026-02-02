-- Migration: Create authorization codes table
-- Description: Temporary authorization codes for OAuth2 authorization code flow

CREATE TABLE IF NOT EXISTS authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash TEXT NOT NULL,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256',
    nonce TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Only S256 PKCE method supported
    CONSTRAINT code_challenge_method_s256 CHECK (code_challenge_method = 'S256')
);

-- Index for code_hash lookups (primary access pattern)
CREATE INDEX IF NOT EXISTS idx_authorization_codes_code_hash ON authorization_codes(code_hash);

-- Index for tenant_id lookups (critical for RLS performance)
CREATE INDEX IF NOT EXISTS idx_authorization_codes_tenant_id ON authorization_codes(tenant_id);

-- Index for expires_at (for cleanup job)
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);

-- Index for unused codes (most codes should be used quickly)
CREATE INDEX IF NOT EXISTS idx_authorization_codes_used ON authorization_codes(used) WHERE used = FALSE;

-- Enable Row-Level Security
ALTER TABLE authorization_codes ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner
ALTER TABLE authorization_codes FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
CREATE POLICY tenant_isolation_policy ON authorization_codes
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE authorization_codes IS 'Temporary OAuth2 authorization codes (single-use, 10 minute expiry)';
COMMENT ON COLUMN authorization_codes.id IS 'Internal unique identifier';
COMMENT ON COLUMN authorization_codes.code_hash IS 'SHA-256 hash of the authorization code';
COMMENT ON COLUMN authorization_codes.client_id IS 'Reference to the OAuth2 client';
COMMENT ON COLUMN authorization_codes.user_id IS 'Reference to the authorizing user';
COMMENT ON COLUMN authorization_codes.tenant_id IS 'Reference to the tenant';
COMMENT ON COLUMN authorization_codes.redirect_uri IS 'Redirect URI that must match token request';
COMMENT ON COLUMN authorization_codes.scope IS 'Granted OAuth2 scopes (space-separated)';
COMMENT ON COLUMN authorization_codes.code_challenge IS 'PKCE code challenge from authorization request';
COMMENT ON COLUMN authorization_codes.code_challenge_method IS 'PKCE method (only S256 supported)';
COMMENT ON COLUMN authorization_codes.nonce IS 'OIDC nonce for replay protection';
COMMENT ON COLUMN authorization_codes.expires_at IS 'Expiration timestamp (10 minutes after creation)';
COMMENT ON COLUMN authorization_codes.used IS 'Whether the code has been exchanged for tokens';
