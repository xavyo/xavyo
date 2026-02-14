-- F069: Security Hardening - Revoked Tokens (JTI Blacklist)
-- Stores revoked JWT access tokens for immediate invalidation before expiry.

CREATE TABLE IF NOT EXISTS revoked_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    jti TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    reason TEXT,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast JTI lookup for per-request revocation check
CREATE UNIQUE INDEX IF NOT EXISTS idx_revoked_tokens_jti ON revoked_tokens(jti);

-- Lookup all revoked tokens for a user (for revoke-all-user operation)
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user_id ON revoked_tokens(user_id);

-- RLS performance index
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_tenant_id ON revoked_tokens(tenant_id);

-- Cleanup query: find expired revocation records
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);

-- Row-Level Security for tenant isolation
ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON revoked_tokens;
CREATE POLICY tenant_isolation_policy ON revoked_tokens
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);
