-- Migration: Create OAuth2 clients table
-- Description: OAuth2 client applications registered for authorization

CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL UNIQUE,
    client_secret_hash TEXT,
    name VARCHAR(255) NOT NULL,
    client_type VARCHAR(20) NOT NULL CHECK (client_type IN ('confidential', 'public')),
    redirect_uris TEXT[] NOT NULL,
    grant_types TEXT[] NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{openid}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Validate that confidential clients have secrets and public clients don't
    CONSTRAINT client_secret_required CHECK (
        (client_type = 'confidential' AND client_secret_hash IS NOT NULL) OR
        (client_type = 'public' AND client_secret_hash IS NULL)
    )
);

-- Index for tenant_id lookups (critical for RLS performance)
CREATE INDEX IF NOT EXISTS idx_oauth_clients_tenant_id ON oauth_clients(tenant_id);

-- Index for is_active filtering
CREATE INDEX IF NOT EXISTS idx_oauth_clients_is_active ON oauth_clients(is_active) WHERE is_active = TRUE;

-- Enable Row-Level Security
ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner
ALTER TABLE oauth_clients FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
CREATE POLICY tenant_isolation_policy ON oauth_clients
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_oauth_clients_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_oauth_clients_updated_at();

COMMENT ON TABLE oauth_clients IS 'OAuth2 client applications registered for authorization';
COMMENT ON COLUMN oauth_clients.id IS 'Internal unique identifier';
COMMENT ON COLUMN oauth_clients.tenant_id IS 'Reference to the tenant this client belongs to';
COMMENT ON COLUMN oauth_clients.client_id IS 'Public client identifier used in OAuth2 flows';
COMMENT ON COLUMN oauth_clients.client_secret_hash IS 'Argon2id hashed client secret (NULL for public clients)';
COMMENT ON COLUMN oauth_clients.name IS 'Human-readable client name';
COMMENT ON COLUMN oauth_clients.client_type IS 'Client type: confidential (has secret) or public (no secret)';
COMMENT ON COLUMN oauth_clients.redirect_uris IS 'Allowed redirect URIs for authorization code flow';
COMMENT ON COLUMN oauth_clients.grant_types IS 'Allowed OAuth2 grant types';
COMMENT ON COLUMN oauth_clients.scopes IS 'Allowed OAuth2 scopes';
COMMENT ON COLUMN oauth_clients.is_active IS 'Whether the client is active (soft delete)';
