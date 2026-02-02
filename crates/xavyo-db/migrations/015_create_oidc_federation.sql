-- Migration: 015_create_oidc_federation.sql
-- OIDC Federation tables for external Identity Provider support

-- Create tenant_identity_providers table
CREATE TABLE IF NOT EXISTS tenant_identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    issuer_url VARCHAR(2048) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret_encrypted BYTEA NOT NULL,
    claim_mapping JSONB NOT NULL DEFAULT '{}',
    scopes VARCHAR(1024) NOT NULL DEFAULT 'openid profile email',
    sync_on_login BOOLEAN NOT NULL DEFAULT true,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    validation_status VARCHAR(50) NOT NULL DEFAULT 'pending',
    last_validated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, issuer_url)
);

-- Create identity_provider_domains table
CREATE TABLE IF NOT EXISTS identity_provider_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL REFERENCES tenant_identity_providers(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, identity_provider_id, domain),
    CHECK (domain ~* '^[a-z0-9][a-z0-9.-]*[a-z0-9]$')
);

-- Create user_identity_links table
CREATE TABLE IF NOT EXISTS user_identity_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL REFERENCES tenant_identity_providers(id) ON DELETE CASCADE,
    subject VARCHAR(1024) NOT NULL,
    issuer VARCHAR(2048) NOT NULL,
    raw_claims JSONB,
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, identity_provider_id, subject),
    UNIQUE (tenant_id, user_id, identity_provider_id)
);

-- Create federated_auth_sessions table (temporary auth flow state)
CREATE TABLE IF NOT EXISTS federated_auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    identity_provider_id UUID NOT NULL REFERENCES tenant_identity_providers(id) ON DELETE CASCADE,
    state VARCHAR(128) NOT NULL UNIQUE,
    nonce VARCHAR(128) NOT NULL,
    pkce_verifier VARCHAR(128) NOT NULL,
    redirect_uri VARCHAR(2048) NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Indexes for tenant_identity_providers
CREATE INDEX IF NOT EXISTS idx_tenant_identity_providers_tenant_id
    ON tenant_identity_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_identity_providers_enabled
    ON tenant_identity_providers(tenant_id, is_enabled) WHERE is_enabled = true;

-- Indexes for identity_provider_domains
CREATE INDEX IF NOT EXISTS idx_identity_provider_domains_lookup
    ON identity_provider_domains(tenant_id, domain);
CREATE INDEX IF NOT EXISTS idx_identity_provider_domains_idp
    ON identity_provider_domains(identity_provider_id);

-- Indexes for user_identity_links
CREATE INDEX IF NOT EXISTS idx_user_identity_links_user
    ON user_identity_links(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_user_identity_links_subject
    ON user_identity_links(tenant_id, identity_provider_id, subject);

-- Indexes for federated_auth_sessions
CREATE INDEX IF NOT EXISTS idx_federated_auth_sessions_state
    ON federated_auth_sessions(state);
CREATE INDEX IF NOT EXISTS idx_federated_auth_sessions_expires
    ON federated_auth_sessions(expires_at);

-- Enable RLS
ALTER TABLE tenant_identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_provider_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_identity_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE federated_auth_sessions ENABLE ROW LEVEL SECURITY;

-- RLS Policies
DROP POLICY IF EXISTS tenant_identity_providers_tenant_isolation ON tenant_identity_providers;
CREATE POLICY tenant_identity_providers_tenant_isolation ON tenant_identity_providers
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS identity_provider_domains_tenant_isolation ON identity_provider_domains;
CREATE POLICY identity_provider_domains_tenant_isolation ON identity_provider_domains
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS user_identity_links_tenant_isolation ON user_identity_links;
CREATE POLICY user_identity_links_tenant_isolation ON user_identity_links
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS federated_auth_sessions_tenant_isolation ON federated_auth_sessions;
CREATE POLICY federated_auth_sessions_tenant_isolation ON federated_auth_sessions
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
