-- Migration: Tenant Provisioning API (F097)
-- Creates tables for API keys, MFA policies, and session policies

-- =============================================================================
-- API Keys table for tenant admin access
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    key_hash VARCHAR(64) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for api_keys
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

-- RLS for api_keys
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS api_keys_tenant_isolation ON api_keys;
CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- =============================================================================
-- MFA Policy table for tenant-level MFA configuration
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenant_mfa_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    required BOOLEAN NOT NULL DEFAULT false,
    methods_allowed TEXT[] NOT NULL DEFAULT ARRAY['totp', 'webauthn'],
    grace_period_days INTEGER NOT NULL DEFAULT 0,
    remember_device_days INTEGER NOT NULL DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- RLS for tenant_mfa_policies
ALTER TABLE tenant_mfa_policies ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_mfa_policies_isolation ON tenant_mfa_policies;
CREATE POLICY tenant_mfa_policies_isolation ON tenant_mfa_policies
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- =============================================================================
-- Note: tenant_session_policies table already exists (migration 019)
-- The existing TenantSessionPolicy model and table will be used
-- =============================================================================

-- =============================================================================
-- Add unique index on tenant slug if not exists
-- =============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
