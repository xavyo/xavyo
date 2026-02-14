-- Migration: 992_dynamic_secrets.sql
-- Feature: 120-dynamic-secrets-provisioning (SecretlessAI)
-- Date: 2026-02-01
-- Description: Dynamic secrets provisioning for AI agents with ephemeral credentials

-- 1. Secret Type Configuration
CREATE TABLE secret_type_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    type_name VARCHAR(100) NOT NULL,
    description TEXT,
    default_ttl_seconds INTEGER NOT NULL DEFAULT 300,
    max_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    provider_type VARCHAR(20) NOT NULL CHECK (provider_type IN ('openbao', 'infisical', 'internal', 'aws')),
    provider_path VARCHAR(255),
    rate_limit_per_hour INTEGER NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, type_name)
);

ALTER TABLE secret_type_configurations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secret_type_configurations
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

CREATE INDEX idx_secret_type_configurations_tenant ON secret_type_configurations(tenant_id);
CREATE INDEX idx_secret_type_configurations_type ON secret_type_configurations(tenant_id, type_name);

-- 2. Agent Secret Permissions
CREATE TABLE agent_secret_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    secret_type VARCHAR(100) NOT NULL,
    max_ttl_seconds INTEGER,
    max_requests_per_hour INTEGER,
    expires_at TIMESTAMPTZ,
    granted_by UUID NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, agent_id, secret_type)
);

CREATE INDEX idx_agent_secret_permissions_agent ON agent_secret_permissions(tenant_id, agent_id);
CREATE INDEX idx_agent_secret_permissions_type ON agent_secret_permissions(tenant_id, secret_type);

ALTER TABLE agent_secret_permissions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_secret_permissions
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 3. Dynamic Credentials
CREATE TABLE dynamic_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    secret_type VARCHAR(100) NOT NULL,
    credential_value TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
    provider_type VARCHAR(20) NOT NULL CHECK (provider_type IN ('openbao', 'infisical', 'internal', 'aws')),
    provider_lease_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dynamic_credentials_tenant_agent ON dynamic_credentials(tenant_id, agent_id);
CREATE INDEX idx_dynamic_credentials_expires_at ON dynamic_credentials(expires_at) WHERE status = 'active';
CREATE INDEX idx_dynamic_credentials_lease_id ON dynamic_credentials(provider_lease_id) WHERE provider_lease_id IS NOT NULL;
CREATE INDEX idx_dynamic_credentials_status ON dynamic_credentials(tenant_id, status);

ALTER TABLE dynamic_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON dynamic_credentials
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 4. Credential Request Audit (append-only)
CREATE TABLE credential_request_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    secret_type VARCHAR(100) NOT NULL,
    outcome VARCHAR(20) NOT NULL CHECK (outcome IN ('success', 'denied', 'rate_limited', 'error')),
    ttl_granted INTEGER,
    error_code VARCHAR(50),
    source_ip INET,
    user_agent TEXT,
    latency_ms REAL NOT NULL,
    context JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credential_request_audit_tenant_created ON credential_request_audit(tenant_id, created_at DESC);
CREATE INDEX idx_credential_request_audit_agent ON credential_request_audit(tenant_id, agent_id, created_at DESC);
CREATE INDEX idx_credential_request_audit_outcome ON credential_request_audit(tenant_id, outcome, created_at DESC);

ALTER TABLE credential_request_audit ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON credential_request_audit
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Prevent updates and deletes on audit table (append-only)
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'credential_request_audit is append-only. Updates and deletes are not allowed.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER prevent_audit_update
    BEFORE UPDATE ON credential_request_audit
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER prevent_audit_delete
    BEFORE DELETE ON credential_request_audit
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- 5. Secret Provider Config
CREATE TABLE secret_provider_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    provider_type VARCHAR(20) NOT NULL CHECK (provider_type IN ('openbao', 'infisical', 'aws')),
    name VARCHAR(100) NOT NULL,
    connection_settings TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'error')),
    last_health_check TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_secret_provider_configs_tenant ON secret_provider_configs(tenant_id);
CREATE INDEX idx_secret_provider_configs_type ON secret_provider_configs(tenant_id, provider_type);

ALTER TABLE secret_provider_configs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secret_provider_configs
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
