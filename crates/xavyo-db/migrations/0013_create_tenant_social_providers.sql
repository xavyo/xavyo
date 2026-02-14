-- Migration: 013_create_tenant_social_providers
-- Description: Create tenant_social_providers table for per-tenant provider configuration

CREATE TABLE tenant_social_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT FALSE,
    client_id VARCHAR(255) NOT NULL,
    client_secret_encrypted BYTEA NOT NULL,
    additional_config JSONB,
    scopes TEXT[],
    claims_mapping JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One config per provider per tenant
    CONSTRAINT uq_tenant_provider UNIQUE (tenant_id, provider)
);

-- Enable Row-Level Security
ALTER TABLE tenant_social_providers ENABLE ROW LEVEL SECURITY;

-- RLS Policy for tenant isolation
CREATE POLICY tenant_isolation ON tenant_social_providers
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Trigger for updated_at
CREATE TRIGGER set_updated_at_tenant_social_providers
    BEFORE UPDATE ON tenant_social_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
