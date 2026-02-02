-- Migration: Create scim_targets table with Row-Level Security
-- Feature: F087 - SCIM 2.0 Outbound Provisioning Client
-- Description: Stores SCIM 2.0 target endpoint configurations for outbound provisioning

CREATE TABLE IF NOT EXISTS scim_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    base_url VARCHAR(2048) NOT NULL,
    auth_method VARCHAR(20) NOT NULL,
    credentials_encrypted BYTEA NOT NULL,
    credentials_key_version INT NOT NULL DEFAULT 1,
    deprovisioning_strategy VARCHAR(20) NOT NULL DEFAULT 'deactivate',
    tls_verify BOOLEAN NOT NULL DEFAULT true,
    rate_limit_per_minute INT NOT NULL DEFAULT 60,
    request_timeout_secs INT NOT NULL DEFAULT 30,
    max_retries INT NOT NULL DEFAULT 5,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    last_health_check_at TIMESTAMPTZ,
    last_health_check_error TEXT,
    service_provider_config JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Auth method must be a known value
    CONSTRAINT scim_targets_auth_method_check CHECK (
        auth_method IN ('bearer', 'oauth2')
    ),

    -- Deprovisioning strategy must be a known value
    CONSTRAINT scim_targets_deprov_strategy_check CHECK (
        deprovisioning_strategy IN ('delete', 'deactivate')
    ),

    -- Status must be a known value
    CONSTRAINT scim_targets_status_check CHECK (
        status IN ('active', 'disabled', 'unreachable')
    ),

    -- Unique name per tenant
    CONSTRAINT scim_targets_tenant_name_unique UNIQUE (tenant_id, name)
);

-- Index for tenant_id lookups (critical for RLS performance)
CREATE INDEX IF NOT EXISTS idx_scim_targets_tenant
    ON scim_targets(tenant_id);

-- Index for tenant + status queries (find active targets)
CREATE INDEX IF NOT EXISTS idx_scim_targets_tenant_status
    ON scim_targets(tenant_id, status);

-- Enable Row-Level Security on the table
ALTER TABLE scim_targets ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE scim_targets FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
DROP POLICY IF EXISTS tenant_isolation_policy ON scim_targets;
CREATE POLICY tenant_isolation_policy ON scim_targets
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE scim_targets IS 'SCIM 2.0 target endpoint configurations for outbound identity provisioning';
COMMENT ON COLUMN scim_targets.credentials_encrypted IS 'AES-256-GCM encrypted credentials JSON (bearer_token or OAuth2 client_id/secret/token_endpoint)';
COMMENT ON COLUMN scim_targets.credentials_key_version IS 'Encryption key version for rotation support';
COMMENT ON COLUMN scim_targets.deprovisioning_strategy IS 'How to deprovision users: delete (SCIM DELETE) or deactivate (PATCH active=false)';
COMMENT ON COLUMN scim_targets.service_provider_config IS 'Cached SCIM ServiceProviderConfig response from target';
