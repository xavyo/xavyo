-- F121: Workload Identity Federation
-- Creates tables for cloud identity provider configurations, IAM role mappings, and audit logging

-- Identity Provider Configurations
-- Stores cloud identity provider settings per tenant (AWS, GCP, Azure, Kubernetes)
CREATE TABLE IF NOT EXISTS identity_provider_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_type VARCHAR(50) NOT NULL CHECK (provider_type IN ('aws', 'gcp', 'azure', 'kubernetes')),
    name VARCHAR(255) NOT NULL,
    configuration TEXT NOT NULL, -- Encrypted JSONB with provider-specific settings
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_health_check TIMESTAMPTZ,
    health_status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (health_status IN ('pending', 'healthy', 'unhealthy')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider_type, name)
);

-- Enable RLS on identity_provider_configs
ALTER TABLE identity_provider_configs ENABLE ROW LEVEL SECURITY;

-- RLS policy for identity_provider_configs
CREATE POLICY tenant_isolation_identity_provider_configs ON identity_provider_configs
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes for identity_provider_configs
CREATE INDEX idx_identity_provider_configs_tenant ON identity_provider_configs(tenant_id);
CREATE INDEX idx_identity_provider_configs_type ON identity_provider_configs(tenant_id, provider_type);
CREATE INDEX idx_identity_provider_configs_active ON identity_provider_configs(tenant_id, is_active) WHERE is_active = true;

-- IAM Role Mappings
-- Maps agent types to cloud IAM roles per provider
CREATE TABLE IF NOT EXISTS iam_role_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_config_id UUID NOT NULL REFERENCES identity_provider_configs(id) ON DELETE CASCADE,
    agent_type VARCHAR(255), -- NULL for default mapping
    role_identifier VARCHAR(500) NOT NULL, -- AWS ARN, GCP SA email, Azure app ID
    allowed_scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    max_ttl_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (max_ttl_seconds >= 900 AND max_ttl_seconds <= 43200),
    constraints JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enable RLS on iam_role_mappings
ALTER TABLE iam_role_mappings ENABLE ROW LEVEL SECURITY;

-- RLS policy for iam_role_mappings
CREATE POLICY tenant_isolation_iam_role_mappings ON iam_role_mappings
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Unique constraint with NULL-safe handling for agent_type
CREATE UNIQUE INDEX idx_iam_role_mappings_unique_type ON iam_role_mappings (tenant_id, provider_config_id, COALESCE(agent_type, ''));

-- Indexes for iam_role_mappings
CREATE INDEX idx_iam_role_mappings_tenant ON iam_role_mappings(tenant_id);
CREATE INDEX idx_iam_role_mappings_provider ON iam_role_mappings(provider_config_id);
CREATE INDEX idx_iam_role_mappings_agent_type ON iam_role_mappings(tenant_id, agent_type);

-- Identity Credential Requests
-- Tracks credential requests for audit and rate limiting
CREATE TABLE IF NOT EXISTS identity_credential_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    provider_config_id UUID NOT NULL REFERENCES identity_provider_configs(id) ON DELETE SET NULL,
    role_mapping_id UUID REFERENCES iam_role_mappings(id) ON DELETE SET NULL,
    requested_ttl_seconds INTEGER NOT NULL,
    granted_ttl_seconds INTEGER,
    outcome VARCHAR(50) NOT NULL CHECK (outcome IN ('success', 'denied', 'rate_limited', 'error')),
    error_code VARCHAR(100),
    error_message TEXT,
    duration_ms INTEGER NOT NULL,
    source_ip INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enable RLS on identity_credential_requests
ALTER TABLE identity_credential_requests ENABLE ROW LEVEL SECURITY;

-- RLS policy for identity_credential_requests
CREATE POLICY tenant_isolation_identity_credential_requests ON identity_credential_requests
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes for identity_credential_requests
CREATE INDEX idx_identity_credential_requests_tenant_time ON identity_credential_requests(tenant_id, created_at DESC);
CREATE INDEX idx_identity_credential_requests_agent ON identity_credential_requests(tenant_id, agent_id);
CREATE INDEX idx_identity_credential_requests_outcome ON identity_credential_requests(tenant_id, outcome);

-- Identity Audit Events
-- Immutable audit log for all IAM operations
CREATE TABLE IF NOT EXISTS identity_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    agent_id UUID,
    user_id UUID,
    provider_type VARCHAR(50),
    operation VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    outcome VARCHAR(50) NOT NULL CHECK (outcome IN ('success', 'failure')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enable RLS on identity_audit_events
ALTER TABLE identity_audit_events ENABLE ROW LEVEL SECURITY;

-- RLS policy for identity_audit_events
CREATE POLICY tenant_isolation_identity_audit_events ON identity_audit_events
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes for identity_audit_events
CREATE INDEX idx_identity_audit_events_tenant_time ON identity_audit_events(tenant_id, created_at DESC);
CREATE INDEX idx_identity_audit_events_agent ON identity_audit_events(tenant_id, agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX idx_identity_audit_events_type ON identity_audit_events(tenant_id, event_type);
CREATE INDEX idx_identity_audit_events_provider ON identity_audit_events(tenant_id, provider_type) WHERE provider_type IS NOT NULL;
CREATE INDEX idx_identity_audit_events_outcome ON identity_audit_events(tenant_id, outcome);

-- Trigger to update updated_at on identity_provider_configs
CREATE OR REPLACE FUNCTION update_identity_provider_configs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_identity_provider_configs_updated_at
    BEFORE UPDATE ON identity_provider_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_identity_provider_configs_updated_at();

-- Trigger to update updated_at on iam_role_mappings
CREATE OR REPLACE FUNCTION update_iam_role_mappings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_iam_role_mappings_updated_at
    BEFORE UPDATE ON iam_role_mappings
    FOR EACH ROW
    EXECUTE FUNCTION update_iam_role_mappings_updated_at();
