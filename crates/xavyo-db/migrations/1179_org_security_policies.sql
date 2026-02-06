-- Migration: F-066 Organization-Level Security Policies
-- Creates table for organization-specific security policy configurations
-- with support for inheritance through the group hierarchy.

-- Policy type enum (stored as varchar for flexibility)
-- Valid values: password, mfa, session, ip_restriction

-- Create the org_security_policies table
CREATE TABLE IF NOT EXISTS org_security_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    policy_type VARCHAR(20) NOT NULL,
    config JSONB NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Only one policy per org and type
    CONSTRAINT uq_org_security_policy UNIQUE (tenant_id, group_id, policy_type),

    -- Validate policy type
    CONSTRAINT chk_policy_type CHECK (policy_type IN ('password', 'mfa', 'session', 'ip_restriction'))
);

-- Add comment for documentation
COMMENT ON TABLE org_security_policies IS 'Organization-specific security policies with inheritance support (F-066)';
COMMENT ON COLUMN org_security_policies.policy_type IS 'Type of security policy: password, mfa, session, ip_restriction';
COMMENT ON COLUMN org_security_policies.config IS 'JSONB configuration specific to the policy type';
COMMENT ON COLUMN org_security_policies.is_active IS 'Whether this policy is currently active';

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_org_security_policies_tenant_group
ON org_security_policies(tenant_id, group_id);

CREATE INDEX IF NOT EXISTS idx_org_security_policies_tenant_type
ON org_security_policies(tenant_id, policy_type)
WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_org_security_policies_group
ON org_security_policies(group_id);

-- Trigger to auto-update updated_at
CREATE OR REPLACE FUNCTION update_org_security_policy_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_org_security_policy_timestamp ON org_security_policies;
CREATE TRIGGER trg_update_org_security_policy_timestamp
    BEFORE UPDATE ON org_security_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_org_security_policy_timestamp();

-- Enable Row Level Security
ALTER TABLE org_security_policies ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS org_security_policies_tenant_isolation ON org_security_policies;
CREATE POLICY org_security_policies_tenant_isolation
ON org_security_policies
FOR ALL
USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON org_security_policies TO authenticated;
