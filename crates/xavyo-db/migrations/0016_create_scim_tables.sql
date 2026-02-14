-- SCIM 2.0 Provisioning Tables
-- Feature: 015-scim-provisioning
-- Created: 2026-01-23

-- Enable RLS
ALTER TABLE IF EXISTS scim_tokens DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS scim_attribute_mappings DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS scim_audit_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS groups DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS group_memberships DISABLE ROW LEVEL SECURITY;

-- Drop existing tables if recreating (for development)
DROP TABLE IF EXISTS group_memberships CASCADE;
DROP TABLE IF EXISTS groups CASCADE;
DROP TABLE IF EXISTS scim_audit_logs CASCADE;
DROP TABLE IF EXISTS scim_attribute_mappings CASCADE;
DROP TABLE IF EXISTS scim_tokens CASCADE;

-- ScimToken: Bearer tokens for SCIM API authentication
CREATE TABLE scim_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    token_prefix VARCHAR(16) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_by UUID NOT NULL REFERENCES users(id),

    CONSTRAINT scim_tokens_token_hash_unique UNIQUE (token_hash)
);

-- Indexes for ScimToken
CREATE INDEX idx_scim_tokens_tenant ON scim_tokens(tenant_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_scim_tokens_hash ON scim_tokens(token_hash) WHERE revoked_at IS NULL;

-- RLS for ScimToken
ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY scim_tokens_tenant_isolation ON scim_tokens
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ScimAttributeMapping: Custom attribute mapping configuration per tenant
CREATE TABLE scim_attribute_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scim_path VARCHAR(255) NOT NULL,
    xavyo_field VARCHAR(255) NOT NULL,
    transform VARCHAR(50),
    required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT scim_mappings_unique_path UNIQUE (tenant_id, scim_path),
    CONSTRAINT scim_mappings_valid_transform CHECK (
        transform IS NULL OR transform IN ('lowercase', 'uppercase', 'trim')
    )
);

-- Indexes for ScimAttributeMapping
CREATE INDEX idx_scim_mappings_tenant ON scim_attribute_mappings(tenant_id);

-- RLS for ScimAttributeMapping
ALTER TABLE scim_attribute_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY scim_mappings_tenant_isolation ON scim_attribute_mappings
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ScimAuditLog: Audit trail for all SCIM operations
CREATE TABLE scim_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_id UUID REFERENCES scim_tokens(id) ON DELETE SET NULL,
    operation VARCHAR(20) NOT NULL,
    resource_type VARCHAR(20) NOT NULL,
    resource_id UUID,
    source_ip TEXT NOT NULL,
    user_agent VARCHAR(500),
    request_body JSONB,
    response_code INTEGER NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT scim_audit_valid_operation CHECK (
        operation IN ('CREATE', 'READ', 'UPDATE', 'DELETE', 'LIST')
    ),
    CONSTRAINT scim_audit_valid_resource_type CHECK (
        resource_type IN ('User', 'Group')
    )
);

-- Indexes for ScimAuditLog
CREATE INDEX idx_scim_audit_tenant_time ON scim_audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_scim_audit_resource ON scim_audit_logs(tenant_id, resource_type, resource_id);

-- RLS for ScimAuditLog
ALTER TABLE scim_audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY scim_audit_tenant_isolation ON scim_audit_logs
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Group: User groups for role-based access control
CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name VARCHAR(255) NOT NULL,
    external_id VARCHAR(255),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT groups_unique_name UNIQUE (tenant_id, display_name)
);

-- Conditional unique index for external_id (only when not null)
CREATE UNIQUE INDEX idx_groups_external_unique
    ON groups(tenant_id, external_id)
    WHERE external_id IS NOT NULL;

-- Indexes for Group
CREATE INDEX idx_groups_tenant ON groups(tenant_id);
CREATE INDEX idx_groups_external ON groups(tenant_id, external_id) WHERE external_id IS NOT NULL;

-- RLS for Group
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY groups_tenant_isolation ON groups
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- GroupMembership: Many-to-many relationship between users and groups
CREATE TABLE group_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT group_memberships_unique UNIQUE (group_id, user_id)
);

-- Indexes for GroupMembership
CREATE INDEX idx_group_members_group ON group_memberships(group_id);
CREATE INDEX idx_group_members_user ON group_memberships(user_id);

-- RLS for GroupMembership
ALTER TABLE group_memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY group_memberships_tenant_isolation ON group_memberships
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Extend Users table with SCIM fields
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS external_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS first_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS last_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS scim_provisioned BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS scim_last_sync TIMESTAMPTZ;

-- Index for external_id lookup
CREATE INDEX IF NOT EXISTS idx_users_external_id
    ON users(tenant_id, external_id)
    WHERE external_id IS NOT NULL;

-- Insert default attribute mappings function (call for each tenant)
CREATE OR REPLACE FUNCTION create_default_scim_mappings(p_tenant_id UUID)
RETURNS void AS $$
BEGIN
    INSERT INTO scim_attribute_mappings (tenant_id, scim_path, xavyo_field, required)
    VALUES
        (p_tenant_id, 'userName', 'email', TRUE),
        (p_tenant_id, 'displayName', 'display_name', FALSE),
        (p_tenant_id, 'active', 'is_active', FALSE),
        (p_tenant_id, 'externalId', 'external_id', FALSE),
        (p_tenant_id, 'name.givenName', 'first_name', FALSE),
        (p_tenant_id, 'name.familyName', 'last_name', FALSE)
    ON CONFLICT (tenant_id, scim_path) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE scim_tokens IS 'Bearer tokens for SCIM API authentication';
COMMENT ON TABLE scim_attribute_mappings IS 'Custom attribute mapping configuration per tenant';
COMMENT ON TABLE scim_audit_logs IS 'Audit trail for all SCIM operations';
COMMENT ON TABLE groups IS 'User groups for role-based access control';
COMMENT ON TABLE group_memberships IS 'Many-to-many relationship between users and groups';
