-- Migration: Create scim_target_attribute_mappings table with Row-Level Security
-- Feature: F087 - SCIM 2.0 Outbound Provisioning Client
-- Description: Per-target attribute mappings from internal xavyo fields to SCIM attribute paths

CREATE TABLE IF NOT EXISTS scim_target_attribute_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
    source_field VARCHAR(255) NOT NULL,
    target_scim_path VARCHAR(512) NOT NULL,
    mapping_type VARCHAR(20) NOT NULL DEFAULT 'direct',
    constant_value TEXT,
    transform VARCHAR(20),
    resource_type VARCHAR(10) NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Mapping type must be a known value
    CONSTRAINT scim_attr_map_type_check CHECK (
        mapping_type IN ('direct', 'constant', 'expression')
    ),

    -- Transform must be a known value if set
    CONSTRAINT scim_attr_map_transform_check CHECK (
        transform IS NULL OR transform IN ('lowercase', 'uppercase', 'trim')
    ),

    -- Resource type must be user or group
    CONSTRAINT scim_attr_map_resource_type_check CHECK (
        resource_type IN ('user', 'group')
    ),

    -- Unique mapping per target, source field, and resource type
    CONSTRAINT scim_attr_map_unique UNIQUE (target_id, source_field, resource_type)
);

-- Index for target_id lookups
CREATE INDEX IF NOT EXISTS idx_scim_target_mappings_target
    ON scim_target_attribute_mappings(target_id);

-- Enable Row-Level Security on the table
ALTER TABLE scim_target_attribute_mappings ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE scim_target_attribute_mappings FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
DROP POLICY IF EXISTS tenant_isolation_policy ON scim_target_attribute_mappings;
CREATE POLICY tenant_isolation_policy ON scim_target_attribute_mappings
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE scim_target_attribute_mappings IS 'Maps internal xavyo fields to SCIM attribute paths per target';
COMMENT ON COLUMN scim_target_attribute_mappings.source_field IS 'Internal xavyo field path (e.g., email, first_name, custom_attributes.department)';
COMMENT ON COLUMN scim_target_attribute_mappings.target_scim_path IS 'SCIM attribute path (e.g., userName, name.givenName, enterprise extension URN)';
COMMENT ON COLUMN scim_target_attribute_mappings.mapping_type IS 'How value is derived: direct (field copy), constant (fixed value), expression';
