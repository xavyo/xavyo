-- Feature 070: Custom User Attributes
-- Migration: 070_001_custom_user_attributes.sql
-- Adds extensible user schema via JSONB custom_attributes column and tenant_attribute_definitions table.

-- 1. Add custom_attributes column to users table
ALTER TABLE users ADD COLUMN custom_attributes JSONB NOT NULL DEFAULT '{}';

-- 2. Create GIN index for JSONB containment queries
CREATE INDEX idx_users_custom_attributes_gin
    ON users USING GIN (custom_attributes jsonb_path_ops);

-- 3. Create tenant_attribute_definitions table
CREATE TABLE tenant_attribute_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    display_label VARCHAR(255) NOT NULL,
    data_type VARCHAR(20) NOT NULL CHECK (data_type IN ('string', 'number', 'boolean', 'date', 'json')),
    required BOOLEAN NOT NULL DEFAULT false,
    validation_rules JSONB,
    default_value JSONB,
    sort_order INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tenant_attr_def_name UNIQUE(tenant_id, name),
    CONSTRAINT ck_attr_def_name CHECK (name ~ '^[a-z][a-z0-9_]{0,63}$')
);

-- 4. Enable Row-Level Security
ALTER TABLE tenant_attribute_definitions ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenant_attribute_definitions
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- 5. Indexes
CREATE INDEX idx_tenant_attr_defs_tenant_id
    ON tenant_attribute_definitions(tenant_id);

CREATE INDEX idx_tenant_attr_defs_active
    ON tenant_attribute_definitions(tenant_id, is_active)
    WHERE is_active = true;
