-- Migration: 088_001_gov_roles
-- Feature: F088 - Business Role Hierarchy Model
-- Description: Create gov_roles table for formal business role hierarchy

-- Create gov_roles table
CREATE TABLE IF NOT EXISTS gov_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parent_role_id UUID REFERENCES gov_roles(id) ON DELETE SET NULL,
    is_abstract BOOLEAN NOT NULL DEFAULT false,
    hierarchy_depth INT NOT NULL DEFAULT 0,
    version INT NOT NULL DEFAULT 1,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Role names must be unique within a tenant
    CONSTRAINT gov_roles_tenant_name_unique UNIQUE (tenant_id, name),
    -- Hierarchy depth must be non-negative
    CONSTRAINT gov_roles_depth_non_negative CHECK (hierarchy_depth >= 0)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_gov_roles_tenant ON gov_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_roles_parent ON gov_roles(tenant_id, parent_role_id);
CREATE INDEX IF NOT EXISTS idx_gov_roles_depth ON gov_roles(tenant_id, hierarchy_depth);
CREATE INDEX IF NOT EXISTS idx_gov_roles_abstract ON gov_roles(tenant_id, is_abstract) WHERE is_abstract = true;

-- Enable RLS
ALTER TABLE gov_roles ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS gov_roles_tenant_isolation ON gov_roles;
CREATE POLICY gov_roles_tenant_isolation ON gov_roles
    USING (
        tenant_id = COALESCE(
            NULLIF(current_setting('app.current_tenant', true), '')::uuid,
            tenant_id
        )
    );

-- Comments for documentation
COMMENT ON TABLE gov_roles IS 'Business role hierarchy with parent-child relationships and entitlement inheritance (F088)';
COMMENT ON COLUMN gov_roles.parent_role_id IS 'Parent role reference for hierarchy; NULL indicates a root role';
COMMENT ON COLUMN gov_roles.is_abstract IS 'Abstract roles cannot be directly assigned to users; used for grouping shared entitlements';
COMMENT ON COLUMN gov_roles.hierarchy_depth IS 'Computed depth from root (0 = root role); used for depth limit enforcement';
COMMENT ON COLUMN gov_roles.version IS 'Optimistic concurrency control version; incremented on each update';
