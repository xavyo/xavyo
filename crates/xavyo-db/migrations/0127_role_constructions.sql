-- Migration: 1000_role_constructions
-- Feature: F-063 - Role Inducements (Construction Pattern)
-- Description: Create tables for role constructions and role inducements

-- ============================================================================
-- Part 1: Deprovisioning Policy Enum
-- ============================================================================

-- Create deprovisioning_policy enum type
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'deprovisioning_policy') THEN
        CREATE TYPE deprovisioning_policy AS ENUM ('disable', 'delete', 'retain');
    END IF;
END$$;

COMMENT ON TYPE deprovisioning_policy IS 'Policy for handling accounts when role is revoked: disable (update status), delete (remove account), retain (keep account)';

-- ============================================================================
-- Part 2: Role Constructions Table
-- ============================================================================

-- Create role_constructions table
-- Defines what gets provisioned when a role is assigned to a user
CREATE TABLE IF NOT EXISTS role_constructions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES gov_roles(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE RESTRICT,
    object_class VARCHAR(255) NOT NULL,
    account_type VARCHAR(100) NOT NULL DEFAULT 'default',
    attribute_mappings JSONB NOT NULL DEFAULT '{"mappings": [], "static_values": {}}',
    condition JSONB,
    deprovisioning_policy deprovisioning_policy NOT NULL DEFAULT 'disable',
    priority INT NOT NULL DEFAULT 0,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    description TEXT,
    version INT NOT NULL DEFAULT 1,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Each role can have only one construction per connector + object_class + account_type combo
    CONSTRAINT uq_role_construction UNIQUE (tenant_id, role_id, connector_id, object_class, account_type),
    -- Priority must be non-negative
    CONSTRAINT role_construction_priority_valid CHECK (priority >= 0),
    -- Version must be positive
    CONSTRAINT role_construction_version_valid CHECK (version >= 1)
);

-- Indexes for role_constructions
CREATE INDEX IF NOT EXISTS idx_role_construction_tenant_role
    ON role_constructions(tenant_id, role_id);
CREATE INDEX IF NOT EXISTS idx_role_construction_connector
    ON role_constructions(tenant_id, connector_id);
CREATE INDEX IF NOT EXISTS idx_role_construction_enabled
    ON role_constructions(tenant_id, role_id) WHERE is_enabled = true;

-- Enable RLS for role_constructions
ALTER TABLE role_constructions ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS role_construction_tenant_isolation ON role_constructions;
CREATE POLICY role_construction_tenant_isolation ON role_constructions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Comments for role_constructions
COMMENT ON TABLE role_constructions IS 'Defines provisioning constructions triggered when a role is assigned (F-063)';
COMMENT ON COLUMN role_constructions.role_id IS 'The role this construction belongs to';
COMMENT ON COLUMN role_constructions.connector_id IS 'Target connector for provisioning the account';
COMMENT ON COLUMN role_constructions.object_class IS 'Object class to provision (e.g., user, group)';
COMMENT ON COLUMN role_constructions.account_type IS 'Account type identifier (e.g., standard, privileged)';
COMMENT ON COLUMN role_constructions.attribute_mappings IS 'JSONB containing attribute transformation rules and static values';
COMMENT ON COLUMN role_constructions.condition IS 'Optional JSONB condition expression; NULL means always trigger';
COMMENT ON COLUMN role_constructions.deprovisioning_policy IS 'What to do when role is revoked: disable, delete, or retain the account';
COMMENT ON COLUMN role_constructions.priority IS 'Execution order (higher = executed first)';
COMMENT ON COLUMN role_constructions.is_enabled IS 'Soft disable without deletion';
COMMENT ON COLUMN role_constructions.version IS 'Optimistic concurrency control version';

-- ============================================================================
-- Part 3: Role Inducements Table
-- ============================================================================

-- Create role_inducements table
-- Links one role to another for automatic construction inheritance
CREATE TABLE IF NOT EXISTS role_inducements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    inducing_role_id UUID NOT NULL REFERENCES gov_roles(id) ON DELETE CASCADE,
    induced_role_id UUID NOT NULL REFERENCES gov_roles(id) ON DELETE CASCADE,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    description TEXT,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Each inducement relationship must be unique
    CONSTRAINT uq_role_inducement UNIQUE (tenant_id, inducing_role_id, induced_role_id),
    -- No self-reference allowed
    CONSTRAINT role_inducement_no_self_ref CHECK (inducing_role_id != induced_role_id)
);

-- Indexes for role_inducements
CREATE INDEX IF NOT EXISTS idx_role_inducement_inducing
    ON role_inducements(tenant_id, inducing_role_id);
CREATE INDEX IF NOT EXISTS idx_role_inducement_induced
    ON role_inducements(tenant_id, induced_role_id);
CREATE INDEX IF NOT EXISTS idx_role_inducement_enabled
    ON role_inducements(tenant_id, inducing_role_id) WHERE is_enabled = true;

-- Enable RLS for role_inducements
ALTER TABLE role_inducements ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS role_inducement_tenant_isolation ON role_inducements;
CREATE POLICY role_inducement_tenant_isolation ON role_inducements
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Comments for role_inducements
COMMENT ON TABLE role_inducements IS 'Links roles for automatic construction inheritance (F-063)';
COMMENT ON COLUMN role_inducements.inducing_role_id IS 'Parent role that induces the child role';
COMMENT ON COLUMN role_inducements.induced_role_id IS 'Child role whose constructions are inherited';
COMMENT ON COLUMN role_inducements.is_enabled IS 'Soft disable without deletion';

-- ============================================================================
-- Part 4: Extend Provisioning Operations
-- ============================================================================

-- Add construction_id and role_assignment_id to provisioning_operations
-- These track the source of construction-triggered operations
ALTER TABLE provisioning_operations
    ADD COLUMN IF NOT EXISTS construction_id UUID REFERENCES role_constructions(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS role_assignment_id UUID;

-- Index for finding operations by construction
CREATE INDEX IF NOT EXISTS idx_provisioning_operations_construction
    ON provisioning_operations(tenant_id, construction_id) WHERE construction_id IS NOT NULL;

-- Comments for new columns
COMMENT ON COLUMN provisioning_operations.construction_id IS 'Source construction that triggered this operation (if any)';
COMMENT ON COLUMN provisioning_operations.role_assignment_id IS 'Source role assignment that triggered this operation (if any)';

-- ============================================================================
-- Part 5: Cycle Detection Helper Function
-- ============================================================================

-- Function to detect cycles in role inducements
-- Returns true if adding an inducement from source_role to target_role would create a cycle
CREATE OR REPLACE FUNCTION check_inducement_cycle(
    p_tenant_id UUID,
    p_source_role_id UUID,
    p_target_role_id UUID
) RETURNS BOOLEAN AS $$
DECLARE
    v_has_cycle BOOLEAN;
BEGIN
    -- Check if target_role already has a path back to source_role
    WITH RECURSIVE inducement_path AS (
        -- Base case: start from target_role
        SELECT induced_role_id, 1 as depth
        FROM role_inducements
        WHERE tenant_id = p_tenant_id
            AND inducing_role_id = p_target_role_id
            AND is_enabled = true

        UNION ALL

        -- Recursive case: follow inducement chain
        SELECT ri.induced_role_id, ip.depth + 1
        FROM role_inducements ri
        INNER JOIN inducement_path ip ON ri.inducing_role_id = ip.induced_role_id
        WHERE ri.tenant_id = p_tenant_id
            AND ri.is_enabled = true
            AND ip.depth < 20  -- Prevent infinite loops with depth limit
    )
    SELECT EXISTS (
        SELECT 1 FROM inducement_path WHERE induced_role_id = p_source_role_id
    ) INTO v_has_cycle;

    RETURN v_has_cycle;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION check_inducement_cycle IS 'Checks if adding an inducement would create a circular reference (F-063)';
