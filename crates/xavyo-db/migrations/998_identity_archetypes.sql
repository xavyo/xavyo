-- Migration: 998_identity_archetypes
-- Feature: F-058 Identity Archetype System
-- Description: Archetype definitions for identity classification with inheritance,
--              schema extensions, policy bindings, and lifecycle model association

-- ============================================================================
-- TABLES
-- ============================================================================

-- Identity Archetypes: Core entity for identity categorization
CREATE TABLE IF NOT EXISTS identity_archetypes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parent_archetype_id UUID REFERENCES identity_archetypes(id) ON DELETE SET NULL,
    schema_extensions JSONB NOT NULL DEFAULT '{"attributes": []}',
    lifecycle_model_id UUID,  -- FK to lifecycle_state_models when F-059 is implemented
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT uq_archetype_name_per_tenant UNIQUE (tenant_id, name),
    CONSTRAINT chk_no_self_parent CHECK (parent_archetype_id != id)
);

-- Archetype Policy Bindings: Links archetypes to security policies
CREATE TABLE IF NOT EXISTS archetype_policy_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    archetype_id UUID NOT NULL REFERENCES identity_archetypes(id) ON DELETE CASCADE,
    policy_type VARCHAR(50) NOT NULL,
    policy_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT uq_archetype_policy_type UNIQUE (archetype_id, policy_type),
    CONSTRAINT chk_valid_policy_type CHECK (policy_type IN ('password', 'mfa', 'session'))
);

-- ============================================================================
-- USER TABLE EXTENSION
-- ============================================================================

-- Add archetype reference to users table
ALTER TABLE users
ADD COLUMN IF NOT EXISTS archetype_id UUID REFERENCES identity_archetypes(id) ON DELETE SET NULL;

ALTER TABLE users
ADD COLUMN IF NOT EXISTS archetype_custom_attrs JSONB NOT NULL DEFAULT '{}';

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Identity Archetypes indexes
CREATE INDEX IF NOT EXISTS idx_archetypes_tenant ON identity_archetypes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_archetypes_parent ON identity_archetypes(parent_archetype_id)
    WHERE parent_archetype_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_archetypes_active ON identity_archetypes(tenant_id)
    WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_archetypes_name ON identity_archetypes(tenant_id, name);

-- Policy bindings indexes
CREATE INDEX IF NOT EXISTS idx_policy_bindings_archetype ON archetype_policy_bindings(archetype_id);
CREATE INDEX IF NOT EXISTS idx_policy_bindings_tenant ON archetype_policy_bindings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policy_bindings_type ON archetype_policy_bindings(archetype_id, policy_type);

-- User archetype lookup
CREATE INDEX IF NOT EXISTS idx_users_archetype ON users(archetype_id)
    WHERE archetype_id IS NOT NULL;

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Enable RLS on identity_archetypes
ALTER TABLE identity_archetypes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identity_archetypes_tenant_isolation ON identity_archetypes;
CREATE POLICY identity_archetypes_tenant_isolation ON identity_archetypes
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Enable RLS on archetype_policy_bindings
ALTER TABLE archetype_policy_bindings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS archetype_policy_bindings_tenant_isolation ON archetype_policy_bindings;
CREATE POLICY archetype_policy_bindings_tenant_isolation ON archetype_policy_bindings
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Update updated_at trigger for identity_archetypes
DROP TRIGGER IF EXISTS update_identity_archetypes_updated_at ON identity_archetypes;
CREATE TRIGGER update_identity_archetypes_updated_at
    BEFORE UPDATE ON identity_archetypes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE identity_archetypes IS
    'Identity archetype definitions for classifying and managing identity types (F-058).
     Supports inheritance hierarchy, schema extensions, and policy bindings.';

COMMENT ON COLUMN identity_archetypes.schema_extensions IS
    'JSON structure defining custom attributes for this archetype.
     Format: {"attributes": [{"name": "...", "type": "string|number|date|boolean|enum|uuid", "required": bool, ...}]}';

COMMENT ON COLUMN identity_archetypes.parent_archetype_id IS
    'Optional parent archetype for inheritance. Child archetypes inherit parent policies and schema extensions.';

COMMENT ON COLUMN identity_archetypes.lifecycle_model_id IS
    'Optional reference to lifecycle state model (F-059). When set, users with this archetype follow the specified lifecycle.';

COMMENT ON TABLE archetype_policy_bindings IS
    'Links archetypes to security policies (password, MFA, session).
     Each archetype can have at most one policy per type.';

COMMENT ON COLUMN users.archetype_id IS
    'Optional reference to identity archetype. When set, archetype policies and schema extensions apply to this user.';

COMMENT ON COLUMN users.archetype_custom_attrs IS
    'Custom attribute values for this user based on their archetype schema extensions.';
