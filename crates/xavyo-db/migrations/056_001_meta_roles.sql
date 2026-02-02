-- Migration: 056_001_meta_roles
-- Feature: F056 Meta-roles
-- Description: Creates tables for meta-role management with hierarchical role inheritance

-- ============================================================================
-- Enum Types
-- ============================================================================

-- Meta-role status
CREATE TYPE gov_meta_role_status AS ENUM ('active', 'disabled');

-- Criteria logic (AND/OR)
CREATE TYPE gov_meta_role_criteria_logic AS ENUM ('and', 'or');

-- Criteria operator
CREATE TYPE gov_meta_role_criteria_operator AS ENUM (
    'eq',        -- equals
    'neq',       -- not equals
    'in',        -- in list
    'not_in',    -- not in list
    'gt',        -- greater than
    'gte',       -- greater than or equal
    'lt',        -- less than
    'lte',       -- less than or equal
    'contains',  -- contains substring
    'starts_with' -- starts with prefix
);

-- Entitlement permission type (grant or deny)
CREATE TYPE gov_meta_role_permission_type AS ENUM ('grant', 'deny');

-- Inheritance status
CREATE TYPE gov_meta_role_inheritance_status AS ENUM ('active', 'suspended', 'removed');

-- Conflict type
CREATE TYPE gov_meta_role_conflict_type AS ENUM (
    'entitlement_conflict',  -- Same entitlement with grant vs deny
    'constraint_conflict',   -- Same constraint type with different values
    'policy_conflict'        -- Contradicting boolean policies
);

-- Conflict resolution status
CREATE TYPE gov_meta_role_resolution_status AS ENUM (
    'unresolved',
    'resolved_priority',
    'resolved_manual',
    'ignored'
);

-- Event type for audit trail
CREATE TYPE gov_meta_role_event_type AS ENUM (
    'created',
    'updated',
    'deleted',
    'disabled',
    'enabled',
    'inheritance_applied',
    'inheritance_removed',
    'conflict_detected',
    'conflict_resolved',
    'cascade_started',
    'cascade_completed',
    'cascade_failed'
);

-- ============================================================================
-- Main Meta-role Table
-- ============================================================================

CREATE TABLE gov_meta_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    priority INTEGER NOT NULL DEFAULT 100,
    status gov_meta_role_status NOT NULL DEFAULT 'active',
    criteria_logic gov_meta_role_criteria_logic NOT NULL DEFAULT 'and',
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique name per tenant
    CONSTRAINT gov_meta_roles_name_unique UNIQUE (tenant_id, name),
    -- Priority must be 1-1000
    CONSTRAINT gov_meta_roles_priority_range CHECK (priority >= 1 AND priority <= 1000)
);

-- Enable RLS
ALTER TABLE gov_meta_roles ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_meta_roles_tenant_isolation ON gov_meta_roles
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_meta_roles_tenant ON gov_meta_roles(tenant_id);
CREATE INDEX idx_gov_meta_roles_status ON gov_meta_roles(tenant_id, status);
CREATE INDEX idx_gov_meta_roles_priority ON gov_meta_roles(tenant_id, priority);

-- ============================================================================
-- Meta-role Criteria Table
-- ============================================================================

CREATE TABLE gov_meta_role_criteria (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    meta_role_id UUID NOT NULL REFERENCES gov_meta_roles(id) ON DELETE CASCADE,
    field VARCHAR(100) NOT NULL,
    operator gov_meta_role_criteria_operator NOT NULL,
    value JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE gov_meta_role_criteria ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_meta_role_criteria_tenant_isolation ON gov_meta_role_criteria
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_meta_role_criteria_meta_role ON gov_meta_role_criteria(meta_role_id);

-- ============================================================================
-- Meta-role Entitlement Table
-- ============================================================================

CREATE TABLE gov_meta_role_entitlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    meta_role_id UUID NOT NULL REFERENCES gov_meta_roles(id) ON DELETE CASCADE,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    permission_type gov_meta_role_permission_type NOT NULL DEFAULT 'grant',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique entitlement per meta-role
    CONSTRAINT gov_meta_role_entitlements_unique UNIQUE (meta_role_id, entitlement_id)
);

-- Enable RLS
ALTER TABLE gov_meta_role_entitlements ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_meta_role_entitlements_tenant_isolation ON gov_meta_role_entitlements
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_meta_role_entitlements_meta_role ON gov_meta_role_entitlements(meta_role_id);
CREATE INDEX idx_gov_meta_role_entitlements_entitlement ON gov_meta_role_entitlements(entitlement_id);

-- ============================================================================
-- Meta-role Constraint Table
-- ============================================================================

CREATE TABLE gov_meta_role_constraints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    meta_role_id UUID NOT NULL REFERENCES gov_meta_roles(id) ON DELETE CASCADE,
    constraint_type VARCHAR(100) NOT NULL,
    constraint_value JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique constraint type per meta-role
    CONSTRAINT gov_meta_role_constraints_unique UNIQUE (meta_role_id, constraint_type)
);

-- Enable RLS
ALTER TABLE gov_meta_role_constraints ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_meta_role_constraints_tenant_isolation ON gov_meta_role_constraints
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_meta_role_constraints_meta_role ON gov_meta_role_constraints(meta_role_id);

-- ============================================================================
-- Meta-role Inheritance Table (meta-role ↔ role relationship)
-- ============================================================================

CREATE TABLE gov_meta_role_inheritances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    meta_role_id UUID NOT NULL REFERENCES gov_meta_roles(id) ON DELETE CASCADE,
    child_role_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    match_reason JSONB NOT NULL,
    status gov_meta_role_inheritance_status NOT NULL DEFAULT 'active',
    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique inheritance relationship
    CONSTRAINT gov_meta_role_inheritances_unique UNIQUE (tenant_id, meta_role_id, child_role_id)
);

-- Enable RLS
ALTER TABLE gov_meta_role_inheritances ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_meta_role_inheritances_tenant_isolation ON gov_meta_role_inheritances
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_meta_role_inheritances_meta_role ON gov_meta_role_inheritances(meta_role_id);
CREATE INDEX idx_gov_meta_role_inheritances_child_role ON gov_meta_role_inheritances(child_role_id);
CREATE INDEX idx_gov_meta_role_inheritances_status ON gov_meta_role_inheritances(tenant_id, status);

-- ============================================================================
-- Meta-role Conflict Table
-- ============================================================================

CREATE TABLE gov_meta_role_conflicts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    meta_role_a_id UUID NOT NULL REFERENCES gov_meta_roles(id) ON DELETE CASCADE,
    meta_role_b_id UUID NOT NULL REFERENCES gov_meta_roles(id) ON DELETE CASCADE,
    affected_role_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    conflict_type gov_meta_role_conflict_type NOT NULL,
    conflicting_items JSONB NOT NULL,
    resolution_status gov_meta_role_resolution_status NOT NULL DEFAULT 'unresolved',
    resolved_by UUID,
    resolution_choice JSONB,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,

    -- Ensure meta_role_a_id < meta_role_b_id to avoid duplicates
    CONSTRAINT gov_meta_role_conflicts_order CHECK (meta_role_a_id < meta_role_b_id)
);

-- Enable RLS
ALTER TABLE gov_meta_role_conflicts ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_meta_role_conflicts_tenant_isolation ON gov_meta_role_conflicts
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_meta_role_conflicts_role ON gov_meta_role_conflicts(affected_role_id);
CREATE INDEX idx_gov_meta_role_conflicts_status ON gov_meta_role_conflicts(tenant_id, resolution_status);
CREATE INDEX idx_gov_meta_role_conflicts_meta_role_a ON gov_meta_role_conflicts(meta_role_a_id);
CREATE INDEX idx_gov_meta_role_conflicts_meta_role_b ON gov_meta_role_conflicts(meta_role_b_id);

-- ============================================================================
-- Meta-role Event Table (Audit Trail)
-- ============================================================================

CREATE TABLE gov_meta_role_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    meta_role_id UUID REFERENCES gov_meta_roles(id) ON DELETE SET NULL,
    event_type gov_meta_role_event_type NOT NULL,
    actor_id UUID,
    changes JSONB,
    affected_roles JSONB,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE gov_meta_role_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_meta_role_events_tenant_isolation ON gov_meta_role_events
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_meta_role_events_type ON gov_meta_role_events(tenant_id, event_type);
CREATE INDEX idx_gov_meta_role_events_time ON gov_meta_role_events(tenant_id, created_at DESC);
CREATE INDEX idx_gov_meta_role_events_meta_role ON gov_meta_role_events(meta_role_id);

-- ============================================================================
-- Trigger for updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION update_gov_meta_role_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_gov_meta_roles_updated_at
    BEFORE UPDATE ON gov_meta_roles
    FOR EACH ROW
    EXECUTE FUNCTION update_gov_meta_role_updated_at();

CREATE TRIGGER trigger_gov_meta_role_inheritances_updated_at
    BEFORE UPDATE ON gov_meta_role_inheritances
    FOR EACH ROW
    EXECUTE FUNCTION update_gov_meta_role_updated_at();
