-- Migration: 057_001_parametric_roles
-- Feature: F057 Parametric Roles
-- Description: Creates tables for parametric role management with customizable parameter definitions

-- ============================================================================
-- Enum Types
-- ============================================================================

-- Parameter type enum
CREATE TYPE gov_parameter_type AS ENUM (
    'string',
    'integer',
    'boolean',
    'date',
    'enum'
);

-- Parameter audit event type
CREATE TYPE gov_parameter_event_type AS ENUM (
    'parameters_set',           -- Initial parameter values on assignment
    'parameters_updated',       -- Parameter values modified
    'parameter_added',          -- New parameter added to existing assignment
    'parameter_removed',        -- Parameter removed from assignment
    'validation_failed',        -- Parameter validation rejection (for audit)
    'schema_violation_flagged'  -- Assignment flagged for schema non-conformance
);

-- ============================================================================
-- Role Parameter Definition Table
-- ============================================================================

CREATE TABLE gov_role_parameters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES gov_roles(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    parameter_type gov_parameter_type NOT NULL,
    is_required BOOLEAN NOT NULL DEFAULT false,
    default_value JSONB,
    constraints JSONB,
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique parameter name per role within tenant
    CONSTRAINT gov_role_parameters_unique UNIQUE (tenant_id, role_id, name),
    -- Name must be alphanumeric with underscores
    CONSTRAINT gov_role_parameters_name_format CHECK (name ~ '^[a-zA-Z][a-zA-Z0-9_]*$')
);

-- Enable RLS
ALTER TABLE gov_role_parameters ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_role_parameters_tenant_isolation ON gov_role_parameters
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_role_parameters_role ON gov_role_parameters(role_id);
CREATE INDEX idx_gov_role_parameters_tenant ON gov_role_parameters(tenant_id);

-- ============================================================================
-- Role Assignment Parameter Values Table
-- ============================================================================

CREATE TABLE gov_role_assignment_parameters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assignment_id UUID NOT NULL REFERENCES gov_entitlement_assignments(id) ON DELETE CASCADE,
    parameter_id UUID NOT NULL REFERENCES gov_role_parameters(id) ON DELETE CASCADE,
    value JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique parameter value per assignment
    CONSTRAINT gov_role_assignment_parameters_unique UNIQUE (tenant_id, assignment_id, parameter_id)
);

-- Enable RLS
ALTER TABLE gov_role_assignment_parameters ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_role_assignment_parameters_tenant_isolation ON gov_role_assignment_parameters
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_role_assignment_parameters_assignment ON gov_role_assignment_parameters(assignment_id);
CREATE INDEX idx_gov_role_assignment_parameters_parameter ON gov_role_assignment_parameters(parameter_id);

-- ============================================================================
-- Extend gov_entitlement_assignments with parameter support
-- ============================================================================

-- Add parameter_hash column for unique parametric assignments
ALTER TABLE gov_entitlement_assignments
    ADD COLUMN IF NOT EXISTS parameter_hash VARCHAR(64);

-- Add temporal validity columns
ALTER TABLE gov_entitlement_assignments
    ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ;

ALTER TABLE gov_entitlement_assignments
    ADD COLUMN IF NOT EXISTS valid_to TIMESTAMPTZ;

-- Create unique index for parametric assignments (allowing null for non-parametric)
CREATE UNIQUE INDEX idx_gov_entitlement_assignments_param_hash
    ON gov_entitlement_assignments(tenant_id, entitlement_id, target_type, target_id, parameter_hash)
    WHERE parameter_hash IS NOT NULL;

-- Indexes for temporal validity queries
CREATE INDEX idx_gov_entitlement_assignments_valid_from
    ON gov_entitlement_assignments(valid_from)
    WHERE valid_from IS NOT NULL;

CREATE INDEX idx_gov_entitlement_assignments_valid_to
    ON gov_entitlement_assignments(valid_to)
    WHERE valid_to IS NOT NULL;

-- ============================================================================
-- Parameter Audit Events Table
-- ============================================================================

CREATE TABLE gov_parameter_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assignment_id UUID NOT NULL REFERENCES gov_entitlement_assignments(id) ON DELETE CASCADE,
    event_type gov_parameter_event_type NOT NULL,
    actor_id UUID,
    old_values JSONB,
    new_values JSONB,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE gov_parameter_audit_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_parameter_audit_events_tenant_isolation ON gov_parameter_audit_events
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_parameter_audit_events_assignment ON gov_parameter_audit_events(assignment_id);
CREATE INDEX idx_gov_parameter_audit_events_time ON gov_parameter_audit_events(tenant_id, created_at DESC);
CREATE INDEX idx_gov_parameter_audit_events_type ON gov_parameter_audit_events(tenant_id, event_type);

-- ============================================================================
-- Trigger for updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION update_gov_role_parameter_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_gov_role_parameters_updated_at
    BEFORE UPDATE ON gov_role_parameters
    FOR EACH ROW
    EXECUTE FUNCTION update_gov_role_parameter_updated_at();

CREATE TRIGGER trigger_gov_role_assignment_parameters_updated_at
    BEFORE UPDATE ON gov_role_assignment_parameters
    FOR EACH ROW
    EXECUTE FUNCTION update_gov_role_parameter_updated_at();
