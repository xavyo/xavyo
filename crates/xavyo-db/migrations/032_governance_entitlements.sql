-- F033: Entitlement Management - IGA Foundation
-- This migration creates the core tables for Identity Governance and Administration.
-- Includes: applications, entitlements, entitlement_assignments, role_entitlements

-- ============================================================================
-- ENUMS
-- ============================================================================

-- Application type: internal apps vs external third-party apps
CREATE TYPE gov_app_type AS ENUM ('internal', 'external');

-- Application status
CREATE TYPE gov_app_status AS ENUM ('active', 'inactive');

-- Risk level classification for entitlements
CREATE TYPE gov_risk_level AS ENUM ('low', 'medium', 'high', 'critical');

-- Entitlement status
CREATE TYPE gov_entitlement_status AS ENUM ('active', 'inactive', 'suspended');

-- Assignment target type (user or group)
CREATE TYPE gov_assignment_target_type AS ENUM ('user', 'group');

-- Assignment status
CREATE TYPE gov_assignment_status AS ENUM ('active', 'suspended', 'expired');

-- ============================================================================
-- APPLICATIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    app_type gov_app_type NOT NULL,
    status gov_app_status NOT NULL DEFAULT 'active',
    description TEXT,
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    external_id VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique name per tenant
    CONSTRAINT gov_applications_tenant_name_unique UNIQUE (tenant_id, name)
);

-- Indexes for applications
CREATE INDEX IF NOT EXISTS idx_gov_applications_tenant_status ON gov_applications(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_applications_external_id ON gov_applications(tenant_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_gov_applications_owner ON gov_applications(owner_id) WHERE owner_id IS NOT NULL;

-- RLS for applications
ALTER TABLE gov_applications ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_applications_tenant_isolation_select ON gov_applications
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_applications_tenant_isolation_insert ON gov_applications
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_applications_tenant_isolation_update ON gov_applications
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_applications_tenant_isolation_delete ON gov_applications
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- ENTITLEMENTS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_entitlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES gov_applications(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    risk_level gov_risk_level NOT NULL DEFAULT 'low',
    status gov_entitlement_status NOT NULL DEFAULT 'active',
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    external_id VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique name per application
    CONSTRAINT gov_entitlements_app_name_unique UNIQUE (tenant_id, application_id, name)
);

-- Indexes for entitlements
CREATE INDEX IF NOT EXISTS idx_gov_entitlements_tenant_status ON gov_entitlements(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_entitlements_app_status ON gov_entitlements(application_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_entitlements_risk_level ON gov_entitlements(tenant_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_gov_entitlements_owner ON gov_entitlements(owner_id) WHERE owner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_gov_entitlements_external_id ON gov_entitlements(tenant_id, external_id) WHERE external_id IS NOT NULL;

-- RLS for entitlements
ALTER TABLE gov_entitlements ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_entitlements_tenant_isolation_select ON gov_entitlements
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_entitlements_tenant_isolation_insert ON gov_entitlements
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_entitlements_tenant_isolation_update ON gov_entitlements
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_entitlements_tenant_isolation_delete ON gov_entitlements
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- ENTITLEMENT ASSIGNMENTS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_entitlement_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    target_type gov_assignment_target_type NOT NULL,
    target_id UUID NOT NULL, -- user_id or group_id (FK checked at app level)
    assigned_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    status gov_assignment_status NOT NULL DEFAULT 'active',
    justification TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- No duplicate active assignments
    CONSTRAINT gov_assignments_unique_active UNIQUE (tenant_id, entitlement_id, target_type, target_id)
);

-- Indexes for assignments
CREATE INDEX IF NOT EXISTS idx_gov_assignments_target ON gov_entitlement_assignments(tenant_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_gov_assignments_entitlement_status ON gov_entitlement_assignments(entitlement_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_assignments_expires ON gov_entitlement_assignments(tenant_id, expires_at) WHERE expires_at IS NOT NULL;

-- RLS for assignments
ALTER TABLE gov_entitlement_assignments ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_assignments_tenant_isolation_select ON gov_entitlement_assignments
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_assignments_tenant_isolation_insert ON gov_entitlement_assignments
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_assignments_tenant_isolation_update ON gov_entitlement_assignments
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_assignments_tenant_isolation_delete ON gov_entitlement_assignments
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- ROLE ENTITLEMENTS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_role_entitlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    role_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- No duplicate mappings
    CONSTRAINT gov_role_entitlements_unique UNIQUE (tenant_id, entitlement_id, role_name)
);

-- Indexes for role entitlements
CREATE INDEX IF NOT EXISTS idx_gov_role_entitlements_role ON gov_role_entitlements(tenant_id, role_name);
CREATE INDEX IF NOT EXISTS idx_gov_role_entitlements_entitlement ON gov_role_entitlements(entitlement_id);

-- RLS for role entitlements
ALTER TABLE gov_role_entitlements ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_role_entitlements_tenant_isolation_select ON gov_role_entitlements
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_role_entitlements_tenant_isolation_insert ON gov_role_entitlements
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_role_entitlements_tenant_isolation_update ON gov_role_entitlements
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_role_entitlements_tenant_isolation_delete ON gov_role_entitlements
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGER: Update updated_at timestamp
-- ============================================================================

CREATE OR REPLACE FUNCTION gov_update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER gov_applications_updated_at
    BEFORE UPDATE ON gov_applications
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();

CREATE TRIGGER gov_entitlements_updated_at
    BEFORE UPDATE ON gov_entitlements
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();

CREATE TRIGGER gov_assignments_updated_at
    BEFORE UPDATE ON gov_entitlement_assignments
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();
