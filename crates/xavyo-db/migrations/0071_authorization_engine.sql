-- F083: Fine-Grained Authorization Engine (PDP/PEP)
-- Creates tables for authorization policies, conditions, and entitlement-to-action mappings

-- ============================================================================
-- Table 1: authorization_policies
-- Tenant-scoped authorization policies with allow/deny effects
-- ============================================================================

CREATE TABLE IF NOT EXISTS authorization_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    priority INTEGER NOT NULL DEFAULT 100,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    resource_type VARCHAR(255),
    action VARCHAR(255),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT authorization_policies_tenant_name_unique UNIQUE (tenant_id, name)
);

-- Indexes
CREATE INDEX idx_authz_policies_tenant_status ON authorization_policies(tenant_id, status);
CREATE INDEX idx_authz_policies_tenant_priority ON authorization_policies(tenant_id, priority);

-- RLS
ALTER TABLE authorization_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY authz_policies_tenant_isolation_select ON authorization_policies
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY authz_policies_tenant_isolation_insert ON authorization_policies
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY authz_policies_tenant_isolation_update ON authorization_policies
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY authz_policies_tenant_isolation_delete ON authorization_policies
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Updated_at trigger
CREATE TRIGGER authorization_policies_updated_at
    BEFORE UPDATE ON authorization_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


-- ============================================================================
-- Table 2: policy_conditions
-- Conditions attached to authorization policies (AND-combined)
-- ============================================================================

CREATE TABLE IF NOT EXISTS policy_conditions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES authorization_policies(id) ON DELETE CASCADE,
    condition_type TEXT NOT NULL CHECK (condition_type IN ('time_window', 'user_attribute', 'entitlement_check')),
    attribute_path VARCHAR(255),
    operator VARCHAR(50),
    value JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_policy_conditions_policy ON policy_conditions(policy_id);
CREATE INDEX idx_policy_conditions_tenant ON policy_conditions(tenant_id);

-- RLS
ALTER TABLE policy_conditions ENABLE ROW LEVEL SECURITY;

CREATE POLICY policy_conditions_tenant_isolation_select ON policy_conditions
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY policy_conditions_tenant_isolation_insert ON policy_conditions
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY policy_conditions_tenant_isolation_update ON policy_conditions
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY policy_conditions_tenant_isolation_delete ON policy_conditions
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);


-- ============================================================================
-- Table 3: entitlement_action_mappings
-- Links entitlements to actions and resource types
-- ============================================================================

CREATE TABLE IF NOT EXISTS entitlement_action_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255) NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT eam_tenant_entitlement_action_resource_unique
        UNIQUE (tenant_id, entitlement_id, action, resource_type)
);

-- Indexes
CREATE INDEX idx_eam_tenant_entitlement ON entitlement_action_mappings(tenant_id, entitlement_id);
CREATE INDEX idx_eam_tenant_resource_action ON entitlement_action_mappings(tenant_id, resource_type, action);

-- RLS
ALTER TABLE entitlement_action_mappings ENABLE ROW LEVEL SECURITY;

CREATE POLICY eam_tenant_isolation_select ON entitlement_action_mappings
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY eam_tenant_isolation_insert ON entitlement_action_mappings
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY eam_tenant_isolation_update ON entitlement_action_mappings
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY eam_tenant_isolation_delete ON entitlement_action_mappings
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
