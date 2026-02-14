-- F034: Separation of Duties (SoD) Rules
-- This migration creates tables for SoD rule definitions, violation tracking, and exemption management.

-- ============================================================================
-- ENUMS
-- ============================================================================

-- Severity levels for SoD rules (reuses concept from gov_risk_level)
CREATE TYPE gov_sod_severity AS ENUM ('low', 'medium', 'high', 'critical');

-- Status for SoD rules
CREATE TYPE gov_sod_rule_status AS ENUM ('active', 'inactive');

-- Status for SoD violations
CREATE TYPE gov_violation_status AS ENUM ('active', 'exempted', 'remediated');

-- Status for SoD exemptions
CREATE TYPE gov_exemption_status AS ENUM ('active', 'expired', 'revoked');

-- ============================================================================
-- SOD RULES TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_sod_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    first_entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE RESTRICT,
    second_entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE RESTRICT,
    severity gov_sod_severity NOT NULL DEFAULT 'medium',
    status gov_sod_rule_status NOT NULL DEFAULT 'active',
    business_rationale TEXT,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Prevent self-referencing rules
    CONSTRAINT gov_sod_rules_different_entitlements CHECK (first_entitlement_id != second_entitlement_id),

    -- Unique name per tenant
    CONSTRAINT gov_sod_rules_tenant_name_unique UNIQUE (tenant_id, name)
);

-- Unique constraint on normalized entitlement pair (order-independent)
-- Uses LEAST/GREATEST to normalize the pair
CREATE UNIQUE INDEX gov_sod_rules_unique_pair ON gov_sod_rules (
    tenant_id,
    LEAST(first_entitlement_id, second_entitlement_id),
    GREATEST(first_entitlement_id, second_entitlement_id)
);

-- Indexes for rules
CREATE INDEX IF NOT EXISTS idx_gov_sod_rules_tenant_status ON gov_sod_rules(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_sod_rules_first_ent ON gov_sod_rules(tenant_id, first_entitlement_id);
CREATE INDEX IF NOT EXISTS idx_gov_sod_rules_second_ent ON gov_sod_rules(tenant_id, second_entitlement_id);
CREATE INDEX IF NOT EXISTS idx_gov_sod_rules_severity ON gov_sod_rules(tenant_id, severity);

-- RLS for rules
ALTER TABLE gov_sod_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_sod_rules_tenant_isolation_select ON gov_sod_rules
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_sod_rules_tenant_isolation_insert ON gov_sod_rules
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_sod_rules_tenant_isolation_update ON gov_sod_rules
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_sod_rules_tenant_isolation_delete ON gov_sod_rules
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- SOD VIOLATIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_sod_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES gov_sod_rules(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    first_assignment_id UUID REFERENCES gov_entitlement_assignments(id) ON DELETE SET NULL,
    second_assignment_id UUID REFERENCES gov_entitlement_assignments(id) ON DELETE SET NULL,
    status gov_violation_status NOT NULL DEFAULT 'active',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    remediated_at TIMESTAMPTZ,
    remediated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    remediation_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial unique index: only one active/exempted violation per rule/user
CREATE UNIQUE INDEX gov_sod_violations_unique_active ON gov_sod_violations (tenant_id, rule_id, user_id)
    WHERE status IN ('active', 'exempted');

-- Indexes for violations
CREATE INDEX IF NOT EXISTS idx_gov_sod_violations_tenant_status ON gov_sod_violations(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_sod_violations_rule ON gov_sod_violations(tenant_id, rule_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_sod_violations_user ON gov_sod_violations(tenant_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_sod_violations_detected ON gov_sod_violations(tenant_id, detected_at);

-- RLS for violations
ALTER TABLE gov_sod_violations ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_sod_violations_tenant_isolation_select ON gov_sod_violations
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_sod_violations_tenant_isolation_insert ON gov_sod_violations
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_sod_violations_tenant_isolation_update ON gov_sod_violations
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_sod_violations_tenant_isolation_delete ON gov_sod_violations
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- SOD EXEMPTIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_sod_exemptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES gov_sod_rules(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    approver_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    justification TEXT NOT NULL,
    status gov_exemption_status NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Expiration must be in future at creation (enforced at app level for updates)
    CONSTRAINT gov_sod_exemptions_valid_expiration CHECK (expires_at > created_at),

    -- Justification cannot be empty
    CONSTRAINT gov_sod_exemptions_has_justification CHECK (length(trim(justification)) > 0)
);

-- Partial unique index: only one active exemption per rule/user
CREATE UNIQUE INDEX gov_sod_exemptions_unique_active ON gov_sod_exemptions (tenant_id, rule_id, user_id)
    WHERE status = 'active';

-- Indexes for exemptions
CREATE INDEX IF NOT EXISTS idx_gov_sod_exemptions_tenant_status ON gov_sod_exemptions(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_sod_exemptions_rule_user ON gov_sod_exemptions(tenant_id, rule_id, user_id);
CREATE INDEX IF NOT EXISTS idx_gov_sod_exemptions_expires ON gov_sod_exemptions(tenant_id, status, expires_at)
    WHERE status = 'active';

-- RLS for exemptions
ALTER TABLE gov_sod_exemptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_sod_exemptions_tenant_isolation_select ON gov_sod_exemptions
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_sod_exemptions_tenant_isolation_insert ON gov_sod_exemptions
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_sod_exemptions_tenant_isolation_update ON gov_sod_exemptions
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_sod_exemptions_tenant_isolation_delete ON gov_sod_exemptions
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS: Update updated_at timestamp
-- ============================================================================

CREATE TRIGGER gov_sod_rules_updated_at
    BEFORE UPDATE ON gov_sod_rules
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();

CREATE TRIGGER gov_sod_violations_updated_at
    BEFORE UPDATE ON gov_sod_violations
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();

CREATE TRIGGER gov_sod_exemptions_updated_at
    BEFORE UPDATE ON gov_sod_exemptions
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();
