-- Migration: 024_ip_restrictions.sql
-- Feature: F028 - IP Restrictions
-- Description: IP-based access control per tenant with whitelist/blacklist modes

-- ============================================================================
-- Part 1: Create enforcement_mode enum type
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ip_enforcement_mode') THEN
        CREATE TYPE ip_enforcement_mode AS ENUM ('disabled', 'whitelist', 'blacklist');
    END IF;
END $$;

-- ============================================================================
-- Part 2: Create ip_rule_type enum type
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ip_rule_type') THEN
        CREATE TYPE ip_rule_type AS ENUM ('whitelist', 'blacklist');
    END IF;
END $$;

-- ============================================================================
-- Part 3: Create tenant_ip_settings table
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_ip_settings (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enforcement_mode ip_enforcement_mode NOT NULL DEFAULT 'disabled',
    bypass_for_super_admin BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Enable RLS
ALTER TABLE tenant_ip_settings ENABLE ROW LEVEL SECURITY;

-- RLS policies for tenant isolation
DROP POLICY IF EXISTS tenant_isolation_ip_settings_select ON tenant_ip_settings;
CREATE POLICY tenant_isolation_ip_settings_select ON tenant_ip_settings
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_ip_settings_insert ON tenant_ip_settings;
CREATE POLICY tenant_isolation_ip_settings_insert ON tenant_ip_settings
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_ip_settings_update ON tenant_ip_settings;
CREATE POLICY tenant_isolation_ip_settings_update ON tenant_ip_settings
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_ip_settings_delete ON tenant_ip_settings;
CREATE POLICY tenant_isolation_ip_settings_delete ON tenant_ip_settings
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- Part 4: Create ip_restriction_rules table
-- ============================================================================

CREATE TABLE IF NOT EXISTS ip_restriction_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_type ip_rule_type NOT NULL,
    scope VARCHAR(100) NOT NULL DEFAULT 'all',
    ip_cidr CIDR NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique constraint: rule name must be unique within tenant
    CONSTRAINT uq_ip_rules_tenant_name UNIQUE (tenant_id, name)
);

-- Enable RLS
ALTER TABLE ip_restriction_rules ENABLE ROW LEVEL SECURITY;

-- RLS policies for tenant isolation
DROP POLICY IF EXISTS tenant_isolation_ip_rules_select ON ip_restriction_rules;
CREATE POLICY tenant_isolation_ip_rules_select ON ip_restriction_rules
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_ip_rules_insert ON ip_restriction_rules;
CREATE POLICY tenant_isolation_ip_rules_insert ON ip_restriction_rules
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_ip_rules_update ON ip_restriction_rules;
CREATE POLICY tenant_isolation_ip_rules_update ON ip_restriction_rules
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_ip_rules_delete ON ip_restriction_rules;
CREATE POLICY tenant_isolation_ip_rules_delete ON ip_restriction_rules
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- Part 5: Create indexes for performance
-- ============================================================================

-- Index for active rules lookup (most common query)
CREATE INDEX IF NOT EXISTS idx_ip_rules_tenant_active
    ON ip_restriction_rules(tenant_id, rule_type)
    WHERE is_active = TRUE;

-- Index for rule lookup by tenant
CREATE INDEX IF NOT EXISTS idx_ip_rules_tenant
    ON ip_restriction_rules(tenant_id);

-- ============================================================================
-- Part 6: Add scope validation constraint
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_ip_rule_scope'
    ) THEN
        ALTER TABLE ip_restriction_rules
            ADD CONSTRAINT chk_ip_rule_scope
            CHECK (scope = 'all' OR scope = 'admin' OR scope LIKE 'role:%');
    END IF;
END $$;

-- ============================================================================
-- Part 7: Comments for documentation
-- ============================================================================

COMMENT ON TABLE tenant_ip_settings IS 'Per-tenant IP restriction configuration';
COMMENT ON COLUMN tenant_ip_settings.tenant_id IS 'Tenant identifier';
COMMENT ON COLUMN tenant_ip_settings.enforcement_mode IS 'Mode: disabled (no filtering), whitelist (allow listed), blacklist (block listed)';
COMMENT ON COLUMN tenant_ip_settings.bypass_for_super_admin IS 'Allow super admins to bypass IP restrictions';
COMMENT ON COLUMN tenant_ip_settings.updated_at IS 'Last modification timestamp';
COMMENT ON COLUMN tenant_ip_settings.updated_by IS 'User who last updated settings';

COMMENT ON TABLE ip_restriction_rules IS 'IP access rules for tenant IP restrictions';
COMMENT ON COLUMN ip_restriction_rules.id IS 'Rule identifier';
COMMENT ON COLUMN ip_restriction_rules.tenant_id IS 'Tenant identifier';
COMMENT ON COLUMN ip_restriction_rules.rule_type IS 'Rule type: whitelist or blacklist';
COMMENT ON COLUMN ip_restriction_rules.scope IS 'Target users: all, admin, or role:<name>';
COMMENT ON COLUMN ip_restriction_rules.ip_cidr IS 'IP address or range in CIDR notation (e.g., 192.168.1.0/24)';
COMMENT ON COLUMN ip_restriction_rules.name IS 'Human-readable rule name (unique per tenant)';
COMMENT ON COLUMN ip_restriction_rules.description IS 'Optional rule description';
COMMENT ON COLUMN ip_restriction_rules.is_active IS 'Whether rule is active';
COMMENT ON COLUMN ip_restriction_rules.created_by IS 'User who created the rule';
COMMENT ON COLUMN ip_restriction_rules.created_at IS 'Creation timestamp';
COMMENT ON COLUMN ip_restriction_rules.updated_at IS 'Last modification timestamp';
