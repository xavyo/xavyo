-- License Management Migration (F065)
-- Implements software license pool tracking, assignments, entitlement integration,
-- reclamation rules, incompatibility constraints, and audit events.

-- ============================================================================
-- ENUMS
-- ============================================================================

-- License type: named (permanent user assignment) vs concurrent (floating/session-based)
CREATE TYPE license_type AS ENUM ('named', 'concurrent');

-- Billing period for license cost tracking
CREATE TYPE license_billing_period AS ENUM ('monthly', 'annual', 'perpetual');

-- Policy to enforce when license pool expires
CREATE TYPE license_expiration_policy AS ENUM ('block_new', 'revoke_all', 'warn_only');

-- License pool lifecycle status
CREATE TYPE license_pool_status AS ENUM ('active', 'expired', 'archived');

-- License assignment status
CREATE TYPE license_assignment_status AS ENUM ('active', 'reclaimed', 'expired', 'released');

-- Source of license assignment
CREATE TYPE license_assignment_source AS ENUM ('manual', 'automatic', 'entitlement');

-- Trigger type for reclamation rules
CREATE TYPE license_reclamation_trigger AS ENUM ('inactivity', 'lifecycle_state');

-- Reason for license reclamation
CREATE TYPE license_reclaim_reason AS ENUM ('inactivity', 'termination', 'manual', 'expiration');

-- ============================================================================
-- TABLES
-- ============================================================================

-- License pools: purchased software license packages
CREATE TABLE gov_license_pools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    vendor VARCHAR(255) NOT NULL,
    description TEXT,
    total_capacity INT NOT NULL CHECK (total_capacity >= 0),
    allocated_count INT NOT NULL DEFAULT 0 CHECK (allocated_count >= 0),
    cost_per_license DECIMAL(10,2),
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    billing_period license_billing_period NOT NULL,
    license_type license_type NOT NULL DEFAULT 'named',
    expiration_date TIMESTAMPTZ,
    expiration_policy license_expiration_policy NOT NULL DEFAULT 'block_new',
    warning_days INT NOT NULL DEFAULT 60,
    status license_pool_status NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,

    CONSTRAINT chk_license_pool_allocated CHECK (allocated_count <= total_capacity),
    CONSTRAINT uq_license_pool_name UNIQUE (tenant_id, name)
);

-- License assignments: links users to license pools
CREATE TABLE gov_license_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    license_pool_id UUID NOT NULL REFERENCES gov_license_pools(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID NOT NULL,
    source license_assignment_source NOT NULL,
    entitlement_link_id UUID, -- FK added after gov_license_entitlement_links is created
    session_id UUID, -- For concurrent licenses, FK to sessions table if needed
    status license_assignment_status NOT NULL DEFAULT 'active',
    reclaimed_at TIMESTAMPTZ,
    reclaim_reason license_reclaim_reason,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- License-entitlement links: automatic allocation when entitlements are granted
CREATE TABLE gov_license_entitlement_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    license_pool_id UUID NOT NULL REFERENCES gov_license_pools(id) ON DELETE CASCADE,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    priority INT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,

    CONSTRAINT uq_license_entitlement_link UNIQUE (tenant_id, license_pool_id, entitlement_id)
);

-- Add FK for entitlement_link_id now that table exists
ALTER TABLE gov_license_assignments
    ADD CONSTRAINT fk_license_assignment_entitlement_link
    FOREIGN KEY (entitlement_link_id) REFERENCES gov_license_entitlement_links(id) ON DELETE SET NULL;

-- License reclamation rules: automatic reclamation criteria
CREATE TABLE gov_license_reclamation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    license_pool_id UUID NOT NULL REFERENCES gov_license_pools(id) ON DELETE CASCADE,
    trigger_type license_reclamation_trigger NOT NULL,
    threshold_days INT,
    lifecycle_state VARCHAR(50),
    notification_days_before INT NOT NULL DEFAULT 7,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,

    CONSTRAINT chk_reclamation_rule_threshold CHECK (
        (trigger_type = 'inactivity' AND threshold_days IS NOT NULL) OR
        (trigger_type = 'lifecycle_state' AND lifecycle_state IS NOT NULL)
    )
);

-- License incompatibility rules: pools that cannot be assigned to same user
CREATE TABLE gov_license_incompatibilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pool_a_id UUID NOT NULL REFERENCES gov_license_pools(id) ON DELETE CASCADE,
    pool_b_id UUID NOT NULL REFERENCES gov_license_pools(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,

    CONSTRAINT chk_incompatibility_different CHECK (pool_a_id != pool_b_id),
    -- Symmetric unique constraint using LEAST/GREATEST
    CONSTRAINT uq_license_incompatibility UNIQUE (tenant_id, pool_a_id, pool_b_id)
);

-- Create unique index for symmetric lookup
CREATE UNIQUE INDEX idx_license_incompatibility_symmetric
    ON gov_license_incompatibilities (tenant_id, LEAST(pool_a_id, pool_b_id), GREATEST(pool_a_id, pool_b_id));

-- License audit events: all operations for compliance
CREATE TABLE gov_license_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    license_pool_id UUID REFERENCES gov_license_pools(id) ON DELETE SET NULL,
    license_assignment_id UUID REFERENCES gov_license_assignments(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    actor_id UUID NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- License pools indexes
CREATE INDEX idx_license_pool_tenant ON gov_license_pools(tenant_id);
CREATE INDEX idx_license_pool_vendor ON gov_license_pools(tenant_id, vendor);
CREATE INDEX idx_license_pool_expiration ON gov_license_pools(tenant_id, expiration_date)
    WHERE status = 'active';
CREATE INDEX idx_license_pool_status ON gov_license_pools(tenant_id, status);

-- License assignments indexes
CREATE INDEX idx_license_assignment_tenant ON gov_license_assignments(tenant_id);
CREATE INDEX idx_license_assignment_pool ON gov_license_assignments(tenant_id, license_pool_id);
CREATE INDEX idx_license_assignment_user ON gov_license_assignments(tenant_id, user_id);
CREATE INDEX idx_license_assignment_active ON gov_license_assignments(tenant_id, license_pool_id)
    WHERE status = 'active';
-- Unique constraint: one active assignment per user per pool
CREATE UNIQUE INDEX uq_license_assignment_user_pool
    ON gov_license_assignments(tenant_id, license_pool_id, user_id)
    WHERE status = 'active';

-- License entitlement links indexes
CREATE INDEX idx_license_entitlement_link_tenant ON gov_license_entitlement_links(tenant_id);
CREATE INDEX idx_license_entitlement_link_entitlement ON gov_license_entitlement_links(tenant_id, entitlement_id);
CREATE INDEX idx_license_entitlement_link_pool ON gov_license_entitlement_links(tenant_id, license_pool_id);

-- License reclamation rules indexes
CREATE INDEX idx_license_reclamation_rule_tenant ON gov_license_reclamation_rules(tenant_id);
CREATE INDEX idx_license_reclamation_rule_pool ON gov_license_reclamation_rules(tenant_id, license_pool_id);

-- License incompatibility indexes
CREATE INDEX idx_license_incompatibility_tenant ON gov_license_incompatibilities(tenant_id);
CREATE INDEX idx_license_incompatibility_pools ON gov_license_incompatibilities(tenant_id, pool_a_id, pool_b_id);

-- License audit events indexes
CREATE INDEX idx_license_audit_tenant ON gov_license_audit_events(tenant_id);
CREATE INDEX idx_license_audit_pool ON gov_license_audit_events(tenant_id, license_pool_id);
CREATE INDEX idx_license_audit_user ON gov_license_audit_events(tenant_id, user_id);
CREATE INDEX idx_license_audit_time ON gov_license_audit_events(tenant_id, created_at DESC);
CREATE INDEX idx_license_audit_action ON gov_license_audit_events(tenant_id, action);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE gov_license_pools ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_license_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_license_entitlement_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_license_reclamation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_license_incompatibilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_license_audit_events ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for tenant isolation
CREATE POLICY tenant_isolation_license_pools ON gov_license_pools
    USING (tenant_id = COALESCE(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_license_assignments ON gov_license_assignments
    USING (tenant_id = COALESCE(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_license_entitlement_links ON gov_license_entitlement_links
    USING (tenant_id = COALESCE(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_license_reclamation_rules ON gov_license_reclamation_rules
    USING (tenant_id = COALESCE(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_license_incompatibilities ON gov_license_incompatibilities
    USING (tenant_id = COALESCE(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_license_audit_events ON gov_license_audit_events
    USING (tenant_id = COALESCE(current_setting('app.tenant_id', true), '')::uuid);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Updated_at trigger for license pools
CREATE TRIGGER update_license_pools_updated_at
    BEFORE UPDATE ON gov_license_pools
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Updated_at trigger for license assignments
CREATE TRIGGER update_license_assignments_updated_at
    BEFORE UPDATE ON gov_license_assignments
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Updated_at trigger for reclamation rules
CREATE TRIGGER update_license_reclamation_rules_updated_at
    BEFORE UPDATE ON gov_license_reclamation_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE gov_license_pools IS 'Software license pools representing purchased license packages';
COMMENT ON TABLE gov_license_assignments IS 'License assignments linking users to license pools';
COMMENT ON TABLE gov_license_entitlement_links IS 'Links between license pools and entitlements for automatic allocation';
COMMENT ON TABLE gov_license_reclamation_rules IS 'Rules for automatic license reclamation based on inactivity or lifecycle state';
COMMENT ON TABLE gov_license_incompatibilities IS 'Rules defining license pools that cannot be assigned to the same user';
COMMENT ON TABLE gov_license_audit_events IS 'Audit trail of all license-related operations for compliance';

COMMENT ON COLUMN gov_license_pools.total_capacity IS 'Total number of licenses purchased';
COMMENT ON COLUMN gov_license_pools.allocated_count IS 'Current number of licenses assigned';
COMMENT ON COLUMN gov_license_pools.license_type IS 'named = permanent user assignment, concurrent = floating/session-based';
COMMENT ON COLUMN gov_license_pools.expiration_policy IS 'Action to take when pool expires: block_new, revoke_all, or warn_only';
COMMENT ON COLUMN gov_license_pools.warning_days IS 'Days before expiration to start sending renewal alerts';

COMMENT ON COLUMN gov_license_assignments.source IS 'How the license was assigned: manual, automatic, or via entitlement';
COMMENT ON COLUMN gov_license_assignments.session_id IS 'For concurrent licenses, the active session ID';

COMMENT ON COLUMN gov_license_entitlement_links.priority IS 'Priority when multiple pools could satisfy an entitlement (lower = higher priority)';

COMMENT ON COLUMN gov_license_reclamation_rules.threshold_days IS 'Days of inactivity before reclamation (for inactivity trigger)';
COMMENT ON COLUMN gov_license_reclamation_rules.lifecycle_state IS 'Lifecycle state that triggers reclamation (for lifecycle_state trigger)';
COMMENT ON COLUMN gov_license_reclamation_rules.notification_days_before IS 'Days before reclamation to notify user';
