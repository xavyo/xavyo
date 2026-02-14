-- F036: Access Certification Campaigns
-- This migration creates tables for access certification campaigns, items, and decisions.

-- ============================================================================
-- ENUMS
-- ============================================================================

-- Certification campaign scope type
CREATE TYPE cert_scope_type AS ENUM ('all_users', 'department', 'application', 'entitlement');

-- Certification reviewer assignment type
CREATE TYPE cert_reviewer_type AS ENUM ('user_manager', 'application_owner', 'entitlement_owner', 'specific_users');

-- Certification campaign status
CREATE TYPE cert_campaign_status AS ENUM ('draft', 'active', 'completed', 'cancelled', 'overdue');

-- Certification item status
CREATE TYPE cert_item_status AS ENUM ('pending', 'approved', 'revoked', 'skipped');

-- Certification decision type
CREATE TYPE cert_decision_type AS ENUM ('approved', 'revoked');

-- ============================================================================
-- GOV_CERTIFICATION_CAMPAIGNS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_certification_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scope_type cert_scope_type NOT NULL,
    scope_config JSONB DEFAULT '{}',
    reviewer_type cert_reviewer_type NOT NULL,
    specific_reviewers UUID[] DEFAULT '{}',
    status cert_campaign_status NOT NULL DEFAULT 'draft',
    deadline TIMESTAMPTZ NOT NULL,
    launched_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for campaigns
CREATE INDEX IF NOT EXISTS idx_cert_campaigns_tenant_status
    ON gov_certification_campaigns(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_cert_campaigns_deadline
    ON gov_certification_campaigns(tenant_id, deadline)
    WHERE status IN ('active', 'overdue');
CREATE INDEX IF NOT EXISTS idx_cert_campaigns_created_by
    ON gov_certification_campaigns(created_by);

-- RLS for campaigns
ALTER TABLE gov_certification_campaigns ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_cert_campaigns_tenant_isolation_select ON gov_certification_campaigns
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_cert_campaigns_tenant_isolation_insert ON gov_certification_campaigns
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_cert_campaigns_tenant_isolation_update ON gov_certification_campaigns
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_cert_campaigns_tenant_isolation_delete ON gov_certification_campaigns
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- GOV_CERTIFICATION_ITEMS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_certification_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id UUID NOT NULL REFERENCES gov_certification_campaigns(id) ON DELETE CASCADE,
    assignment_id UUID REFERENCES gov_entitlement_assignments(id) ON DELETE SET NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE RESTRICT,
    reviewer_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status cert_item_status NOT NULL DEFAULT 'pending',
    assignment_snapshot JSONB NOT NULL DEFAULT '{}',
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for items
CREATE INDEX IF NOT EXISTS idx_cert_items_campaign
    ON gov_certification_items(campaign_id);
CREATE INDEX IF NOT EXISTS idx_cert_items_reviewer_status
    ON gov_certification_items(tenant_id, reviewer_id, status)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_cert_items_user_entitlement
    ON gov_certification_items(tenant_id, user_id, entitlement_id);

-- Unique constraint: only one pending item per user-entitlement pair (across all campaigns)
CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_items_unique_pending
    ON gov_certification_items(tenant_id, user_id, entitlement_id)
    WHERE status = 'pending';

-- RLS for items
ALTER TABLE gov_certification_items ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_cert_items_tenant_isolation_select ON gov_certification_items
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_cert_items_tenant_isolation_insert ON gov_certification_items
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_cert_items_tenant_isolation_update ON gov_certification_items
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_cert_items_tenant_isolation_delete ON gov_certification_items
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- GOV_CERTIFICATION_DECISIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_certification_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id UUID NOT NULL UNIQUE REFERENCES gov_certification_items(id) ON DELETE CASCADE,
    decision_type cert_decision_type NOT NULL,
    justification TEXT,
    decided_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Justification required for revocations
    CONSTRAINT cert_decision_justification_required
        CHECK (decision_type = 'approved' OR (decision_type = 'revoked' AND justification IS NOT NULL AND length(justification) >= 20))
);

-- Indexes for decisions
CREATE INDEX IF NOT EXISTS idx_cert_decisions_decided_by
    ON gov_certification_decisions(decided_by);

-- Note: No tenant_id column - tenant context comes from item_id FK join

-- ============================================================================
-- TRIGGERS: Update updated_at timestamp
-- ============================================================================

CREATE TRIGGER gov_cert_campaigns_updated_at
    BEFORE UPDATE ON gov_certification_campaigns
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();

CREATE TRIGGER gov_cert_items_updated_at
    BEFORE UPDATE ON gov_certification_items
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();
