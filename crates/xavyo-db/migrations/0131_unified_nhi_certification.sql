-- Migration: F108 - Create unified NHI certification campaign tables
-- Purpose: Support certification campaigns that span both service accounts and AI agents

-- ============================================================================
-- UNIFIED_NHI_CERTIFICATION_CAMPAIGNS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS unified_nhi_certification_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    -- NHI types to include: 'service_account', 'ai_agent'
    nhi_types JSONB NOT NULL DEFAULT '["service_account"]',
    -- Campaign status: draft, active, completed, cancelled
    status VARCHAR(50) NOT NULL DEFAULT 'draft',
    reviewer_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    -- Optional filter criteria as JSON
    filter JSONB,
    due_date TIMESTAMPTZ NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    launched_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT chk_unified_nhi_campaign_status
        CHECK (status IN ('draft', 'active', 'completed', 'cancelled'))
);

-- Indexes for campaigns
CREATE INDEX IF NOT EXISTS idx_unified_nhi_cert_campaigns_tenant_status
    ON unified_nhi_certification_campaigns(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_unified_nhi_cert_campaigns_due_date
    ON unified_nhi_certification_campaigns(tenant_id, due_date)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_unified_nhi_cert_campaigns_reviewer
    ON unified_nhi_certification_campaigns(reviewer_id);

-- RLS for campaigns
ALTER TABLE unified_nhi_certification_campaigns ENABLE ROW LEVEL SECURITY;

CREATE POLICY unified_nhi_cert_campaigns_tenant_isolation_select ON unified_nhi_certification_campaigns
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY unified_nhi_cert_campaigns_tenant_isolation_insert ON unified_nhi_certification_campaigns
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY unified_nhi_cert_campaigns_tenant_isolation_update ON unified_nhi_certification_campaigns
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY unified_nhi_cert_campaigns_tenant_isolation_delete ON unified_nhi_certification_campaigns
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- UNIFIED_NHI_CERTIFICATION_ITEMS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS unified_nhi_certification_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id UUID NOT NULL REFERENCES unified_nhi_certification_campaigns(id) ON DELETE CASCADE,
    -- NHI reference (either service account or AI agent)
    nhi_id UUID NOT NULL,
    nhi_type VARCHAR(50) NOT NULL,
    nhi_name VARCHAR(255) NOT NULL,
    reviewer_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    -- Item status: pending, certified, revoked
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- Decision: certify, revoke (NULL if pending)
    decision VARCHAR(50),
    decided_by UUID REFERENCES users(id) ON DELETE RESTRICT,
    decided_at TIMESTAMPTZ,
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_unified_nhi_cert_item_status
        CHECK (status IN ('pending', 'certified', 'revoked')),
    CONSTRAINT chk_unified_nhi_cert_item_decision
        CHECK (decision IS NULL OR decision IN ('certify', 'revoke')),
    CONSTRAINT chk_unified_nhi_cert_item_nhi_type
        CHECK (nhi_type IN ('service_account', 'ai_agent'))
);

-- Indexes for items
CREATE INDEX IF NOT EXISTS idx_unified_nhi_cert_items_campaign
    ON unified_nhi_certification_items(campaign_id);
CREATE INDEX IF NOT EXISTS idx_unified_nhi_cert_items_tenant_status
    ON unified_nhi_certification_items(tenant_id, status)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_unified_nhi_cert_items_reviewer
    ON unified_nhi_certification_items(tenant_id, reviewer_id, status);
CREATE INDEX IF NOT EXISTS idx_unified_nhi_cert_items_nhi
    ON unified_nhi_certification_items(tenant_id, nhi_id, nhi_type);

-- Unique constraint: only one pending item per NHI per campaign
CREATE UNIQUE INDEX IF NOT EXISTS idx_unified_nhi_cert_items_unique_pending
    ON unified_nhi_certification_items(campaign_id, nhi_id, nhi_type)
    WHERE status = 'pending';

-- RLS for items
ALTER TABLE unified_nhi_certification_items ENABLE ROW LEVEL SECURITY;

CREATE POLICY unified_nhi_cert_items_tenant_isolation_select ON unified_nhi_certification_items
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY unified_nhi_cert_items_tenant_isolation_insert ON unified_nhi_certification_items
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY unified_nhi_cert_items_tenant_isolation_update ON unified_nhi_certification_items
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY unified_nhi_cert_items_tenant_isolation_delete ON unified_nhi_certification_items
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE unified_nhi_certification_campaigns IS 'F108: Unified certification campaigns spanning service accounts and AI agents';
COMMENT ON TABLE unified_nhi_certification_items IS 'F108: Individual certification items for unified NHI campaigns';
COMMENT ON COLUMN unified_nhi_certification_campaigns.nhi_types IS 'JSON array of NHI types to include: service_account, ai_agent';
COMMENT ON COLUMN unified_nhi_certification_campaigns.filter IS 'Optional JSON filter criteria: owner_id, risk_min, inactive_days';
COMMENT ON COLUMN unified_nhi_certification_items.nhi_id IS 'References either gov_service_accounts.id or ai_agents.id based on nhi_type';
