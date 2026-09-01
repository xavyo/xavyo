-- Persist NHI certification campaigns and their create-time filters.
-- POST /governance/nhis/certification/campaigns accepted owner_filter and
-- needs_certification_only, used them only for a draft count, then launch
-- hardcoded owner_filter=None / needs_certification_only=true against a
-- table that was never migrated.

CREATE TABLE IF NOT EXISTS gov_nhi_certification_campaigns (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'active', 'overdue', 'completed', 'cancelled')),
    reviewer_type TEXT NOT NULL
        CHECK (reviewer_type IN ('owner', 'backup_owner', 'specific_users', 'owner_manager')),
    specific_reviewers JSONB,
    deadline TIMESTAMPTZ NOT NULL,
    owner_filter UUID REFERENCES users(id) ON DELETE SET NULL,
    needs_certification_only BOOLEAN NOT NULL DEFAULT TRUE,
    nhi_type_filter TEXT
        CHECK (nhi_type_filter IS NULL OR nhi_type_filter IN ('service_account', 'agent', 'tool')),
    specific_nhi_ids UUID[] DEFAULT '{}',
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    launched_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_gov_nhi_cert_campaigns_tenant_status
    ON gov_nhi_certification_campaigns (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_cert_campaigns_created_by
    ON gov_nhi_certification_campaigns (tenant_id, created_by);

ALTER TABLE gov_nhi_certification_campaigns ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS gov_nhi_cert_campaigns_tenant_isolation ON gov_nhi_certification_campaigns;
CREATE POLICY gov_nhi_cert_campaigns_tenant_isolation ON gov_nhi_certification_campaigns
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON gov_nhi_certification_campaigns TO xavyo_app;

CREATE TABLE IF NOT EXISTS gov_nhi_certification_items (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id UUID NOT NULL REFERENCES gov_nhi_certification_campaigns(id) ON DELETE CASCADE,
    nhi_id UUID NOT NULL REFERENCES nhi_identities(id) ON DELETE CASCADE,
    reviewer_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'certified', 'revoked', 'expired')),
    decision TEXT
        CHECK (decision IS NULL OR decision IN ('certify', 'revoke', 'delegate')),
    decided_by UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at TIMESTAMPTZ,
    comment TEXT,
    delegated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    original_reviewer_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gov_nhi_cert_items_campaign
    ON gov_nhi_certification_items (tenant_id, campaign_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_cert_items_reviewer
    ON gov_nhi_certification_items (tenant_id, reviewer_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_cert_items_nhi
    ON gov_nhi_certification_items (tenant_id, nhi_id);

ALTER TABLE gov_nhi_certification_items ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS gov_nhi_cert_items_tenant_isolation ON gov_nhi_certification_items;
CREATE POLICY gov_nhi_cert_items_tenant_isolation ON gov_nhi_certification_items
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON gov_nhi_certification_items TO xavyo_app;
