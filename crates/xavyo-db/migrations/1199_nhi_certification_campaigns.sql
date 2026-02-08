-- NHI Certification Campaigns (Feature 201 — fix: persist to PostgreSQL)
CREATE TABLE IF NOT EXISTS nhi_certification_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scope VARCHAR(50) NOT NULL DEFAULT 'all' CHECK (scope IN ('all', 'by_type', 'specific')),
    nhi_type_filter VARCHAR(50),
    specific_nhi_ids UUID[] DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed', 'cancelled')),
    due_date TIMESTAMPTZ,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nhi_cert_campaigns_tenant ON nhi_certification_campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_nhi_cert_campaigns_status ON nhi_certification_campaigns(tenant_id, status);

-- RLS
ALTER TABLE nhi_certification_campaigns ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS nhi_certification_campaigns_tenant_isolation ON nhi_certification_campaigns;
CREATE POLICY nhi_certification_campaigns_tenant_isolation ON nhi_certification_campaigns
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
