-- Persist catalog cart submission_id so GET /governance/catalog/requests
-- can group access requests created together. Cart submit previously
-- returned a submission_id that was never stored.

CREATE TABLE IF NOT EXISTS catalog_request_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    submission_id UUID NOT NULL,
    access_request_id UUID NOT NULL REFERENCES gov_access_requests(id) ON DELETE CASCADE,
    catalog_item_id UUID NOT NULL REFERENCES catalog_items(id) ON DELETE CASCADE,
    cart_item_id UUID,
    beneficiary_id UUID REFERENCES users(id) ON DELETE SET NULL,
    form_values JSONB NOT NULL DEFAULT '{}'::jsonb,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_catalog_request_links_request UNIQUE (tenant_id, access_request_id)
);

CREATE INDEX IF NOT EXISTS idx_catalog_request_links_submission
    ON catalog_request_links (tenant_id, submission_id);

ALTER TABLE catalog_request_links ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS catalog_request_links_tenant_isolation ON catalog_request_links;
CREATE POLICY catalog_request_links_tenant_isolation ON catalog_request_links
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON catalog_request_links TO xavyo_app;
