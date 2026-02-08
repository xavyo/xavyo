-- NHI Separation of Duties rules table.
-- Defines tool permission combinations that are prohibited or warned about.

CREATE TABLE IF NOT EXISTS nhi_sod_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_id_a UUID NOT NULL,
    tool_id_b UUID NOT NULL,
    enforcement TEXT NOT NULL DEFAULT 'prevent' CHECK (enforcement IN ('prevent', 'warn')),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,

    -- Prevent duplicate rules (a,b) vs (b,a) by normalizing order
    CONSTRAINT uq_nhi_sod_rule UNIQUE (tenant_id, tool_id_a, tool_id_b),
    -- Ensure the two tools are different
    CONSTRAINT ck_nhi_sod_different_tools CHECK (tool_id_a != tool_id_b)
);

-- Index for looking up rules by either tool
CREATE INDEX IF NOT EXISTS idx_nhi_sod_rules_tool_a ON nhi_sod_rules (tenant_id, tool_id_a);
CREATE INDEX IF NOT EXISTS idx_nhi_sod_rules_tool_b ON nhi_sod_rules (tenant_id, tool_id_b);

-- RLS policy
ALTER TABLE nhi_sod_rules ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS nhi_sod_rules_tenant_isolation ON nhi_sod_rules;
CREATE POLICY nhi_sod_rules_tenant_isolation ON nhi_sod_rules
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
