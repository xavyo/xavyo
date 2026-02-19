-- Lightweight call counters for NHI identities, aggregated by time window.
-- Populated by the ext-authz ActivityTracker during its periodic flush.
CREATE TABLE IF NOT EXISTS nhi_activity_counters (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    nhi_id UUID NOT NULL REFERENCES nhi_identities(id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    window_type TEXT NOT NULL,  -- 'hourly' or 'daily'
    call_count INT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, nhi_id, window_start, window_type)
);

-- Index for querying recent activity by NHI
CREATE INDEX IF NOT EXISTS idx_nhi_activity_counters_nhi
    ON nhi_activity_counters(tenant_id, nhi_id, window_start DESC);

-- RLS policy
ALTER TABLE nhi_activity_counters ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS nhi_activity_counters_tenant_policy ON nhi_activity_counters;
CREATE POLICY nhi_activity_counters_tenant_policy ON nhi_activity_counters
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
