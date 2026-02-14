-- F-USAGE-TRACK: Add tenant usage tracking support
-- Tracks MAU, API calls, auth events, and agent invocations per billing period

-- Tenant usage metrics per billing period
CREATE TABLE IF NOT EXISTS tenant_usage_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    mau_count INTEGER NOT NULL DEFAULT 0,
    api_calls BIGINT NOT NULL DEFAULT 0,
    auth_events BIGINT NOT NULL DEFAULT 0,
    agent_invocations BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, period_start)
);

-- Index for efficient period lookups
CREATE INDEX IF NOT EXISTS idx_tenant_usage_metrics_tenant_period
    ON tenant_usage_metrics(tenant_id, period_start DESC);

-- Track unique active users per period for MAU calculation
CREATE TABLE IF NOT EXISTS tenant_active_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    period_start DATE NOT NULL,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, user_id, period_start)
);

-- Index for MAU calculation
CREATE INDEX IF NOT EXISTS idx_tenant_active_users_tenant_period
    ON tenant_active_users(tenant_id, period_start);

-- RLS policies
ALTER TABLE tenant_usage_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_active_users ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant_usage_metrics
CREATE POLICY tenant_usage_metrics_tenant_isolation ON tenant_usage_metrics
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policy for tenant_active_users
CREATE POLICY tenant_active_users_tenant_isolation ON tenant_active_users
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Comments
COMMENT ON TABLE tenant_usage_metrics IS 'Monthly usage metrics per tenant for billing and quota enforcement';
COMMENT ON COLUMN tenant_usage_metrics.mau_count IS 'Monthly Active Users - count of unique users active during the period';
COMMENT ON COLUMN tenant_usage_metrics.api_calls IS 'Total API calls made during the period';
COMMENT ON COLUMN tenant_usage_metrics.auth_events IS 'Authentication events (logins, token refreshes) during the period';
COMMENT ON COLUMN tenant_usage_metrics.agent_invocations IS 'AI agent API invocations during the period';

COMMENT ON TABLE tenant_active_users IS 'Unique active users per billing period for MAU calculation';
COMMENT ON COLUMN tenant_active_users.last_active_at IS 'Last time the user was active during this period';
