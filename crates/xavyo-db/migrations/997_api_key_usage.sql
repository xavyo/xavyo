-- API Key Usage Statistics (F-054)
-- Tracks usage metrics for API keys including request counts, error rates, and time-series data

-- Cumulative usage statistics per API key
CREATE TABLE IF NOT EXISTS api_key_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    total_requests BIGINT NOT NULL DEFAULT 0,
    success_count BIGINT NOT NULL DEFAULT 0,
    client_error_count BIGINT NOT NULL DEFAULT 0,
    server_error_count BIGINT NOT NULL DEFAULT 0,
    first_used_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (key_id)
);

-- Hourly aggregated usage (90-day retention)
CREATE TABLE IF NOT EXISTS api_key_usage_hourly (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hour TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    client_error_count INTEGER NOT NULL DEFAULT 0,
    server_error_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (key_id, hour)
);

-- Daily aggregated usage (365-day retention)
CREATE TABLE IF NOT EXISTS api_key_usage_daily (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    client_error_count INTEGER NOT NULL DEFAULT 0,
    server_error_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (key_id, date)
);

-- Indexes for api_key_usage
CREATE INDEX IF NOT EXISTS idx_api_key_usage_key ON api_key_usage(key_id);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_tenant ON api_key_usage(tenant_id);

-- Indexes for api_key_usage_hourly
CREATE INDEX IF NOT EXISTS idx_api_key_usage_hourly_key_hour ON api_key_usage_hourly(key_id, hour);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_hourly_tenant ON api_key_usage_hourly(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_hourly_hour ON api_key_usage_hourly(hour);

-- Indexes for api_key_usage_daily
CREATE INDEX IF NOT EXISTS idx_api_key_usage_daily_key_date ON api_key_usage_daily(key_id, date);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_daily_tenant ON api_key_usage_daily(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_daily_date ON api_key_usage_daily(date);

-- Row-Level Security policies
ALTER TABLE api_key_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_key_usage_hourly ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_key_usage_daily ENABLE ROW LEVEL SECURITY;

-- RLS policy for api_key_usage
DROP POLICY IF EXISTS api_key_usage_tenant_isolation ON api_key_usage;
CREATE POLICY api_key_usage_tenant_isolation ON api_key_usage
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policy for api_key_usage_hourly
DROP POLICY IF EXISTS api_key_usage_hourly_tenant_isolation ON api_key_usage_hourly;
CREATE POLICY api_key_usage_hourly_tenant_isolation ON api_key_usage_hourly
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policy for api_key_usage_daily
DROP POLICY IF EXISTS api_key_usage_daily_tenant_isolation ON api_key_usage_daily;
CREATE POLICY api_key_usage_daily_tenant_isolation ON api_key_usage_daily
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
