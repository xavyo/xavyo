-- F094: Behavioral Anomaly Detection - Anomaly Baselines Table
-- Stores pre-computed statistical baselines for each agent

CREATE TABLE IF NOT EXISTS anomaly_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    baseline_type VARCHAR(50) NOT NULL,
    mean_value DECIMAL(15,4) NOT NULL,
    std_deviation DECIMAL(15,4) NOT NULL,
    sample_count INTEGER NOT NULL,
    percentiles JSONB,
    tool_frequencies JSONB,
    hour_frequencies JSONB,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_valid BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT unique_agent_baseline_type UNIQUE (tenant_id, agent_id, baseline_type)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_anomaly_baselines_agent
    ON anomaly_baselines(tenant_id, agent_id);

-- Row Level Security
ALTER TABLE anomaly_baselines ENABLE ROW LEVEL SECURITY;

CREATE POLICY anomaly_baselines_tenant_isolation ON anomaly_baselines
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Grant permissions to app user
GRANT SELECT, INSERT, UPDATE, DELETE ON anomaly_baselines TO xavyo_app;
