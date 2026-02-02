-- F094: Behavioral Anomaly Detection - Anomaly Thresholds Table
-- Configurable thresholds at tenant or agent level

CREATE TABLE IF NOT EXISTS anomaly_thresholds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES ai_agents(id) ON DELETE CASCADE,
    anomaly_type VARCHAR(50) NOT NULL,
    threshold_value DECIMAL(10,4) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    alert_enabled BOOLEAN NOT NULL DEFAULT true,
    aggregation_window_secs INTEGER NOT NULL DEFAULT 300,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),

    -- Unique constraint allows one threshold per type per agent (or tenant default when agent_id is NULL)
    CONSTRAINT unique_threshold_per_agent_type UNIQUE (tenant_id, agent_id, anomaly_type)
);

-- Index for tenant defaults (agent_id IS NULL)
CREATE INDEX IF NOT EXISTS idx_anomaly_thresholds_tenant_defaults
    ON anomaly_thresholds(tenant_id, anomaly_type)
    WHERE agent_id IS NULL;

-- Row Level Security
ALTER TABLE anomaly_thresholds ENABLE ROW LEVEL SECURITY;

CREATE POLICY anomaly_thresholds_tenant_isolation ON anomaly_thresholds
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Grant permissions to app user
GRANT SELECT, INSERT, UPDATE, DELETE ON anomaly_thresholds TO xavyo_app;

-- Trigger for updated_at
CREATE TRIGGER update_anomaly_thresholds_updated_at
    BEFORE UPDATE ON anomaly_thresholds
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
