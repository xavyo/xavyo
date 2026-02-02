-- F094: Behavioral Anomaly Detection - Detected Anomalies Table
-- Records all detected anomalies for audit and analysis

CREATE TABLE IF NOT EXISTS detected_anomalies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    anomaly_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
    z_score DECIMAL(10,4) NOT NULL,
    baseline_value DECIMAL(15,4) NOT NULL,
    observed_value DECIMAL(15,4) NOT NULL,
    description TEXT NOT NULL,
    context JSONB,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_sent BOOLEAN NOT NULL DEFAULT false,
    alert_sent_at TIMESTAMPTZ
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_detected_anomalies_agent_time
    ON detected_anomalies(tenant_id, agent_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_detected_anomalies_tenant_time
    ON detected_anomalies(tenant_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_detected_anomalies_type_severity
    ON detected_anomalies(tenant_id, agent_id, anomaly_type, severity);

CREATE INDEX IF NOT EXISTS idx_detected_anomalies_alert_pending
    ON detected_anomalies(tenant_id, agent_id, anomaly_type)
    WHERE alert_sent = false;

-- Row Level Security
ALTER TABLE detected_anomalies ENABLE ROW LEVEL SECURITY;

CREATE POLICY detected_anomalies_tenant_isolation ON detected_anomalies
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Grant permissions to app user
GRANT SELECT, INSERT, UPDATE, DELETE ON detected_anomalies TO xavyo_app;
