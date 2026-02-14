-- F059: Outlier Detection
-- ML-based anomaly detection for identity governance

-- Outlier detection status enum
CREATE TYPE outlier_analysis_status AS ENUM ('pending', 'running', 'completed', 'failed');
CREATE TYPE outlier_trigger_type AS ENUM ('scheduled', 'manual', 'api');
CREATE TYPE outlier_classification AS ENUM ('normal', 'outlier', 'unclassifiable');
CREATE TYPE outlier_disposition_status AS ENUM ('new', 'legitimate', 'requires_remediation', 'under_investigation', 'remediated');
CREATE TYPE outlier_alert_type AS ENUM ('new_outlier', 'score_increase', 'repeated_outlier');
CREATE TYPE outlier_alert_severity AS ENUM ('low', 'medium', 'high', 'critical');

-- Configuration table (one per tenant)
CREATE TABLE gov_outlier_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    confidence_threshold DOUBLE PRECISION NOT NULL DEFAULT 2.0,
    frequency_threshold DOUBLE PRECISION NOT NULL DEFAULT 0.1,
    min_peer_group_size INTEGER NOT NULL DEFAULT 5,
    scoring_weights JSONB NOT NULL DEFAULT '{"role_frequency":0.30,"entitlement_count":0.25,"assignment_pattern":0.20,"peer_group_coverage":0.15,"historical_deviation":0.10}',
    schedule_cron VARCHAR(100),
    retention_days INTEGER NOT NULL DEFAULT 365,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_confidence_threshold CHECK (confidence_threshold >= 0.0 AND confidence_threshold <= 5.0),
    CONSTRAINT valid_frequency_threshold CHECK (frequency_threshold >= 0.0 AND frequency_threshold <= 1.0),
    CONSTRAINT valid_min_peer_group_size CHECK (min_peer_group_size >= 2 AND min_peer_group_size <= 100),
    CONSTRAINT valid_retention_days CHECK (retention_days >= 30 AND retention_days <= 3650)
);
CREATE UNIQUE INDEX idx_outlier_config_tenant ON gov_outlier_configurations(tenant_id);

-- Analysis runs
CREATE TABLE gov_outlier_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    config_snapshot JSONB NOT NULL,
    status outlier_analysis_status NOT NULL DEFAULT 'pending',
    triggered_by outlier_trigger_type NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    users_analyzed INTEGER NOT NULL DEFAULT 0,
    outliers_detected INTEGER NOT NULL DEFAULT 0,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_outlier_analysis_tenant_status ON gov_outlier_analyses(tenant_id, status);
CREATE INDEX idx_outlier_analysis_tenant_created ON gov_outlier_analyses(tenant_id, created_at DESC);

-- Individual user results
CREATE TABLE gov_outlier_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    analysis_id UUID NOT NULL REFERENCES gov_outlier_analyses(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    overall_score DOUBLE PRECISION NOT NULL,
    classification outlier_classification NOT NULL,
    peer_scores JSONB NOT NULL DEFAULT '[]',
    factor_breakdown JSONB NOT NULL DEFAULT '{}',
    previous_score DOUBLE PRECISION,
    score_change DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_overall_score CHECK (overall_score >= 0.0 AND overall_score <= 100.0)
);
CREATE INDEX idx_outlier_result_analysis ON gov_outlier_results(analysis_id);
CREATE INDEX idx_outlier_result_user ON gov_outlier_results(tenant_id, user_id);
CREATE INDEX idx_outlier_result_classification ON gov_outlier_results(tenant_id, classification)
    WHERE classification = 'outlier';
CREATE INDEX idx_outlier_result_score ON gov_outlier_results(tenant_id, overall_score DESC);

-- Analyst dispositions
CREATE TABLE gov_outlier_dispositions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    result_id UUID NOT NULL REFERENCES gov_outlier_results(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    status outlier_disposition_status NOT NULL DEFAULT 'new',
    justification TEXT,
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_justification_length CHECK (char_length(justification) <= 2000)
);
CREATE INDEX idx_outlier_disposition_user ON gov_outlier_dispositions(tenant_id, user_id);
CREATE INDEX idx_outlier_disposition_status ON gov_outlier_dispositions(tenant_id, status);
CREATE INDEX idx_outlier_disposition_result ON gov_outlier_dispositions(result_id);

-- Alerts
CREATE TABLE gov_outlier_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    analysis_id UUID NOT NULL REFERENCES gov_outlier_analyses(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    alert_type outlier_alert_type NOT NULL,
    severity outlier_alert_severity NOT NULL,
    score DOUBLE PRECISION NOT NULL,
    classification outlier_classification NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT false,
    is_dismissed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_outlier_alert_tenant_unread ON gov_outlier_alerts(tenant_id, is_read)
    WHERE is_read = false;
CREATE INDEX idx_outlier_alert_user ON gov_outlier_alerts(tenant_id, user_id);
CREATE INDEX idx_outlier_alert_analysis ON gov_outlier_alerts(analysis_id);

-- RLS Policies
ALTER TABLE gov_outlier_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_outlier_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_outlier_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_outlier_dispositions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_outlier_alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_outlier_config ON gov_outlier_configurations
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation_outlier_analysis ON gov_outlier_analyses
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation_outlier_result ON gov_outlier_results
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation_outlier_disposition ON gov_outlier_dispositions
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation_outlier_alert ON gov_outlier_alerts
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Trigger for updated_at
CREATE TRIGGER set_outlier_config_updated_at
    BEFORE UPDATE ON gov_outlier_configurations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER set_outlier_disposition_updated_at
    BEFORE UPDATE ON gov_outlier_dispositions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
