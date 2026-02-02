-- Migration: 039_identity_risk_scoring
-- Feature: F039 Identity Risk Scoring
-- Description: Tables for risk scoring, factors, events, alerts, and peer groups

-- Create custom types for risk scoring
DO $$ BEGIN
    CREATE TYPE risk_factor_category AS ENUM ('static', 'dynamic');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE risk_level AS ENUM ('low', 'medium', 'high', 'critical');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE alert_severity AS ENUM ('info', 'warning', 'critical');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE threshold_action AS ENUM ('alert', 'require_mfa', 'block');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE peer_group_type AS ENUM ('department', 'role', 'location', 'custom');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- =============================================================================
-- gov_risk_factors: Configurable risk indicators with weights
-- =============================================================================
CREATE TABLE IF NOT EXISTS gov_risk_factors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    category risk_factor_category NOT NULL,
    factor_type VARCHAR(50) NOT NULL,
    weight DECIMAL(4,2) NOT NULL CHECK (weight >= 0 AND weight <= 10),
    description TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_risk_factor_name_per_tenant UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_risk_factors_tenant_enabled
    ON gov_risk_factors(tenant_id, is_enabled);
CREATE INDEX IF NOT EXISTS idx_risk_factors_tenant_category
    ON gov_risk_factors(tenant_id, category);

-- =============================================================================
-- gov_risk_events: Individual events contributing to risk scores
-- =============================================================================
CREATE TABLE IF NOT EXISTS gov_risk_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    factor_id UUID REFERENCES gov_risk_factors(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    value DECIMAL(10,2) NOT NULL DEFAULT 1,
    source_ref VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_risk_events_tenant_user
    ON gov_risk_events(tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_expires
    ON gov_risk_events(tenant_id, expires_at) WHERE expires_at IS NOT NULL;

-- =============================================================================
-- gov_risk_scores: Current calculated risk score per user
-- =============================================================================
CREATE TABLE IF NOT EXISTS gov_risk_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    total_score INTEGER NOT NULL CHECK (total_score >= 0 AND total_score <= 100),
    risk_level risk_level NOT NULL,
    static_score INTEGER NOT NULL DEFAULT 0,
    dynamic_score INTEGER NOT NULL DEFAULT 0,
    factor_breakdown JSONB NOT NULL DEFAULT '{}',
    peer_comparison JSONB,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_risk_score_user_per_tenant UNIQUE (tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_risk_scores_tenant_level
    ON gov_risk_scores(tenant_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_risk_scores_tenant_score
    ON gov_risk_scores(tenant_id, total_score DESC);

-- =============================================================================
-- gov_risk_score_history: Historical snapshots for trend analysis
-- =============================================================================
CREATE TABLE IF NOT EXISTS gov_risk_score_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
    risk_level risk_level NOT NULL,
    snapshot_date DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_risk_history_user_date UNIQUE (tenant_id, user_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_risk_history_tenant_date
    ON gov_risk_score_history(tenant_id, snapshot_date);
CREATE INDEX IF NOT EXISTS idx_risk_history_tenant_user
    ON gov_risk_score_history(tenant_id, user_id, snapshot_date DESC);

-- =============================================================================
-- gov_risk_thresholds: Configurable thresholds for alerting
-- =============================================================================
CREATE TABLE IF NOT EXISTS gov_risk_thresholds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    score_value INTEGER NOT NULL CHECK (score_value >= 1 AND score_value <= 100),
    severity alert_severity NOT NULL,
    action threshold_action NOT NULL DEFAULT 'alert',
    cooldown_hours INTEGER NOT NULL DEFAULT 24 CHECK (cooldown_hours >= 1 AND cooldown_hours <= 720),
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_thresholds_tenant_score
    ON gov_risk_thresholds(tenant_id, score_value);
CREATE INDEX IF NOT EXISTS idx_risk_thresholds_tenant_enabled
    ON gov_risk_thresholds(tenant_id, is_enabled);

-- =============================================================================
-- gov_risk_alerts: Generated alerts when thresholds exceeded
-- =============================================================================
CREATE TABLE IF NOT EXISTS gov_risk_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    threshold_id UUID NOT NULL REFERENCES gov_risk_thresholds(id) ON DELETE CASCADE,
    score_at_alert INTEGER NOT NULL,
    severity alert_severity NOT NULL,
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_alerts_tenant_user
    ON gov_risk_alerts(tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_alerts_tenant_ack
    ON gov_risk_alerts(tenant_id, acknowledged, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_alerts_dedup
    ON gov_risk_alerts(tenant_id, user_id, threshold_id, created_at DESC);

-- =============================================================================
-- gov_peer_groups: Peer groups for outlier detection
-- =============================================================================
CREATE TABLE IF NOT EXISTS gov_peer_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    group_type peer_group_type NOT NULL,
    attribute_key VARCHAR(100) NOT NULL,
    attribute_value VARCHAR(255) NOT NULL,
    user_count INTEGER NOT NULL DEFAULT 0,
    avg_entitlements DECIMAL(10,2),
    stddev_entitlements DECIMAL(10,2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_peer_group_attr UNIQUE (tenant_id, group_type, attribute_value)
);

CREATE INDEX IF NOT EXISTS idx_peer_groups_tenant_type
    ON gov_peer_groups(tenant_id, group_type);

-- =============================================================================
-- gov_peer_group_members: User membership in peer groups
-- =============================================================================
CREATE TABLE IF NOT EXISTS gov_peer_group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES gov_peer_groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_peer_group_member UNIQUE (tenant_id, group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_peer_members_tenant_user
    ON gov_peer_group_members(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_peer_members_group
    ON gov_peer_group_members(group_id);

-- =============================================================================
-- Row Level Security Policies
-- =============================================================================

-- Enable RLS on all tables
ALTER TABLE gov_risk_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_risk_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_risk_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_risk_score_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_risk_thresholds ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_risk_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_peer_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_peer_group_members ENABLE ROW LEVEL SECURITY;

-- RLS policies for tenant isolation
CREATE POLICY risk_factors_tenant_isolation ON gov_risk_factors
    FOR ALL USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY risk_events_tenant_isolation ON gov_risk_events
    FOR ALL USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY risk_scores_tenant_isolation ON gov_risk_scores
    FOR ALL USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY risk_history_tenant_isolation ON gov_risk_score_history
    FOR ALL USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY risk_thresholds_tenant_isolation ON gov_risk_thresholds
    FOR ALL USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY risk_alerts_tenant_isolation ON gov_risk_alerts
    FOR ALL USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY peer_groups_tenant_isolation ON gov_peer_groups
    FOR ALL USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY peer_members_tenant_isolation ON gov_peer_group_members
    FOR ALL USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- =============================================================================
-- Updated_at trigger function (reuse if exists)
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at triggers
DROP TRIGGER IF EXISTS update_risk_factors_updated_at ON gov_risk_factors;
CREATE TRIGGER update_risk_factors_updated_at
    BEFORE UPDATE ON gov_risk_factors
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_risk_scores_updated_at ON gov_risk_scores;
CREATE TRIGGER update_risk_scores_updated_at
    BEFORE UPDATE ON gov_risk_scores
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_risk_thresholds_updated_at ON gov_risk_thresholds;
CREATE TRIGGER update_risk_thresholds_updated_at
    BEFORE UPDATE ON gov_risk_thresholds
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_peer_groups_updated_at ON gov_peer_groups;
CREATE TRIGGER update_peer_groups_updated_at
    BEFORE UPDATE ON gov_peer_groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
