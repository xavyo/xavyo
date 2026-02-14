-- F067: Correlation Engine
-- Extends gov_correlation_rules (F062) and adds correlation cases, candidates, thresholds, and audit events

-- Enable pg_trgm for fuzzy string matching at database level
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Add 'expression' variant to gov_match_type enum
ALTER TYPE gov_match_type ADD VALUE IF NOT EXISTS 'expression';

-- Extend gov_correlation_rules table with F067 columns
ALTER TABLE gov_correlation_rules
    ADD COLUMN IF NOT EXISTS connector_id UUID REFERENCES connector_configurations(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS source_attribute VARCHAR(255),
    ADD COLUMN IF NOT EXISTS target_attribute VARCHAR(255),
    ADD COLUMN IF NOT EXISTS expression TEXT,
    ADD COLUMN IF NOT EXISTS tier INT,
    ADD COLUMN IF NOT EXISTS is_definitive BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS normalize BOOLEAN NOT NULL DEFAULT true;

-- Index for connector-scoped rule lookups
CREATE INDEX IF NOT EXISTS idx_corr_rules_connector ON gov_correlation_rules(tenant_id, connector_id)
    WHERE connector_id IS NOT NULL;

-- Correlation thresholds per connector
CREATE TABLE IF NOT EXISTS gov_correlation_thresholds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    auto_confirm_threshold DECIMAL(5,4) NOT NULL DEFAULT 0.8500,
    manual_review_threshold DECIMAL(5,4) NOT NULL DEFAULT 0.5000,
    tuning_mode BOOLEAN NOT NULL DEFAULT false,
    include_deactivated BOOLEAN NOT NULL DEFAULT true,
    batch_size INT NOT NULL DEFAULT 500,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, connector_id),
    CONSTRAINT chk_threshold_order CHECK (auto_confirm_threshold > manual_review_threshold),
    CONSTRAINT chk_auto_confirm_range CHECK (auto_confirm_threshold BETWEEN 0.0 AND 1.0),
    CONSTRAINT chk_manual_review_range CHECK (manual_review_threshold BETWEEN 0.0 AND 1.0),
    CONSTRAINT chk_batch_size_range CHECK (batch_size BETWEEN 50 AND 5000)
);

-- Enum types for correlation cases
DO $$ BEGIN
    CREATE TYPE gov_correlation_case_status AS ENUM (
        'pending', 'confirmed', 'rejected', 'no_match', 'new_identity', 'collision'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE gov_correlation_trigger AS ENUM (
        'reconciliation', 'live_sync', 'manual'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Correlation cases (review queue)
CREATE TABLE IF NOT EXISTS gov_correlation_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    account_id UUID NOT NULL,
    account_identifier VARCHAR(512) NOT NULL,
    account_attributes JSONB NOT NULL DEFAULT '{}',
    status gov_correlation_case_status NOT NULL DEFAULT 'pending',
    trigger_type gov_correlation_trigger NOT NULL,
    highest_confidence DECIMAL(5,4) NOT NULL DEFAULT 0.0,
    candidate_count INT NOT NULL DEFAULT 0,
    resolved_by UUID,
    resolved_at TIMESTAMPTZ,
    resolution_reason TEXT,
    resolution_candidate_id UUID,
    assigned_to UUID,
    rules_snapshot JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_corr_cases_tenant_status ON gov_correlation_cases(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_corr_cases_tenant_connector ON gov_correlation_cases(tenant_id, connector_id);
CREATE INDEX IF NOT EXISTS idx_corr_cases_account ON gov_correlation_cases(tenant_id, account_id);
CREATE INDEX IF NOT EXISTS idx_corr_cases_created_at ON gov_correlation_cases(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_corr_cases_assigned ON gov_correlation_cases(tenant_id, assigned_to) WHERE assigned_to IS NOT NULL;

-- Correlation candidates (identity matches per case)
CREATE TABLE IF NOT EXISTS gov_correlation_candidates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES gov_correlation_cases(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL,
    identity_display_name VARCHAR(512),
    identity_attributes JSONB NOT NULL DEFAULT '{}',
    aggregate_confidence DECIMAL(5,4) NOT NULL DEFAULT 0.0,
    per_attribute_scores JSONB NOT NULL DEFAULT '[]',
    is_deactivated BOOLEAN NOT NULL DEFAULT false,
    is_definitive_match BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_corr_candidates_case ON gov_correlation_candidates(case_id);
CREATE INDEX IF NOT EXISTS idx_corr_candidates_identity ON gov_correlation_candidates(identity_id);
CREATE INDEX IF NOT EXISTS idx_corr_candidates_confidence ON gov_correlation_candidates(case_id, aggregate_confidence DESC);

-- Enum types for audit events
DO $$ BEGIN
    CREATE TYPE gov_correlation_event_type AS ENUM (
        'auto_evaluated', 'manual_reviewed', 'case_created', 'case_reassigned', 'rules_changed'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE gov_correlation_outcome AS ENUM (
        'auto_confirmed', 'manual_confirmed', 'manual_rejected', 'new_identity_created',
        'no_match', 'collision_detected', 'deferred_to_review'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Correlation audit events
CREATE TABLE IF NOT EXISTS gov_correlation_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    account_id UUID,
    case_id UUID REFERENCES gov_correlation_cases(id) ON DELETE SET NULL,
    identity_id UUID,
    event_type gov_correlation_event_type NOT NULL,
    outcome gov_correlation_outcome NOT NULL,
    confidence_score DECIMAL(5,4),
    candidate_count INT NOT NULL DEFAULT 0,
    candidates_summary JSONB NOT NULL DEFAULT '[]',
    rules_snapshot JSONB NOT NULL DEFAULT '[]',
    thresholds_snapshot JSONB NOT NULL DEFAULT '{}',
    actor_type VARCHAR(50) NOT NULL,
    actor_id UUID,
    reason TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_corr_audit_tenant_created ON gov_correlation_audit_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_corr_audit_connector ON gov_correlation_audit_events(tenant_id, connector_id);
CREATE INDEX IF NOT EXISTS idx_corr_audit_event_type ON gov_correlation_audit_events(tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_corr_audit_outcome ON gov_correlation_audit_events(tenant_id, outcome);

-- RLS policies for tenant isolation
ALTER TABLE gov_correlation_thresholds ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_correlation_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_correlation_audit_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_corr_thresholds ON gov_correlation_thresholds;
CREATE POLICY tenant_isolation_corr_thresholds ON gov_correlation_thresholds
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
DROP POLICY IF EXISTS tenant_isolation_corr_cases ON gov_correlation_cases;
CREATE POLICY tenant_isolation_corr_cases ON gov_correlation_cases
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
DROP POLICY IF EXISTS tenant_isolation_corr_audit ON gov_correlation_audit_events;
CREATE POLICY tenant_isolation_corr_audit ON gov_correlation_audit_events
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
