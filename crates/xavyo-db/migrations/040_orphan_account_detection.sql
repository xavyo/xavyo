-- Migration: 040_orphan_account_detection
-- Feature: F040 - Orphan Account Detection
-- Description: Tables for orphan account detection, reconciliation, service accounts, and remediation

-- ============================================================================
-- ENUM TYPES
-- ============================================================================

-- Reconciliation run status
DO $$ BEGIN
    CREATE TYPE gov_reconciliation_status AS ENUM (
        'running',
        'completed',
        'failed',
        'partial'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Orphan detection reason
DO $$ BEGIN
    CREATE TYPE gov_detection_reason AS ENUM (
        'no_manager',
        'terminated_employee',
        'inactive',
        'hr_mismatch'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Orphan status
DO $$ BEGIN
    CREATE TYPE gov_orphan_status AS ENUM (
        'pending',
        'under_review',
        'remediated',
        'dismissed'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Remediation action type
DO $$ BEGIN
    CREATE TYPE gov_remediation_action AS ENUM (
        'reassign',
        'disable',
        'delete',
        'dismiss',
        'reopen'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Detection rule type
DO $$ BEGIN
    CREATE TYPE gov_detection_rule_type AS ENUM (
        'no_manager',
        'terminated',
        'inactive',
        'custom'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Service account status
DO $$ BEGIN
    CREATE TYPE gov_service_account_status AS ENUM (
        'active',
        'expired',
        'suspended'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- TABLES
-- ============================================================================

-- Reconciliation runs table
CREATE TABLE IF NOT EXISTS gov_reconciliation_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    status gov_reconciliation_status NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    total_accounts INTEGER NOT NULL DEFAULT 0,
    orphans_found INTEGER NOT NULL DEFAULT 0,
    new_orphans INTEGER NOT NULL DEFAULT 0,
    resolved_orphans INTEGER NOT NULL DEFAULT 0,
    triggered_by UUID,
    error_message TEXT,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_progress_percent CHECK (progress_percent >= 0 AND progress_percent <= 100),
    CONSTRAINT chk_counts_non_negative CHECK (total_accounts >= 0 AND orphans_found >= 0 AND new_orphans >= 0 AND resolved_orphans >= 0)
);

-- Orphan detections table
CREATE TABLE IF NOT EXISTS gov_orphan_detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    run_id UUID NOT NULL REFERENCES gov_reconciliation_runs(id) ON DELETE CASCADE,
    detection_reason gov_detection_reason NOT NULL,
    status gov_orphan_status NOT NULL DEFAULT 'pending',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMPTZ,
    days_inactive INTEGER,
    remediation_action gov_remediation_action,
    remediation_by UUID,
    remediation_at TIMESTAMPTZ,
    remediation_notes TEXT,
    new_owner_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_days_inactive_non_negative CHECK (days_inactive IS NULL OR days_inactive >= 0),
    CONSTRAINT chk_remediation_consistency CHECK (
        (remediation_action IS NULL AND remediation_at IS NULL) OR
        (remediation_action IS NOT NULL AND remediation_at IS NOT NULL)
    )
);

-- Detection rules table
CREATE TABLE IF NOT EXISTS gov_detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(100) NOT NULL,
    rule_type gov_detection_rule_type NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 100,
    parameters JSONB NOT NULL DEFAULT '{}',
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_priority_positive CHECK (priority > 0),
    CONSTRAINT uq_detection_rule_name UNIQUE (tenant_id, name)
);

-- Service accounts table
CREATE TABLE IF NOT EXISTS gov_service_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    name VARCHAR(200) NOT NULL,
    purpose TEXT NOT NULL,
    owner_id UUID NOT NULL,
    status gov_service_account_status NOT NULL DEFAULT 'active',
    expires_at TIMESTAMPTZ,
    last_certified_at TIMESTAMPTZ,
    certified_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_service_account_user UNIQUE (tenant_id, user_id)
);

-- Remediation logs table (audit trail)
CREATE TABLE IF NOT EXISTS gov_remediation_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    orphan_detection_id UUID NOT NULL REFERENCES gov_orphan_detections(id) ON DELETE CASCADE,
    action gov_remediation_action NOT NULL,
    performed_by UUID NOT NULL,
    performed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reconciliation schedule table
CREATE TABLE IF NOT EXISTS gov_reconciliation_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL UNIQUE,
    frequency VARCHAR(20) NOT NULL DEFAULT 'weekly',
    day_of_week INTEGER,
    day_of_month INTEGER,
    hour_of_day INTEGER NOT NULL DEFAULT 2,
    is_enabled BOOLEAN NOT NULL DEFAULT false,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_frequency CHECK (frequency IN ('daily', 'weekly', 'monthly')),
    CONSTRAINT chk_day_of_week CHECK (day_of_week IS NULL OR (day_of_week >= 0 AND day_of_week <= 6)),
    CONSTRAINT chk_day_of_month CHECK (day_of_month IS NULL OR (day_of_month >= 1 AND day_of_month <= 28)),
    CONSTRAINT chk_hour_of_day CHECK (hour_of_day >= 0 AND hour_of_day <= 23)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Reconciliation runs indexes
CREATE INDEX IF NOT EXISTS idx_gov_reconciliation_runs_tenant_id ON gov_reconciliation_runs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_reconciliation_runs_status ON gov_reconciliation_runs(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_reconciliation_runs_started_at ON gov_reconciliation_runs(tenant_id, started_at DESC);

-- Orphan detections indexes
CREATE INDEX IF NOT EXISTS idx_gov_orphan_detections_tenant_id ON gov_orphan_detections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_orphan_detections_status ON gov_orphan_detections(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_orphan_detections_user_id ON gov_orphan_detections(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_gov_orphan_detections_reason ON gov_orphan_detections(tenant_id, detection_reason);
CREATE INDEX IF NOT EXISTS idx_gov_orphan_detections_detected_at ON gov_orphan_detections(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_gov_orphan_detections_run_id ON gov_orphan_detections(run_id);

-- Detection rules indexes
CREATE INDEX IF NOT EXISTS idx_gov_detection_rules_tenant_id ON gov_detection_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_detection_rules_enabled ON gov_detection_rules(tenant_id, is_enabled);
CREATE INDEX IF NOT EXISTS idx_gov_detection_rules_priority ON gov_detection_rules(tenant_id, priority);

-- Service accounts indexes
CREATE INDEX IF NOT EXISTS idx_gov_service_accounts_tenant_id ON gov_service_accounts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_service_accounts_owner_id ON gov_service_accounts(tenant_id, owner_id);
CREATE INDEX IF NOT EXISTS idx_gov_service_accounts_expires_at ON gov_service_accounts(tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_gov_service_accounts_status ON gov_service_accounts(tenant_id, status);

-- Remediation logs indexes
CREATE INDEX IF NOT EXISTS idx_gov_remediation_logs_tenant_id ON gov_remediation_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_remediation_logs_orphan_detection_id ON gov_remediation_logs(orphan_detection_id);
CREATE INDEX IF NOT EXISTS idx_gov_remediation_logs_performed_at ON gov_remediation_logs(tenant_id, performed_at DESC);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE gov_reconciliation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_orphan_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_remediation_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_reconciliation_schedules ENABLE ROW LEVEL SECURITY;

-- RLS policies for gov_reconciliation_runs
DROP POLICY IF EXISTS gov_reconciliation_runs_tenant_isolation ON gov_reconciliation_runs;
CREATE POLICY gov_reconciliation_runs_tenant_isolation ON gov_reconciliation_runs
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_orphan_detections
DROP POLICY IF EXISTS gov_orphan_detections_tenant_isolation ON gov_orphan_detections;
CREATE POLICY gov_orphan_detections_tenant_isolation ON gov_orphan_detections
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_detection_rules
DROP POLICY IF EXISTS gov_detection_rules_tenant_isolation ON gov_detection_rules;
CREATE POLICY gov_detection_rules_tenant_isolation ON gov_detection_rules
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_service_accounts
DROP POLICY IF EXISTS gov_service_accounts_tenant_isolation ON gov_service_accounts;
CREATE POLICY gov_service_accounts_tenant_isolation ON gov_service_accounts
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_remediation_logs
DROP POLICY IF EXISTS gov_remediation_logs_tenant_isolation ON gov_remediation_logs;
CREATE POLICY gov_remediation_logs_tenant_isolation ON gov_remediation_logs
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_reconciliation_schedules
DROP POLICY IF EXISTS gov_reconciliation_schedules_tenant_isolation ON gov_reconciliation_schedules;
CREATE POLICY gov_reconciliation_schedules_tenant_isolation ON gov_reconciliation_schedules
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Updated_at trigger function (reuse if exists)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers
DROP TRIGGER IF EXISTS update_gov_reconciliation_runs_updated_at ON gov_reconciliation_runs;
CREATE TRIGGER update_gov_reconciliation_runs_updated_at
    BEFORE UPDATE ON gov_reconciliation_runs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_gov_orphan_detections_updated_at ON gov_orphan_detections;
CREATE TRIGGER update_gov_orphan_detections_updated_at
    BEFORE UPDATE ON gov_orphan_detections
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_gov_detection_rules_updated_at ON gov_detection_rules;
CREATE TRIGGER update_gov_detection_rules_updated_at
    BEFORE UPDATE ON gov_detection_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_gov_service_accounts_updated_at ON gov_service_accounts;
CREATE TRIGGER update_gov_service_accounts_updated_at
    BEFORE UPDATE ON gov_service_accounts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_gov_reconciliation_schedules_updated_at ON gov_reconciliation_schedules;
CREATE TRIGGER update_gov_reconciliation_schedules_updated_at
    BEFORE UPDATE ON gov_reconciliation_schedules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
