-- Migration: 049_reconciliation_engine.sql
-- Reconciliation Engine - Heavy-weight reliable comparison between xavyo and target systems

-- ============================================================================
-- 1. Create gov_connector_reconciliation_runs table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_connector_reconciliation_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    mode VARCHAR(10) NOT NULL DEFAULT 'full',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    checkpoint JSONB,
    statistics JSONB NOT NULL DEFAULT '{}',
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_recon_mode CHECK (mode IN ('full', 'delta')),
    CONSTRAINT check_recon_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))
);

ALTER TABLE gov_connector_reconciliation_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_connector_reconciliation_runs
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_connector_recon_runs_tenant_connector ON gov_connector_reconciliation_runs(tenant_id, connector_id);
CREATE INDEX idx_connector_recon_runs_status ON gov_connector_reconciliation_runs(tenant_id, status);
CREATE INDEX idx_connector_recon_runs_created ON gov_connector_reconciliation_runs(tenant_id, created_at DESC);
-- Ensure only one running reconciliation per connector
CREATE UNIQUE INDEX idx_connector_recon_runs_unique_running
    ON gov_connector_reconciliation_runs(tenant_id, connector_id)
    WHERE status = 'running';

-- ============================================================================
-- 2. Create gov_reconciliation_discrepancies table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_reconciliation_discrepancies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID NOT NULL REFERENCES gov_connector_reconciliation_runs(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    discrepancy_type VARCHAR(20) NOT NULL,
    identity_id UUID REFERENCES users(id) ON DELETE SET NULL,
    external_uid VARCHAR(500) NOT NULL,
    mismatched_attributes JSONB,
    resolution_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    resolved_action VARCHAR(30),
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_discrepancy_type CHECK (discrepancy_type IN ('missing', 'orphan', 'mismatch', 'collision', 'unlinked', 'deleted')),
    CONSTRAINT check_resolution_status CHECK (resolution_status IN ('pending', 'resolved', 'ignored')),
    CONSTRAINT check_resolved_action CHECK (resolved_action IS NULL OR resolved_action IN ('create', 'update', 'delete', 'link', 'unlink', 'inactivate_identity'))
);

ALTER TABLE gov_reconciliation_discrepancies ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_reconciliation_discrepancies
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_recon_discrepancy_run ON gov_reconciliation_discrepancies(run_id);
CREATE INDEX idx_recon_discrepancy_type ON gov_reconciliation_discrepancies(tenant_id, discrepancy_type);
CREATE INDEX idx_recon_discrepancy_status ON gov_reconciliation_discrepancies(tenant_id, resolution_status);
CREATE INDEX idx_recon_discrepancy_identity ON gov_reconciliation_discrepancies(tenant_id, identity_id) WHERE identity_id IS NOT NULL;
CREATE INDEX idx_recon_discrepancy_external ON gov_reconciliation_discrepancies(tenant_id, external_uid);

-- ============================================================================
-- 3. Create gov_reconciliation_schedules table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_reconciliation_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    mode VARCHAR(10) NOT NULL DEFAULT 'full',
    frequency VARCHAR(50) NOT NULL,
    day_of_week INTEGER,
    day_of_month INTEGER,
    hour_of_day INTEGER NOT NULL DEFAULT 2,
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_run_id UUID REFERENCES gov_connector_reconciliation_runs(id) ON DELETE SET NULL,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_recon_schedule_per_connector UNIQUE (tenant_id, connector_id),
    CONSTRAINT check_schedule_mode CHECK (mode IN ('full', 'delta')),
    CONSTRAINT check_day_of_week CHECK (day_of_week IS NULL OR (day_of_week >= 0 AND day_of_week <= 6)),
    CONSTRAINT check_day_of_month CHECK (day_of_month IS NULL OR (day_of_month >= 1 AND day_of_month <= 28)),
    CONSTRAINT check_hour_of_day CHECK (hour_of_day >= 0 AND hour_of_day <= 23)
);

ALTER TABLE gov_reconciliation_schedules ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_reconciliation_schedules
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- Note: Use is_enabled for compatibility with existing table from 040_orphan_account_detection.sql
-- The table from 040 uses is_enabled, while this migration defines enabled - IF NOT EXISTS preserves the old schema
CREATE INDEX IF NOT EXISTS idx_recon_schedule_next ON gov_reconciliation_schedules(next_run_at) WHERE is_enabled = true;
CREATE INDEX idx_recon_schedule_tenant ON gov_reconciliation_schedules(tenant_id);

-- ============================================================================
-- 4. Create gov_reconciliation_actions table (audit log)
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_reconciliation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    discrepancy_id UUID NOT NULL REFERENCES gov_reconciliation_discrepancies(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action_type VARCHAR(30) NOT NULL,
    executed_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    result VARCHAR(10) NOT NULL,
    error_message TEXT,
    before_state JSONB,
    after_state JSONB,
    dry_run BOOLEAN NOT NULL DEFAULT false,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_action_type CHECK (action_type IN ('create', 'update', 'delete', 'link', 'unlink', 'inactivate_identity')),
    CONSTRAINT check_action_result CHECK (result IN ('success', 'failure'))
);

ALTER TABLE gov_reconciliation_actions ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_reconciliation_actions
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_recon_action_discrepancy ON gov_reconciliation_actions(discrepancy_id);
CREATE INDEX idx_recon_action_executed ON gov_reconciliation_actions(tenant_id, executed_at DESC);
CREATE INDEX idx_recon_action_type ON gov_reconciliation_actions(tenant_id, action_type);

-- ============================================================================
-- 5. Add updated_at triggers
-- ============================================================================

CREATE TRIGGER update_connector_recon_runs_updated_at
    BEFORE UPDATE ON gov_connector_reconciliation_runs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_recon_schedules_updated_at
    BEFORE UPDATE ON gov_reconciliation_schedules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 6. Comments
-- ============================================================================

COMMENT ON TABLE gov_connector_reconciliation_runs IS 'Records of reconciliation executions against connectors, tracking status, progress, and statistics';

COMMENT ON TABLE gov_reconciliation_discrepancies IS 'Detected differences between xavyo and target systems including type, affected entities, and resolution status';

COMMENT ON TABLE gov_reconciliation_schedules IS 'Configuration for automatic recurring reconciliation runs per connector';

COMMENT ON TABLE gov_reconciliation_actions IS 'Audit log of remediation actions executed to resolve discrepancies';

COMMENT ON COLUMN gov_connector_reconciliation_runs.checkpoint IS 'Serialized progress state for resumption: {phase, last_key, accounts_processed, batch_number}';

COMMENT ON COLUMN gov_connector_reconciliation_runs.statistics IS 'Aggregated statistics: {accounts_total, accounts_processed, discrepancies_found, discrepancies_by_type, actions_taken, duration_seconds}';

COMMENT ON COLUMN gov_reconciliation_discrepancies.mismatched_attributes IS 'For mismatch type: {attribute_name: {xavyo: value, target: value}}';

COMMENT ON COLUMN gov_reconciliation_schedules.frequency IS 'Schedule frequency: hourly, daily, weekly, monthly, or cron expression';
