-- Migration: 046_schema_discovery.sql
-- Schema Discovery: versioning, diff, hierarchy, and scheduling

-- ============================================================================
-- Schema version snapshots (stores full schema per discovery run)
-- ============================================================================
CREATE TABLE connector_schema_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    version INT NOT NULL,
    schema_data JSONB NOT NULL,
    object_class_count INT NOT NULL DEFAULT 0,
    attribute_count INT NOT NULL DEFAULT 0,
    discovered_at TIMESTAMPTZ NOT NULL,
    discovery_duration_ms BIGINT NOT NULL DEFAULT 0,
    triggered_by VARCHAR(50) NOT NULL DEFAULT 'manual',
    triggered_by_user UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_connector_version UNIQUE (connector_id, version),
    CONSTRAINT check_version_positive CHECK (version >= 1),
    CONSTRAINT check_triggered_by CHECK (triggered_by IN ('manual', 'scheduled', 'api'))
);

-- Enable RLS
ALTER TABLE connector_schema_versions ENABLE ROW LEVEL SECURITY;

-- Drop-safe RLS policy (handles empty/missing tenant context)
CREATE POLICY tenant_isolation ON connector_schema_versions
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- Indexes for efficient queries
CREATE INDEX idx_schema_versions_connector ON connector_schema_versions(connector_id, version DESC);
CREATE INDEX idx_schema_versions_discovered ON connector_schema_versions(connector_id, discovered_at DESC);
CREATE INDEX idx_schema_versions_tenant ON connector_schema_versions(tenant_id);

-- ============================================================================
-- Refresh schedules (automatic discovery configuration)
-- ============================================================================
CREATE TABLE schema_refresh_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    schedule_type VARCHAR(20) NOT NULL DEFAULT 'interval',
    interval_hours INT,
    cron_expression VARCHAR(100),
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    last_error TEXT,
    notify_on_changes BOOLEAN NOT NULL DEFAULT false,
    notify_email VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_schedule_per_connector UNIQUE (connector_id),
    CONSTRAINT check_schedule_type CHECK (schedule_type IN ('interval', 'cron')),
    CONSTRAINT check_interval_positive CHECK (interval_hours IS NULL OR interval_hours >= 1)
);

-- Enable RLS
ALTER TABLE schema_refresh_schedules ENABLE ROW LEVEL SECURITY;

-- Drop-safe RLS policy
CREATE POLICY tenant_isolation ON schema_refresh_schedules
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- Indexes for scheduler queries
CREATE INDEX idx_schedules_next_run ON schema_refresh_schedules(enabled, next_run_at)
    WHERE enabled = true AND next_run_at IS NOT NULL;
CREATE INDEX idx_schedules_connector ON schema_refresh_schedules(connector_id);
CREATE INDEX idx_schedules_tenant ON schema_refresh_schedules(tenant_id);

-- Trigger for updated_at
CREATE TRIGGER trigger_schema_refresh_schedules_updated_at
    BEFORE UPDATE ON schema_refresh_schedules
    FOR EACH ROW EXECUTE FUNCTION update_connector_updated_at();

-- ============================================================================
-- Function to get next version number (atomic)
-- ============================================================================
CREATE OR REPLACE FUNCTION get_next_schema_version(p_connector_id UUID)
RETURNS INT AS $$
DECLARE
    next_version INT;
BEGIN
    SELECT COALESCE(MAX(version), 0) + 1 INTO next_version
    FROM connector_schema_versions
    WHERE connector_id = p_connector_id;
    RETURN next_version;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Function to clean up old schema versions (keep last N)
-- ============================================================================
CREATE OR REPLACE FUNCTION cleanup_old_schema_versions(p_connector_id UUID, p_keep_count INT DEFAULT 10)
RETURNS INT AS $$
DECLARE
    deleted_count INT;
BEGIN
    WITH versions_to_delete AS (
        SELECT id
        FROM connector_schema_versions
        WHERE connector_id = p_connector_id
        ORDER BY version DESC
        OFFSET p_keep_count
    )
    DELETE FROM connector_schema_versions
    WHERE id IN (SELECT id FROM versions_to_delete);

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
