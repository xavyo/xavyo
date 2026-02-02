-- Migration: 048_live_synchronization.sql
-- Live Synchronization - Real-time change detection from external systems

-- ============================================================================
-- 1. Create gov_sync_configurations table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_sync_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    sync_mode VARCHAR(20) NOT NULL DEFAULT 'polling',
    polling_interval_secs INTEGER NOT NULL DEFAULT 60,
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 1000,
    batch_size INTEGER NOT NULL DEFAULT 100,
    conflict_resolution VARCHAR(20) NOT NULL DEFAULT 'inbound_wins',
    auto_create_identity BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_sync_config_per_connector UNIQUE (tenant_id, connector_id),
    CONSTRAINT check_sync_mode CHECK (sync_mode IN ('polling', 'event', 'hybrid')),
    CONSTRAINT check_polling_interval CHECK (polling_interval_secs BETWEEN 1 AND 3600),
    CONSTRAINT check_rate_limit CHECK (rate_limit_per_minute BETWEEN 1 AND 100000),
    CONSTRAINT check_batch_size CHECK (batch_size BETWEEN 1 AND 10000),
    CONSTRAINT check_conflict_resolution CHECK (conflict_resolution IN ('inbound_wins', 'outbound_wins', 'merge', 'manual'))
);

ALTER TABLE gov_sync_configurations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_sync_configurations
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_sync_configs_tenant ON gov_sync_configurations(tenant_id);
CREATE INDEX idx_sync_configs_enabled ON gov_sync_configurations(tenant_id, connector_id) WHERE enabled = true;

-- ============================================================================
-- 2. Create gov_sync_tokens table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_sync_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    token_value TEXT NOT NULL,
    token_type VARCHAR(20) NOT NULL DEFAULT 'batch',
    sequence_number BIGINT NOT NULL DEFAULT 0,
    last_processed_at TIMESTAMPTZ,
    is_valid BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_sync_token_per_connector UNIQUE (tenant_id, connector_id),
    CONSTRAINT check_token_type CHECK (token_type IN ('precise', 'batch'))
);

ALTER TABLE gov_sync_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_sync_tokens
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_sync_tokens_tenant ON gov_sync_tokens(tenant_id);

-- ============================================================================
-- 3. Create gov_inbound_changes table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_inbound_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    change_type VARCHAR(20) NOT NULL,
    external_uid VARCHAR(1024) NOT NULL,
    object_class VARCHAR(100) NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}',
    sync_situation VARCHAR(20) NOT NULL,
    correlation_result JSONB,
    linked_identity_id UUID REFERENCES users(id) ON DELETE SET NULL,
    conflict_id UUID,
    processing_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_change_type CHECK (change_type IN ('create', 'update', 'delete')),
    CONSTRAINT check_sync_situation CHECK (sync_situation IN ('linked', 'unlinked', 'unmatched', 'disputed', 'deleted', 'collision')),
    CONSTRAINT check_processing_status CHECK (processing_status IN ('pending', 'processing', 'completed', 'failed', 'conflict'))
);

ALTER TABLE gov_inbound_changes ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_inbound_changes
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_inbound_changes_queue ON gov_inbound_changes(tenant_id, connector_id, processing_status);
CREATE INDEX idx_inbound_changes_external_uid ON gov_inbound_changes(tenant_id, connector_id, external_uid);
CREATE INDEX idx_inbound_changes_created ON gov_inbound_changes(tenant_id, created_at DESC);
CREATE INDEX idx_inbound_changes_situation ON gov_inbound_changes(tenant_id, sync_situation) WHERE processing_status = 'pending';

-- ============================================================================
-- 4. Create gov_sync_conflicts table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_sync_conflicts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    inbound_change_id UUID NOT NULL REFERENCES gov_inbound_changes(id) ON DELETE CASCADE,
    outbound_operation_id UUID REFERENCES provisioning_operations(id) ON DELETE SET NULL,
    conflict_type VARCHAR(30) NOT NULL,
    affected_attributes TEXT[] NOT NULL DEFAULT '{}',
    inbound_value JSONB NOT NULL,
    outbound_value JSONB,
    resolution_strategy VARCHAR(20) NOT NULL DEFAULT 'pending',
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_sync_conflict_type CHECK (conflict_type IN ('concurrent_update', 'stale_data', 'attribute_conflict', 'identity_mismatch')),
    CONSTRAINT check_sync_resolution_strategy CHECK (resolution_strategy IN ('inbound_wins', 'outbound_wins', 'merge', 'manual', 'pending'))
);

ALTER TABLE gov_sync_conflicts ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_sync_conflicts
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_sync_conflicts_inbound ON gov_sync_conflicts(inbound_change_id);
CREATE INDEX idx_sync_conflicts_pending ON gov_sync_conflicts(tenant_id) WHERE resolution_strategy = 'pending';
CREATE INDEX idx_sync_conflicts_created ON gov_sync_conflicts(tenant_id, created_at DESC);

-- Add FK from inbound_changes to sync_conflicts after sync_conflicts is created
ALTER TABLE gov_inbound_changes
ADD CONSTRAINT fk_inbound_change_conflict FOREIGN KEY (conflict_id) REFERENCES gov_sync_conflicts(id) ON DELETE SET NULL;

-- ============================================================================
-- 5. Create gov_sync_status table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_sync_status (
    connector_id UUID PRIMARY KEY REFERENCES connector_configurations(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    current_state VARCHAR(20) NOT NULL DEFAULT 'idle',
    last_sync_started_at TIMESTAMPTZ,
    last_sync_completed_at TIMESTAMPTZ,
    last_sync_error TEXT,
    changes_processed BIGINT NOT NULL DEFAULT 0,
    changes_pending INTEGER NOT NULL DEFAULT 0,
    conflicts_pending INTEGER NOT NULL DEFAULT 0,
    current_rate DECIMAL(10,2) NOT NULL DEFAULT 0,
    is_throttled BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_current_state CHECK (current_state IN ('idle', 'syncing', 'paused', 'error', 'throttled'))
);

ALTER TABLE gov_sync_status ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_sync_status
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_sync_status_tenant ON gov_sync_status(tenant_id);

-- ============================================================================
-- 6. Add direction column to attribute_mappings
-- ============================================================================

ALTER TABLE attribute_mappings
ADD COLUMN IF NOT EXISTS direction VARCHAR(15) NOT NULL DEFAULT 'outbound';

ALTER TABLE attribute_mappings
DROP CONSTRAINT IF EXISTS check_mapping_direction;

ALTER TABLE attribute_mappings
ADD CONSTRAINT check_mapping_direction CHECK (direction IN ('inbound', 'outbound', 'bidirectional'));

CREATE INDEX IF NOT EXISTS idx_mappings_direction ON attribute_mappings(tenant_id, connector_id, direction);

-- ============================================================================
-- 7. Add updated_at triggers
-- ============================================================================

-- Reuse existing trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_sync_configs_updated_at
    BEFORE UPDATE ON gov_sync_configurations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sync_tokens_updated_at
    BEFORE UPDATE ON gov_sync_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sync_status_updated_at
    BEFORE UPDATE ON gov_sync_status
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 8. Comments
-- ============================================================================

COMMENT ON TABLE gov_sync_configurations IS 'Per-connector settings for live synchronization including polling interval, rate limits, and conflict resolution strategy';

COMMENT ON TABLE gov_sync_tokens IS 'Persisted synchronization progress tokens for resumable sync across service restarts';

COMMENT ON TABLE gov_inbound_changes IS 'Detected changes from external systems pending processing or completed';

COMMENT ON TABLE gov_sync_conflicts IS 'Conflicts detected between inbound changes and pending outbound operations';

COMMENT ON TABLE gov_sync_status IS 'Real-time synchronization status per connector including metrics and state';

COMMENT ON COLUMN attribute_mappings.direction IS 'Mapping direction: inbound (external->internal), outbound (internal->external), or bidirectional';
