-- Migration: 044_connector_framework.sql
-- Connector Framework for external system provisioning

-- Connector configurations
CREATE TABLE connector_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    connector_type VARCHAR(50) NOT NULL,
    description TEXT,
    config JSONB NOT NULL,
    credentials_encrypted BYTEA NOT NULL,
    credentials_key_version INT NOT NULL DEFAULT 1,
    status VARCHAR(20) NOT NULL DEFAULT 'inactive',
    last_connection_test TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_connector_name_per_tenant UNIQUE (tenant_id, name),
    CONSTRAINT check_connector_type CHECK (connector_type IN ('ldap', 'database', 'rest')),
    CONSTRAINT check_connector_status CHECK (status IN ('active', 'inactive', 'error'))
);

-- Enable RLS
ALTER TABLE connector_configurations ENABLE ROW LEVEL SECURITY;

-- Drop-safe RLS policy (handles empty/missing tenant context)
CREATE POLICY tenant_isolation ON connector_configurations
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- Indexes
CREATE INDEX idx_connectors_tenant_id ON connector_configurations(tenant_id);
CREATE INDEX idx_connectors_tenant_type ON connector_configurations(tenant_id, connector_type);
CREATE INDEX idx_connectors_status ON connector_configurations(tenant_id, status);

-- Connector schemas (cached discovery results)
CREATE TABLE connector_schemas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    object_class VARCHAR(255) NOT NULL,
    native_name VARCHAR(255) NOT NULL,
    attributes JSONB NOT NULL,
    supports_create BOOLEAN NOT NULL DEFAULT true,
    supports_update BOOLEAN NOT NULL DEFAULT true,
    supports_delete BOOLEAN NOT NULL DEFAULT true,
    discovered_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_schema_per_connector UNIQUE (connector_id, object_class)
);

ALTER TABLE connector_schemas ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON connector_schemas
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_schemas_connector ON connector_schemas(connector_id);
CREATE INDEX idx_schemas_expiry ON connector_schemas(expires_at);

-- Attribute mappings
CREATE TABLE attribute_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    object_class VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT false,
    mappings JSONB NOT NULL,
    correlation_rule JSONB,
    deprovision_action VARCHAR(20) NOT NULL DEFAULT 'disable',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_deprovision_action CHECK (deprovision_action IN ('disable', 'delete'))
);

ALTER TABLE attribute_mappings ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON attribute_mappings
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_mappings_connector ON attribute_mappings(connector_id, object_class);
CREATE INDEX idx_mappings_default ON attribute_mappings(connector_id, object_class) WHERE is_default = true;

-- Partial unique index to ensure only one default mapping per connector+object_class
CREATE UNIQUE INDEX unique_default_mapping_per_connector_object_class
    ON attribute_mappings(connector_id, object_class)
    WHERE is_default = true;

-- Provisioning operations (queue)
CREATE TABLE provisioning_operations (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id),
    user_id UUID NOT NULL,
    object_class VARCHAR(255) NOT NULL,
    operation_type VARCHAR(20) NOT NULL,
    target_uid VARCHAR(255),
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    priority INT NOT NULL DEFAULT 0,
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ,
    error_message TEXT,
    error_code VARCHAR(50),
    is_transient_error BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT check_operation_type CHECK (operation_type IN ('create', 'update', 'delete')),
    CONSTRAINT check_operation_status CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'dead_letter')),
    CONSTRAINT check_max_retries CHECK (max_retries >= 0 AND max_retries <= 10)
);

ALTER TABLE provisioning_operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON provisioning_operations
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_operations_tenant_status ON provisioning_operations(tenant_id, status);
CREATE INDEX idx_operations_connector_status ON provisioning_operations(connector_id, status);
CREATE INDEX idx_operations_user ON provisioning_operations(user_id);
CREATE INDEX idx_operations_retry ON provisioning_operations(next_retry_at)
    WHERE status = 'pending' AND next_retry_at IS NOT NULL;
CREATE INDEX idx_operations_created ON provisioning_operations(created_at DESC);
CREATE INDEX idx_operations_priority ON provisioning_operations(priority DESC, created_at ASC)
    WHERE status = 'pending';

-- Operation logs (audit trail)
CREATE TABLE operation_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL REFERENCES provisioning_operations(id),
    connector_id UUID NOT NULL,
    user_id UUID,
    operation_type VARCHAR(20) NOT NULL,
    target_uid VARCHAR(255),
    status VARCHAR(20) NOT NULL,
    duration_ms INT,
    request_payload JSONB,
    response_summary JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_log_status CHECK (status IN ('success', 'failure'))
);

ALTER TABLE operation_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON operation_logs
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_operation_logs_tenant_created ON operation_logs(tenant_id, created_at DESC);
CREATE INDEX idx_operation_logs_operation ON operation_logs(operation_id);
CREATE INDEX idx_operation_logs_user ON operation_logs(user_id, created_at DESC);
CREATE INDEX idx_operation_logs_connector ON operation_logs(connector_id, created_at DESC);

-- Connector health (real-time metrics)
CREATE TABLE connector_health (
    connector_id UUID PRIMARY KEY REFERENCES connector_configurations(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'disconnected',
    last_check_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consecutive_failures INT NOT NULL DEFAULT 0,
    circuit_state VARCHAR(20) NOT NULL DEFAULT 'closed',
    circuit_opened_at TIMESTAMPTZ,
    operations_pending INT NOT NULL DEFAULT 0,
    operations_completed_24h INT NOT NULL DEFAULT 0,
    operations_failed_24h INT NOT NULL DEFAULT 0,
    avg_latency_ms INT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_health_status CHECK (status IN ('connected', 'degraded', 'disconnected')),
    CONSTRAINT check_circuit_state CHECK (circuit_state IN ('closed', 'open', 'half_open'))
);

ALTER TABLE connector_health ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON connector_health
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_health_tenant_status ON connector_health(tenant_id, status);

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_connector_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER trigger_connector_configurations_updated_at
    BEFORE UPDATE ON connector_configurations
    FOR EACH ROW EXECUTE FUNCTION update_connector_updated_at();

CREATE TRIGGER trigger_attribute_mappings_updated_at
    BEFORE UPDATE ON attribute_mappings
    FOR EACH ROW EXECUTE FUNCTION update_connector_updated_at();

CREATE TRIGGER trigger_provisioning_operations_updated_at
    BEFORE UPDATE ON provisioning_operations
    FOR EACH ROW EXECUTE FUNCTION update_connector_updated_at();

CREATE TRIGGER trigger_connector_health_updated_at
    BEFORE UPDATE ON connector_health
    FOR EACH ROW EXECUTE FUNCTION update_connector_updated_at();

-- Shadow objects (local representation of external accounts)
CREATE TABLE gov_shadows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    connector_id UUID NOT NULL REFERENCES connector_configurations(id) ON DELETE CASCADE,
    user_id UUID, -- NULL for unlinked/unmatched shadows
    object_class VARCHAR(255) NOT NULL,
    target_uid VARCHAR(1024) NOT NULL, -- DN or unique identifier in target system
    attributes JSONB NOT NULL DEFAULT '{}',
    expected_attributes JSONB NOT NULL DEFAULT '{}',
    sync_situation VARCHAR(20) NOT NULL DEFAULT 'unlinked',
    state VARCHAR(20) NOT NULL DEFAULT 'unknown',
    pending_operation_count INT NOT NULL DEFAULT 0,
    last_sync_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_shadow_target UNIQUE (tenant_id, connector_id, target_uid),
    CONSTRAINT check_sync_situation CHECK (sync_situation IN ('linked', 'unlinked', 'unmatched', 'disputed', 'collision', 'deleted')),
    CONSTRAINT check_shadow_state CHECK (state IN ('active', 'pending', 'dead', 'unknown'))
);

ALTER TABLE gov_shadows ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON gov_shadows
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_shadows_tenant_connector ON gov_shadows(tenant_id, connector_id);
CREATE INDEX idx_shadows_user ON gov_shadows(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_shadows_situation ON gov_shadows(tenant_id, sync_situation);
CREATE INDEX idx_shadows_state ON gov_shadows(tenant_id, state);
CREATE INDEX idx_shadows_pending ON gov_shadows(tenant_id, connector_id) WHERE state = 'pending';

CREATE TRIGGER trigger_gov_shadows_updated_at
    BEFORE UPDATE ON gov_shadows
    FOR EACH ROW EXECUTE FUNCTION update_connector_updated_at();

-- Function to initialize health record when connector is created
CREATE OR REPLACE FUNCTION create_connector_health_on_insert()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO connector_health (connector_id, tenant_id, status, last_check_at)
    VALUES (NEW.id, NEW.tenant_id, 'disconnected', NOW());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_create_connector_health
    AFTER INSERT ON connector_configurations
    FOR EACH ROW EXECUTE FUNCTION create_connector_health_on_insert();

-- Processed provisioning events for idempotence (extends existing pattern)
-- Note: Uses existing processed_events table from migration 017 with 'provisioning' consumer_group
