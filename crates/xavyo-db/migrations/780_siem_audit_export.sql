-- F078: SIEM Integration & Audit Log Export
-- Creates tables for SIEM destination configuration, export event tracking,
-- delivery health aggregation, and batch export management.

-- ============================================================================
-- Table: siem_destinations
-- ============================================================================
CREATE TABLE IF NOT EXISTS siem_destinations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    destination_type VARCHAR(50) NOT NULL,
    endpoint_host VARCHAR(512) NOT NULL,
    endpoint_port INTEGER,
    export_format VARCHAR(20) NOT NULL,
    auth_config BYTEA,
    event_type_filter JSONB NOT NULL DEFAULT '[]'::jsonb,
    rate_limit_per_second INTEGER NOT NULL DEFAULT 1000,
    queue_buffer_size INTEGER NOT NULL DEFAULT 10000,
    circuit_breaker_threshold INTEGER NOT NULL DEFAULT 5,
    circuit_breaker_cooldown_secs INTEGER NOT NULL DEFAULT 60,
    circuit_state VARCHAR(20) NOT NULL DEFAULT 'closed',
    circuit_last_failure_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    splunk_source VARCHAR(255),
    splunk_sourcetype VARCHAR(255),
    splunk_index VARCHAR(255),
    splunk_ack_enabled BOOLEAN NOT NULL DEFAULT false,
    syslog_facility SMALLINT NOT NULL DEFAULT 10,
    tls_verify_cert BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID NOT NULL REFERENCES users(id),
    CONSTRAINT uq_siem_destinations_tenant_name UNIQUE (tenant_id, name),
    CONSTRAINT chk_siem_destination_type CHECK (destination_type IN ('syslog_tcp_tls', 'syslog_udp', 'webhook', 'splunk_hec')),
    CONSTRAINT chk_siem_export_format CHECK (export_format IN ('cef', 'syslog_rfc5424', 'json', 'csv')),
    CONSTRAINT chk_siem_circuit_state CHECK (circuit_state IN ('closed', 'open', 'half_open')),
    CONSTRAINT chk_siem_rate_limit CHECK (rate_limit_per_second > 0),
    CONSTRAINT chk_siem_queue_buffer CHECK (queue_buffer_size > 0),
    CONSTRAINT chk_siem_circuit_threshold CHECK (circuit_breaker_threshold > 0),
    CONSTRAINT chk_siem_circuit_cooldown CHECK (circuit_breaker_cooldown_secs > 0),
    CONSTRAINT chk_siem_syslog_facility CHECK (syslog_facility BETWEEN 0 AND 23)
);

CREATE INDEX IF NOT EXISTS idx_siem_destinations_tenant ON siem_destinations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_siem_destinations_tenant_enabled ON siem_destinations(tenant_id, enabled);

-- RLS
ALTER TABLE siem_destinations ENABLE ROW LEVEL SECURITY;
CREATE POLICY siem_destinations_tenant_isolation ON siem_destinations
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- ============================================================================
-- Table: siem_export_events
-- ============================================================================
CREATE TABLE IF NOT EXISTS siem_export_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    destination_id UUID NOT NULL REFERENCES siem_destinations(id) ON DELETE CASCADE,
    source_event_id UUID NOT NULL,
    source_event_type VARCHAR(100) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    formatted_payload TEXT,
    delivery_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    retry_count SMALLINT NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    error_detail TEXT,
    delivered_at TIMESTAMPTZ,
    delivery_latency_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_siem_delivery_status CHECK (delivery_status IN ('pending', 'delivered', 'failed', 'dead_letter', 'dropped'))
);

CREATE INDEX IF NOT EXISTS idx_siem_export_events_tenant_dest ON siem_export_events(tenant_id, destination_id);
CREATE INDEX IF NOT EXISTS idx_siem_export_events_status ON siem_export_events(tenant_id, destination_id, delivery_status);
CREATE INDEX IF NOT EXISTS idx_siem_export_events_retry ON siem_export_events(delivery_status, next_retry_at) WHERE delivery_status = 'failed';
CREATE INDEX IF NOT EXISTS idx_siem_export_events_dead_letter ON siem_export_events(tenant_id, destination_id) WHERE delivery_status = 'dead_letter';
CREATE INDEX IF NOT EXISTS idx_siem_export_events_source ON siem_export_events(tenant_id, source_event_id);
CREATE INDEX IF NOT EXISTS idx_siem_export_events_timestamp ON siem_export_events(tenant_id, event_timestamp);

-- RLS
ALTER TABLE siem_export_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY siem_export_events_tenant_isolation ON siem_export_events
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- ============================================================================
-- Table: siem_delivery_health
-- ============================================================================
CREATE TABLE IF NOT EXISTS siem_delivery_health (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    destination_id UUID NOT NULL REFERENCES siem_destinations(id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    events_sent BIGINT NOT NULL DEFAULT 0,
    events_delivered BIGINT NOT NULL DEFAULT 0,
    events_failed BIGINT NOT NULL DEFAULT 0,
    events_dropped BIGINT NOT NULL DEFAULT 0,
    avg_latency_ms INTEGER,
    p95_latency_ms INTEGER,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_siem_delivery_health_window UNIQUE (tenant_id, destination_id, window_start)
);

CREATE INDEX IF NOT EXISTS idx_siem_delivery_health_tenant_dest ON siem_delivery_health(tenant_id, destination_id, window_start);

-- RLS
ALTER TABLE siem_delivery_health ENABLE ROW LEVEL SECURITY;
CREATE POLICY siem_delivery_health_tenant_isolation ON siem_delivery_health
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- ============================================================================
-- Table: siem_batch_exports
-- ============================================================================
CREATE TABLE IF NOT EXISTS siem_batch_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    requested_by UUID NOT NULL REFERENCES users(id),
    date_range_start TIMESTAMPTZ NOT NULL,
    date_range_end TIMESTAMPTZ NOT NULL,
    event_type_filter JSONB NOT NULL DEFAULT '[]'::jsonb,
    output_format VARCHAR(10) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    total_events BIGINT,
    file_path TEXT,
    file_size_bytes BIGINT,
    error_detail TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_siem_batch_output_format CHECK (output_format IN ('json', 'csv')),
    CONSTRAINT chk_siem_batch_status CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    CONSTRAINT chk_siem_batch_date_range CHECK (date_range_end > date_range_start)
);

CREATE INDEX IF NOT EXISTS idx_siem_batch_exports_tenant ON siem_batch_exports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_siem_batch_exports_status ON siem_batch_exports(status) WHERE status IN ('pending', 'processing');

-- RLS
ALTER TABLE siem_batch_exports ENABLE ROW LEVEL SECURITY;
CREATE POLICY siem_batch_exports_tenant_isolation ON siem_batch_exports
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
