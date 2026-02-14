-- Migration: 047_provisioning_consistency.sql
-- Provisioning Consistency Engine - Enhances operation queue with idempotency,
-- attempt tracking, enhanced health status, and conflict detection

-- ============================================================================
-- 1. Enhance provisioning_operations table
-- ============================================================================

-- Add new status values to the constraint
ALTER TABLE provisioning_operations
DROP CONSTRAINT IF EXISTS check_operation_status;

ALTER TABLE provisioning_operations
ADD CONSTRAINT check_operation_status
CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'dead_letter', 'awaiting_system', 'resolved', 'cancelled'));

-- Add idempotency_key column for duplicate detection
ALTER TABLE provisioning_operations
ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(64);

-- Add resolution_notes for resolved operations
ALTER TABLE provisioning_operations
ADD COLUMN IF NOT EXISTS resolution_notes TEXT;

-- Add resolved_by for tracking who resolved dead letter items
ALTER TABLE provisioning_operations
ADD COLUMN IF NOT EXISTS resolved_by UUID;

-- Add resolved_at timestamp
ALTER TABLE provisioning_operations
ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

-- Add started_at for tracking when processing began
ALTER TABLE provisioning_operations
ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;

-- Create unique index for idempotency (per tenant)
CREATE UNIQUE INDEX IF NOT EXISTS idx_operations_idempotency
ON provisioning_operations(tenant_id, idempotency_key)
WHERE idempotency_key IS NOT NULL;

-- Index for awaiting_system operations (for resume when connector online)
CREATE INDEX IF NOT EXISTS idx_operations_awaiting_system
ON provisioning_operations(connector_id, status)
WHERE status = 'awaiting_system';

-- ============================================================================
-- 2. Create operation_attempts table for attempt history
-- ============================================================================

CREATE TABLE IF NOT EXISTS operation_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL REFERENCES provisioning_operations(id) ON DELETE CASCADE,
    attempt_number INT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    success BOOLEAN NOT NULL DEFAULT false,
    error_code VARCHAR(50),
    error_message TEXT,
    response_data JSONB,
    duration_ms INT,
    CONSTRAINT unique_attempt_per_operation UNIQUE (operation_id, attempt_number)
);

ALTER TABLE operation_attempts ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON operation_attempts
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_attempts_operation ON operation_attempts(operation_id, attempt_number);
CREATE INDEX idx_attempts_tenant_created ON operation_attempts(tenant_id, started_at DESC);

-- ============================================================================
-- 3. Create connector_health_status table for offline detection
-- ============================================================================

-- Note: connector_health table already exists from 044_connector_framework.sql
-- We enhance it with additional fields for offline detection

-- Add offline_since column if not exists
ALTER TABLE connector_health
ADD COLUMN IF NOT EXISTS offline_since TIMESTAMPTZ;

-- Add last_success_at column
ALTER TABLE connector_health
ADD COLUMN IF NOT EXISTS last_success_at TIMESTAMPTZ;

-- Add last_error column
ALTER TABLE connector_health
ADD COLUMN IF NOT EXISTS last_error TEXT;

-- Add is_online computed field (based on health status and consecutive failures)
-- We'll use status = 'connected' or 'degraded' as online indicator
-- consecutive_failures >= 3 marks offline

-- Create index for offline connectors
CREATE INDEX IF NOT EXISTS idx_health_offline
ON connector_health(tenant_id, connector_id)
WHERE status = 'disconnected' OR consecutive_failures >= 3;

-- ============================================================================
-- 4. Create conflict_records table for conflict detection
-- ============================================================================

CREATE TABLE IF NOT EXISTS conflict_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL REFERENCES provisioning_operations(id) ON DELETE CASCADE,
    conflicting_operation_id UUID REFERENCES provisioning_operations(id) ON DELETE SET NULL,
    conflict_type VARCHAR(30) NOT NULL,
    affected_attributes JSONB NOT NULL DEFAULT '[]',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolution_strategy VARCHAR(20) NOT NULL,
    resolved_at TIMESTAMPTZ,
    resolution_outcome VARCHAR(20),
    resolved_by UUID,
    notes TEXT,
    CONSTRAINT check_conflict_type CHECK (conflict_type IN ('concurrent_update', 'stale_data', 'missing_target', 'external_change')),
    CONSTRAINT check_resolution_strategy CHECK (resolution_strategy IN ('last_write_wins', 'first_write_wins', 'manual', 'merge')),
    CONSTRAINT check_resolution_outcome CHECK (resolution_outcome IS NULL OR resolution_outcome IN ('applied', 'superseded', 'merged', 'rejected', 'pending'))
);

ALTER TABLE conflict_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON conflict_records
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_conflicts_operation ON conflict_records(operation_id);
CREATE INDEX idx_conflicts_tenant_status ON conflict_records(tenant_id, resolution_outcome)
WHERE resolution_outcome IS NULL OR resolution_outcome = 'pending';
CREATE INDEX idx_conflicts_detected ON conflict_records(tenant_id, detected_at DESC);

-- ============================================================================
-- 5. Update QueueConfig defaults (applied at application level, but document here)
-- ============================================================================

-- Default configuration values (documented for reference):
-- base_delay_secs: 30 (was 5)
-- max_delay_secs: 3600 (1 hour, unchanged)
-- jitter_factor: 0.25 (unchanged)
-- default_max_retries: 10 (was 5)
-- batch_size: 50 (was 10)
-- lock_timeout_secs: 300 (5 minutes, unchanged)
-- offline_threshold: 3 consecutive failures

-- ============================================================================
-- 6. Add triggers for updated_at on new tables
-- ============================================================================

-- Reuse existing trigger function if available
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Note: operation_attempts doesn't have updated_at, only started_at and completed_at

-- ============================================================================
-- 7. Create helper function for idempotency key generation (documented)
-- ============================================================================

-- Idempotency key is generated at application level using:
-- SHA256(tenant_id + connector_id + user_id + operation_type + SHA256(canonical_json(payload)))
-- Truncated to 64 characters (hex)

COMMENT ON COLUMN provisioning_operations.idempotency_key IS
'SHA256 hash for duplicate detection: SHA256(tenant_id + connector_id + user_id + operation_type + payload_hash)[:64]';

COMMENT ON TABLE operation_attempts IS
'Records each execution attempt for a provisioning operation, enabling retry history tracking';

COMMENT ON TABLE conflict_records IS
'Tracks detected conflicts between concurrent provisioning operations';
