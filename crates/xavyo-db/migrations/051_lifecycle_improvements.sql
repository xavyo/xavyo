-- Migration: 051_lifecycle_improvements.sql
-- Lifecycle States Improvements - Optimistic locking, retry queue, orphan detection
-- Feature F052 - Improvements based on IGA edge case analysis

-- ============================================================================
-- 1. Add version field for optimistic locking on transition requests
-- ============================================================================

ALTER TABLE gov_state_transition_requests
    ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;

-- ============================================================================
-- 2. Add retry_count and next_retry_at for failed transition retry mechanism
-- ============================================================================

ALTER TABLE gov_state_transition_requests
    ADD COLUMN IF NOT EXISTS retry_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS max_retries INT NOT NULL DEFAULT 3;

-- Add 'failed' status to transition request status if not exists
-- Note: We already have 'expired' status, we'll use 'failed' differently
-- Actually, we need to add a new status for retryable failures

-- Index for finding requests that need retry
CREATE INDEX IF NOT EXISTS idx_transition_requests_retry
    ON gov_state_transition_requests(next_retry_at)
    WHERE status = 'pending' AND retry_count > 0;

-- ============================================================================
-- 3. Create gov_lifecycle_failed_operations table for retry queue
-- ============================================================================

CREATE TYPE gov_failed_operation_type AS ENUM (
    'transition',
    'entitlement_action',
    'state_update',
    'audit_record'
);

CREATE TABLE IF NOT EXISTS gov_lifecycle_failed_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    operation_type gov_failed_operation_type NOT NULL,
    related_request_id UUID REFERENCES gov_state_transition_requests(id) ON DELETE CASCADE,
    object_id UUID NOT NULL,
    object_type gov_lifecycle_object_type NOT NULL,
    operation_payload JSONB NOT NULL,
    error_message TEXT NOT NULL,
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ NOT NULL,
    last_attempted_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, retrying, succeeded, dead_letter
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    CONSTRAINT chk_retry_status CHECK (status IN ('pending', 'retrying', 'succeeded', 'dead_letter'))
);

ALTER TABLE gov_lifecycle_failed_operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_failed_operations ON gov_lifecycle_failed_operations
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_failed_operations_tenant ON gov_lifecycle_failed_operations(tenant_id);
CREATE INDEX idx_failed_operations_retry ON gov_lifecycle_failed_operations(next_retry_at)
    WHERE status IN ('pending', 'retrying');
CREATE INDEX idx_failed_operations_dead_letter ON gov_lifecycle_failed_operations(tenant_id, status)
    WHERE status = 'dead_letter';

-- ============================================================================
-- 4. Add auto_assign_initial_state flag to lifecycle configs
-- ============================================================================

ALTER TABLE gov_lifecycle_configs
    ADD COLUMN IF NOT EXISTS auto_assign_initial_state BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN gov_lifecycle_configs.auto_assign_initial_state IS
    'When true, new objects of this type are automatically assigned the initial state';

-- ============================================================================
-- 5. Create function for detecting orphaned lifecycle states
-- ============================================================================

-- Function to find objects with invalid lifecycle_state_id references
CREATE OR REPLACE FUNCTION find_lifecycle_orphans(p_tenant_id UUID, p_object_type gov_lifecycle_object_type)
RETURNS TABLE (
    object_id UUID,
    object_type gov_lifecycle_object_type,
    current_state_id UUID,
    issue TEXT
) AS $$
BEGIN
    IF p_object_type = 'user' THEN
        RETURN QUERY
        SELECT
            u.id AS object_id,
            'user'::gov_lifecycle_object_type AS object_type,
            u.lifecycle_state_id AS current_state_id,
            CASE
                WHEN u.lifecycle_state_id IS NOT NULL AND s.id IS NULL THEN 'orphaned_state_reference'
                WHEN u.lifecycle_state_id IS NULL AND c.auto_assign_initial_state = true THEN 'missing_initial_state'
                ELSE 'unknown'
            END AS issue
        FROM users u
        LEFT JOIN gov_lifecycle_states s ON u.lifecycle_state_id = s.id AND s.tenant_id = p_tenant_id
        LEFT JOIN gov_lifecycle_configs c ON c.tenant_id = p_tenant_id AND c.object_type = 'user' AND c.is_active = true
        WHERE u.tenant_id = p_tenant_id
        AND (
            (u.lifecycle_state_id IS NOT NULL AND s.id IS NULL)
            OR (u.lifecycle_state_id IS NULL AND c.auto_assign_initial_state = true AND c.id IS NOT NULL)
        );
    END IF;
    -- Add entitlement and role cases as needed
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 6. Create function for auto-assigning initial state
-- ============================================================================

CREATE OR REPLACE FUNCTION assign_initial_lifecycle_state()
RETURNS TRIGGER AS $$
DECLARE
    v_initial_state_id UUID;
    v_config_active BOOLEAN;
    v_auto_assign BOOLEAN;
BEGIN
    -- Only for users currently (extend for entitlements/roles later)
    IF TG_TABLE_NAME = 'users' THEN
        -- Check if lifecycle config exists and is active for this tenant
        SELECT c.is_active, c.auto_assign_initial_state, s.id
        INTO v_config_active, v_auto_assign, v_initial_state_id
        FROM gov_lifecycle_configs c
        LEFT JOIN gov_lifecycle_states s ON s.config_id = c.id AND s.is_initial = true
        WHERE c.tenant_id = NEW.tenant_id AND c.object_type = 'user'
        LIMIT 1;

        -- If auto-assign is enabled and we have an initial state, assign it
        IF v_config_active = true AND v_auto_assign = true AND v_initial_state_id IS NOT NULL THEN
            NEW.lifecycle_state_id := v_initial_state_id;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for auto-assigning initial state on user creation
DROP TRIGGER IF EXISTS trg_assign_initial_lifecycle_state ON users;
CREATE TRIGGER trg_assign_initial_lifecycle_state
    BEFORE INSERT ON users
    FOR EACH ROW
    WHEN (NEW.lifecycle_state_id IS NULL)
    EXECUTE FUNCTION assign_initial_lifecycle_state();

-- ============================================================================
-- 7. Add optimistic locking check function
-- ============================================================================

CREATE OR REPLACE FUNCTION check_transition_request_version(
    p_request_id UUID,
    p_expected_version INT
) RETURNS BOOLEAN AS $$
DECLARE
    v_current_version INT;
BEGIN
    SELECT version INTO v_current_version
    FROM gov_state_transition_requests
    WHERE id = p_request_id
    FOR UPDATE;

    IF v_current_version IS NULL THEN
        RETURN FALSE;
    END IF;

    RETURN v_current_version = p_expected_version;
END;
$$ LANGUAGE plpgsql;

-- Function to increment version atomically
CREATE OR REPLACE FUNCTION increment_transition_request_version(
    p_request_id UUID,
    p_expected_version INT
) RETURNS INT AS $$
DECLARE
    v_new_version INT;
BEGIN
    UPDATE gov_state_transition_requests
    SET version = version + 1, updated_at = NOW()
    WHERE id = p_request_id AND version = p_expected_version
    RETURNING version INTO v_new_version;

    RETURN v_new_version;
END;
$$ LANGUAGE plpgsql;
