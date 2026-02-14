-- Migration: 050_object_lifecycle_states.sql
-- Object Lifecycle States - Configurable lifecycle states for identity objects
-- Feature F052

-- ============================================================================
-- 1. Create ENUMs for lifecycle states
-- ============================================================================

-- Object types that can have lifecycle states
CREATE TYPE gov_lifecycle_object_type AS ENUM ('user', 'entitlement', 'role');

-- Action to take on entitlements when entering a state
CREATE TYPE gov_entitlement_action AS ENUM ('none', 'pause', 'revoke');

-- Status of a state transition request
CREATE TYPE gov_transition_request_status AS ENUM (
    'pending',
    'pending_approval',
    'approved',
    'executed',
    'rejected',
    'cancelled',
    'expired',
    'rolled_back'
);

-- Status of a scheduled transition
-- Note: gov_schedule_status is defined in 042_compliance_reporting.sql with different values
-- Using gov_scheduled_transition_status to avoid collision
CREATE TYPE gov_scheduled_transition_status AS ENUM ('pending', 'executed', 'cancelled', 'failed');

-- Status of a bulk state operation
CREATE TYPE gov_bulk_operation_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');

-- Type of audit action
CREATE TYPE gov_audit_action_type AS ENUM ('execute', 'rollback');

-- ============================================================================
-- 2. Create gov_lifecycle_configs table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_lifecycle_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    object_type gov_lifecycle_object_type NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One configuration per object type per tenant
    CONSTRAINT uq_lifecycle_config_object_type UNIQUE (tenant_id, object_type)
);

ALTER TABLE gov_lifecycle_configs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_lifecycle_configs ON gov_lifecycle_configs
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_lifecycle_configs_tenant ON gov_lifecycle_configs(tenant_id);
CREATE INDEX idx_lifecycle_configs_object_type ON gov_lifecycle_configs(tenant_id, object_type);

-- ============================================================================
-- 3. Create gov_lifecycle_states table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_lifecycle_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL REFERENCES gov_lifecycle_configs(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    is_initial BOOLEAN NOT NULL DEFAULT false,
    is_terminal BOOLEAN NOT NULL DEFAULT false,
    entitlement_action gov_entitlement_action NOT NULL DEFAULT 'none',
    position INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- State names unique within a configuration
    CONSTRAINT uq_lifecycle_state_name UNIQUE (config_id, name),
    -- Cannot be both initial and terminal
    CONSTRAINT chk_not_initial_and_terminal CHECK (NOT (is_initial AND is_terminal))
);

ALTER TABLE gov_lifecycle_states ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_lifecycle_states ON gov_lifecycle_states
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_lifecycle_states_config ON gov_lifecycle_states(config_id);
CREATE INDEX idx_lifecycle_states_tenant ON gov_lifecycle_states(tenant_id);
CREATE INDEX idx_lifecycle_states_position ON gov_lifecycle_states(config_id, position);

-- ============================================================================
-- 4. Create gov_lifecycle_transitions table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_lifecycle_transitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL REFERENCES gov_lifecycle_configs(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    from_state_id UUID NOT NULL REFERENCES gov_lifecycle_states(id) ON DELETE CASCADE,
    to_state_id UUID NOT NULL REFERENCES gov_lifecycle_states(id) ON DELETE CASCADE,
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    approval_workflow_id UUID REFERENCES gov_approval_workflows(id) ON DELETE SET NULL,
    grace_period_hours INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Transition names unique within a configuration
    CONSTRAINT uq_lifecycle_transition_name UNIQUE (config_id, name),
    -- One transition per state pair
    CONSTRAINT uq_lifecycle_transition_states UNIQUE (from_state_id, to_state_id),
    -- Grace period must be 0-720 hours (30 days)
    CONSTRAINT chk_grace_period_range CHECK (grace_period_hours >= 0 AND grace_period_hours <= 720),
    -- If requires_approval, must have workflow
    CONSTRAINT chk_approval_workflow CHECK (NOT requires_approval OR approval_workflow_id IS NOT NULL)
);

ALTER TABLE gov_lifecycle_transitions ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_lifecycle_transitions ON gov_lifecycle_transitions
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_lifecycle_transitions_config ON gov_lifecycle_transitions(config_id);
CREATE INDEX idx_lifecycle_transitions_from ON gov_lifecycle_transitions(from_state_id);
CREATE INDEX idx_lifecycle_transitions_to ON gov_lifecycle_transitions(to_state_id);
CREATE INDEX idx_lifecycle_transitions_tenant ON gov_lifecycle_transitions(tenant_id);

-- ============================================================================
-- 5. Create gov_state_transition_requests table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_state_transition_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    config_id UUID NOT NULL REFERENCES gov_lifecycle_configs(id) ON DELETE RESTRICT,
    transition_id UUID NOT NULL REFERENCES gov_lifecycle_transitions(id) ON DELETE RESTRICT,
    object_id UUID NOT NULL,
    object_type gov_lifecycle_object_type NOT NULL,
    from_state_id UUID NOT NULL REFERENCES gov_lifecycle_states(id) ON DELETE RESTRICT,
    to_state_id UUID NOT NULL REFERENCES gov_lifecycle_states(id) ON DELETE RESTRICT,
    requested_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status gov_transition_request_status NOT NULL DEFAULT 'pending',
    scheduled_for TIMESTAMPTZ,
    approval_request_id UUID REFERENCES gov_access_requests(id) ON DELETE SET NULL,
    executed_at TIMESTAMPTZ,
    grace_period_ends_at TIMESTAMPTZ,
    rollback_available BOOLEAN NOT NULL DEFAULT false,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- If pending_approval, must have approval_request_id
    CONSTRAINT chk_approval_request CHECK (status != 'pending_approval' OR approval_request_id IS NOT NULL)
);

ALTER TABLE gov_state_transition_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_transition_requests ON gov_state_transition_requests
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_transition_requests_tenant ON gov_state_transition_requests(tenant_id);
CREATE INDEX idx_transition_requests_object ON gov_state_transition_requests(tenant_id, object_id);
CREATE INDEX idx_transition_requests_status ON gov_state_transition_requests(tenant_id, status);
CREATE INDEX idx_transition_requests_created ON gov_state_transition_requests(tenant_id, created_at DESC);
-- For finding requests with active grace periods
CREATE INDEX idx_transition_requests_grace_period ON gov_state_transition_requests(grace_period_ends_at)
    WHERE rollback_available = true;

-- ============================================================================
-- 6. Create gov_scheduled_transitions table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_scheduled_transitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    transition_request_id UUID NOT NULL REFERENCES gov_state_transition_requests(id) ON DELETE CASCADE,
    scheduled_for TIMESTAMPTZ NOT NULL,
    status gov_scheduled_transition_status NOT NULL DEFAULT 'pending',
    executed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    cancelled_by UUID REFERENCES users(id) ON DELETE SET NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One schedule per request
    CONSTRAINT uq_scheduled_transition_request UNIQUE (transition_request_id)
);

ALTER TABLE gov_scheduled_transitions ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_scheduled_transitions ON gov_scheduled_transitions
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_scheduled_transitions_tenant ON gov_scheduled_transitions(tenant_id);
CREATE INDEX idx_scheduled_transitions_due ON gov_scheduled_transitions(scheduled_for)
    WHERE status = 'pending';
CREATE INDEX idx_scheduled_transitions_status ON gov_scheduled_transitions(tenant_id, status);

-- ============================================================================
-- 7. Create gov_bulk_state_operations table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_bulk_state_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    transition_id UUID NOT NULL REFERENCES gov_lifecycle_transitions(id) ON DELETE RESTRICT,
    object_ids UUID[] NOT NULL,
    status gov_bulk_operation_status NOT NULL DEFAULT 'pending',
    total_count INT NOT NULL,
    processed_count INT NOT NULL DEFAULT 0,
    success_count INT NOT NULL DEFAULT 0,
    failure_count INT NOT NULL DEFAULT 0,
    results JSONB,
    requested_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    -- Max 1000 objects per operation
    CONSTRAINT chk_bulk_max_objects CHECK (array_length(object_ids, 1) <= 1000),
    -- Processed count cannot exceed total
    CONSTRAINT chk_processed_count CHECK (processed_count <= total_count),
    -- Success + failure cannot exceed processed
    CONSTRAINT chk_success_failure_count CHECK (success_count + failure_count <= processed_count)
);

ALTER TABLE gov_bulk_state_operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_bulk_operations ON gov_bulk_state_operations
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_bulk_operations_tenant ON gov_bulk_state_operations(tenant_id);
CREATE INDEX idx_bulk_operations_status ON gov_bulk_state_operations(tenant_id, status);
CREATE INDEX idx_bulk_operations_created ON gov_bulk_state_operations(tenant_id, created_at DESC);

-- ============================================================================
-- 8. Create gov_state_transition_audit table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_state_transition_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id UUID NOT NULL REFERENCES gov_state_transition_requests(id) ON DELETE RESTRICT,
    object_id UUID NOT NULL,
    object_type gov_lifecycle_object_type NOT NULL,
    from_state VARCHAR(50) NOT NULL,
    to_state VARCHAR(50) NOT NULL,
    transition_name VARCHAR(100) NOT NULL,
    actor_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    action_type gov_audit_action_type NOT NULL,
    approval_details JSONB,
    entitlements_before JSONB NOT NULL DEFAULT '[]',
    entitlements_after JSONB NOT NULL DEFAULT '[]',
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE gov_state_transition_audit ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_transition_audit ON gov_state_transition_audit
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

CREATE INDEX idx_transition_audit_tenant ON gov_state_transition_audit(tenant_id);
CREATE INDEX idx_transition_audit_object ON gov_state_transition_audit(tenant_id, object_id);
CREATE INDEX idx_transition_audit_actor ON gov_state_transition_audit(tenant_id, actor_id);
CREATE INDEX idx_transition_audit_created ON gov_state_transition_audit(tenant_id, created_at DESC);
CREATE INDEX idx_transition_audit_request ON gov_state_transition_audit(request_id);

-- ============================================================================
-- 9. Add lifecycle_state_id column to users table
-- ============================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS lifecycle_state_id UUID REFERENCES gov_lifecycle_states(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_users_lifecycle_state ON users(lifecycle_state_id) WHERE lifecycle_state_id IS NOT NULL;

-- ============================================================================
-- 10. Comments for documentation
-- ============================================================================

COMMENT ON TABLE gov_lifecycle_configs IS 'Defines lifecycle state machines for object types (user, entitlement, role)';
COMMENT ON TABLE gov_lifecycle_states IS 'Named states within a lifecycle configuration';
COMMENT ON TABLE gov_lifecycle_transitions IS 'Allowed transitions between states with policies';
COMMENT ON TABLE gov_state_transition_requests IS 'Requests to transition objects between states';
COMMENT ON TABLE gov_scheduled_transitions IS 'Scheduled future state transitions';
COMMENT ON TABLE gov_bulk_state_operations IS 'Bulk state transition operations';
COMMENT ON TABLE gov_state_transition_audit IS 'Immutable audit trail of state transitions';

COMMENT ON COLUMN gov_lifecycle_states.entitlement_action IS 'Action on entitlements when entering state: none, pause, revoke';
COMMENT ON COLUMN gov_lifecycle_transitions.grace_period_hours IS 'Hours during which transition can be rolled back (0-720)';
COMMENT ON COLUMN gov_state_transition_requests.rollback_available IS 'Whether rollback is currently possible (within grace period)';
COMMENT ON COLUMN gov_bulk_state_operations.results IS 'Per-object results including failures with error messages';
