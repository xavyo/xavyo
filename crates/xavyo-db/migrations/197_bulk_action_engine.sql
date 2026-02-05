-- Migration: 197_bulk_action_engine.sql
-- Bulk Action Engine - Expression-based mass operations on identities
-- Feature F-064

-- ============================================================================
-- 1. Create ENUMs for bulk action types and status
-- ============================================================================

-- Types of bulk actions that can be performed
CREATE TYPE gov_bulk_action_type AS ENUM (
    'assign_role',
    'revoke_role',
    'enable',
    'disable',
    'modify_attribute'
);

-- Status of a bulk action (reuses pattern from gov_bulk_operation_status)
CREATE TYPE gov_bulk_action_status AS ENUM (
    'pending',
    'running',
    'completed',
    'failed',
    'cancelled'
);

-- ============================================================================
-- 2. Create gov_bulk_actions table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_bulk_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Filter expression (SQL-like syntax)
    filter_expression TEXT NOT NULL,

    -- Action configuration
    action_type gov_bulk_action_type NOT NULL,
    action_params JSONB NOT NULL DEFAULT '{}',

    -- Status and tracking
    status gov_bulk_action_status NOT NULL DEFAULT 'pending',
    justification TEXT NOT NULL,

    -- Progress counters
    total_matched INT NOT NULL DEFAULT 0,
    processed_count INT NOT NULL DEFAULT 0,
    success_count INT NOT NULL DEFAULT 0,
    failure_count INT NOT NULL DEFAULT 0,
    skipped_count INT NOT NULL DEFAULT 0,

    -- Results storage
    results JSONB,

    -- Audit fields
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Constraints
    -- Justification must be at least 10 characters
    CONSTRAINT chk_justification_min_length CHECK (length(justification) >= 10),
    -- Total matched must not exceed 100,000
    CONSTRAINT chk_max_matched CHECK (total_matched <= 100000),
    -- Processed count cannot exceed total matched
    CONSTRAINT chk_processed_count CHECK (processed_count <= total_matched),
    -- Success + failure + skipped cannot exceed processed
    CONSTRAINT chk_result_counts CHECK (success_count + failure_count + skipped_count <= processed_count)
);

-- ============================================================================
-- 3. Enable Row Level Security
-- ============================================================================

ALTER TABLE gov_bulk_actions ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_gov_bulk_actions ON gov_bulk_actions
    FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL THEN false
            WHEN current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- ============================================================================
-- 4. Create indexes
-- ============================================================================

-- Primary tenant index
CREATE INDEX idx_gov_bulk_actions_tenant_id ON gov_bulk_actions(tenant_id);

-- Status filtering (common query pattern)
CREATE INDEX idx_gov_bulk_actions_status ON gov_bulk_actions(tenant_id, status);

-- Created by filtering (for user's own actions)
CREATE INDEX idx_gov_bulk_actions_created_by ON gov_bulk_actions(tenant_id, created_by);

-- Created at for sorting (most recent first)
CREATE INDEX idx_gov_bulk_actions_created_at ON gov_bulk_actions(tenant_id, created_at DESC);

-- Action type filtering
CREATE INDEX idx_gov_bulk_actions_action_type ON gov_bulk_actions(tenant_id, action_type);

-- Find pending/running actions for background processing
CREATE INDEX idx_gov_bulk_actions_pending_running ON gov_bulk_actions(status, created_at)
    WHERE status IN ('pending', 'running');

-- ============================================================================
-- 5. Comments for documentation
-- ============================================================================

COMMENT ON TABLE gov_bulk_actions IS 'Expression-based bulk actions for mass operations on identities';
COMMENT ON COLUMN gov_bulk_actions.filter_expression IS 'SQL-like filter expression (e.g., "department = ''engineering'' AND lifecycle_state = ''active''")';
COMMENT ON COLUMN gov_bulk_actions.action_type IS 'Type of action: assign_role, revoke_role, enable, disable, modify_attribute';
COMMENT ON COLUMN gov_bulk_actions.action_params IS 'Action-specific parameters (e.g., role_id for assign_role, attribute_name for modify_attribute)';
COMMENT ON COLUMN gov_bulk_actions.justification IS 'Audit justification for the bulk action (minimum 10 characters)';
COMMENT ON COLUMN gov_bulk_actions.total_matched IS 'Total number of users matching the filter expression';
COMMENT ON COLUMN gov_bulk_actions.skipped_count IS 'Number of users skipped (no change needed)';
COMMENT ON COLUMN gov_bulk_actions.results IS 'Per-user results with success/failure status and error messages';
