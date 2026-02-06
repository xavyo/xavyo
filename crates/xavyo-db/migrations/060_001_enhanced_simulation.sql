-- Migration: F060 Enhanced Simulation Engine
-- Description: Add tables for policy simulation, batch simulation, and comparison reports

-- =============================================================================
-- Enum Types
-- =============================================================================

-- Type of policy simulation
CREATE TYPE policy_simulation_type AS ENUM ('sod_rule', 'birthright_policy');

-- Type of batch simulation
CREATE TYPE batch_simulation_type AS ENUM ('role_add', 'role_remove', 'entitlement_add', 'entitlement_remove');

-- User selection mode for batch simulations
CREATE TYPE selection_mode AS ENUM ('user_list', 'filter');

-- Impact type for simulation results
CREATE TYPE impact_type AS ENUM ('violation', 'entitlement_gain', 'entitlement_loss', 'no_change', 'warning');

-- Comparison type
CREATE TYPE comparison_type AS ENUM ('simulation_vs_simulation', 'simulation_vs_current');

-- =============================================================================
-- Policy Simulations Table
-- =============================================================================

CREATE TABLE gov_policy_simulations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    simulation_type policy_simulation_type NOT NULL,
    policy_id UUID,  -- Reference to existing policy (optional)
    policy_config JSONB NOT NULL DEFAULT '{}',  -- Draft config or override
    status simulation_status NOT NULL DEFAULT 'draft',
    affected_users UUID[] NOT NULL DEFAULT '{}',
    impact_summary JSONB NOT NULL DEFAULT '{}',
    detailed_results JSONB NOT NULL DEFAULT '{}',
    data_snapshot_at TIMESTAMPTZ,
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    retain_until TIMESTAMPTZ,
    notes TEXT,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at TIMESTAMPTZ,
    applied_at TIMESTAMPTZ,
    applied_by UUID
);

-- Indexes for policy simulations
CREATE INDEX idx_gov_policy_simulations_tenant_status ON gov_policy_simulations(tenant_id, status) WHERE NOT is_archived;
CREATE INDEX idx_gov_policy_simulations_created_by ON gov_policy_simulations(tenant_id, created_by);
CREATE INDEX idx_gov_policy_simulations_type ON gov_policy_simulations(tenant_id, simulation_type);
CREATE INDEX idx_gov_policy_simulations_created_at ON gov_policy_simulations(tenant_id, created_at DESC);

-- RLS for policy simulations
ALTER TABLE gov_policy_simulations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy_simulations ON gov_policy_simulations
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- =============================================================================
-- Policy Simulation Results Table (per-user details)
-- =============================================================================

CREATE TABLE gov_policy_simulation_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    simulation_id UUID NOT NULL REFERENCES gov_policy_simulations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    impact_type impact_type NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    severity VARCHAR(20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for policy simulation results
CREATE INDEX idx_gov_policy_simulation_results_simulation ON gov_policy_simulation_results(simulation_id);
CREATE INDEX idx_gov_policy_simulation_results_user ON gov_policy_simulation_results(user_id);
CREATE INDEX idx_gov_policy_simulation_results_type ON gov_policy_simulation_results(simulation_id, impact_type);

-- =============================================================================
-- Batch Simulations Table
-- =============================================================================

CREATE TABLE gov_batch_simulations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    batch_type batch_simulation_type NOT NULL,
    selection_mode selection_mode NOT NULL,
    user_ids UUID[] NOT NULL DEFAULT '{}',  -- For user_list mode
    filter_criteria JSONB NOT NULL DEFAULT '{}',  -- For filter mode
    change_spec JSONB NOT NULL,  -- What to change
    status simulation_status NOT NULL DEFAULT 'draft',
    total_users INT NOT NULL DEFAULT 0,
    processed_users INT NOT NULL DEFAULT 0,
    impact_summary JSONB NOT NULL DEFAULT '{}',
    data_snapshot_at TIMESTAMPTZ,
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    retain_until TIMESTAMPTZ,
    notes TEXT,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at TIMESTAMPTZ,
    applied_at TIMESTAMPTZ,
    applied_by UUID
);

-- Indexes for batch simulations
CREATE INDEX idx_gov_batch_simulations_tenant_status ON gov_batch_simulations(tenant_id, status) WHERE NOT is_archived;
CREATE INDEX idx_gov_batch_simulations_created_by ON gov_batch_simulations(tenant_id, created_by);
CREATE INDEX idx_gov_batch_simulations_type ON gov_batch_simulations(tenant_id, batch_type);
CREATE INDEX idx_gov_batch_simulations_created_at ON gov_batch_simulations(tenant_id, created_at DESC);

-- RLS for batch simulations
ALTER TABLE gov_batch_simulations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_batch_simulations ON gov_batch_simulations
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- =============================================================================
-- Batch Simulation Results Table (per-user details)
-- =============================================================================

CREATE TABLE gov_batch_simulation_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    simulation_id UUID NOT NULL REFERENCES gov_batch_simulations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    access_gained JSONB NOT NULL DEFAULT '[]',
    access_lost JSONB NOT NULL DEFAULT '[]',
    warnings JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for batch simulation results
CREATE INDEX idx_gov_batch_simulation_results_simulation ON gov_batch_simulation_results(simulation_id);
CREATE INDEX idx_gov_batch_simulation_results_user ON gov_batch_simulation_results(user_id);

-- =============================================================================
-- Simulation Comparisons Table
-- =============================================================================

CREATE TABLE gov_simulation_comparisons (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    comparison_type comparison_type NOT NULL,
    simulation_a_id UUID,  -- First simulation (nullable for vs_current)
    simulation_a_type VARCHAR(50),  -- 'policy' or 'batch'
    simulation_b_id UUID,  -- Second simulation (nullable for vs_current)
    simulation_b_type VARCHAR(50),
    summary_stats JSONB NOT NULL DEFAULT '{}',
    delta_results JSONB NOT NULL DEFAULT '{}',
    is_stale BOOLEAN NOT NULL DEFAULT FALSE,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for simulation comparisons
CREATE INDEX idx_gov_simulation_comparisons_tenant ON gov_simulation_comparisons(tenant_id);
CREATE INDEX idx_gov_simulation_comparisons_created_at ON gov_simulation_comparisons(tenant_id, created_at DESC);

-- RLS for simulation comparisons
ALTER TABLE gov_simulation_comparisons ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_simulation_comparisons ON gov_simulation_comparisons
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- =============================================================================
-- Comments for documentation
-- =============================================================================

COMMENT ON TABLE gov_policy_simulations IS 'What-if analysis for SoD rules and birthright policies (F060)';
COMMENT ON TABLE gov_policy_simulation_results IS 'Per-user impact details for policy simulations';
COMMENT ON TABLE gov_batch_simulations IS 'Simulate access changes for multiple users at once';
COMMENT ON TABLE gov_batch_simulation_results IS 'Per-user impact details for batch simulations';
COMMENT ON TABLE gov_simulation_comparisons IS 'Comparison reports between simulations or simulation vs current state';

COMMENT ON COLUMN gov_policy_simulations.policy_config IS 'Draft policy configuration to simulate (JSONB)';
COMMENT ON COLUMN gov_policy_simulations.data_snapshot_at IS 'Timestamp when input data was captured for staleness detection';
COMMENT ON COLUMN gov_policy_simulations.is_archived IS 'Hidden from default listings when true';
COMMENT ON COLUMN gov_policy_simulations.retain_until IS 'Cannot delete before this timestamp';

COMMENT ON COLUMN gov_batch_simulations.selection_mode IS 'How users are selected: user_list (explicit) or filter (criteria)';
COMMENT ON COLUMN gov_batch_simulations.change_spec IS 'What access change to simulate (operation, role_id, etc.)';
COMMENT ON COLUMN gov_batch_simulations.total_users IS 'Total users in selection (for progress tracking)';
COMMENT ON COLUMN gov_batch_simulations.processed_users IS 'Users processed so far (for progress tracking)';

COMMENT ON COLUMN gov_simulation_comparisons.simulation_a_type IS 'Type of first simulation: policy or batch';
COMMENT ON COLUMN gov_simulation_comparisons.is_stale IS 'True if underlying simulations have changed since comparison was generated';
